#!/usr/bin/env python3
# Copyright (C) 2026 Securemetrics
# SPDX-License-Identifier: GPL-3.0-only
"""Ledger by Securemetrics: daily snapshots of Microsoft Defender for Endpoint inventory data."""
import argparse
import csv
import datetime
import getpass
import gzip
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from xml.sax.saxutils import escape

import keyring
from keyring.errors import KeyringError

__version__ = "0.1.0"

API = os.environ.get("LEDGER_API_URL", "https://api.securitycenter.microsoft.com")
SCOPE = "https://api.securitycenter.microsoft.com/.default"
TOKEN_URL = "https://login.microsoftonline.com/{}/oauth2/v2.0/token"
SETTINGS = {
    "AZURE_TENANT_ID": "Tenant ID",
    "AZURE_CLIENT_ID": "Client ID",
    "AZURE_CLIENT_SECRET": "Client secret (the Value, not the Secret ID)",
}

# Inventory and posture only: no alerts, no advanced hunting telemetry.
DATASETS = {
    "machines": "/api/machines",  # Machine.Read.All
    "av_health": "/api/deviceavinfo",  # Machine.Read.All
    "software": "/api/Software",  # Software.Read.All
    "software_by_machine": "/api/machines/SoftwareInventoryByMachine",  # Software.Read.All
    # one row per device x software x CVE, with CVSS, exploitability and first/last seen
    # ponytail: JSON export pages; Microsoft suggests the file export (SoftwareVulnerabilitiesExport) above ~100k devices
    "vulnerabilities": "/api/machines/SoftwareVulnerabilitiesByMachine",  # Vulnerability.Read.All
    "recommendations": "/api/recommendations",  # SecurityRecommendation.Read.All
    "exposure_score": "/api/exposureScore",  # Score.Read.All
    "configuration_score": "/api/configurationScore",  # Score.Read.All
    "indicators": "/api/indicators",  # Ti.Read.All
}
# json keeps the API's nested records as-is; csv and parquet flatten them into columns.
FORMATS = {"json": ".json.gz", "csv": ".csv", "parquet": ".parquet"}
# What `ledger query` shows unless --columns says otherwise.
QUERY_COLUMNS = {
    "machines": ["computerDnsName", "osPlatform", "healthStatus", "riskScore", "exposureLevel", "lastSeen"],
    "av_health": ["computerDnsName", "avMode", "avIsSignatureUpToDate", "avIsEngineUpToDate", "quickScanTime",
                  "cloudProtectionState"],
    "software": ["name", "vendor", "weaknesses", "exposedMachines", "installedMachines", "publicExploit"],
    "software_by_machine": ["deviceName", "softwareName", "softwareVersion", "numberOfWeaknesses",
                            "endOfSupportStatus"],
    "vulnerabilities": ["deviceName", "cveId", "vulnerabilitySeverityLevel", "cvssScore", "exploitabilityLevel",
                        "softwareName"],
    "recommendations": ["recommendationName", "severityScore", "exposedMachinesCount", "remediationType", "status"],
    "exposure_score": ["time", "score"],
    "configuration_score": ["time", "score"],
    "indicators": ["indicatorValue", "indicatorType", "action", "severity", "title"],
}

WORD = [
    "██╗     ███████╗██████╗  ██████╗ ███████╗██████╗ ",
    "██║     ██╔════╝██╔══██╗██╔════╝ ██╔════╝██╔══██╗",
    "██║     █████╗  ██║  ██║██║  ███╗█████╗  ██████╔╝",
    "██║     ██╔══╝  ██║  ██║██║   ██║██╔══╝  ██╔══██╗",
    "███████╗███████╗██████╔╝╚██████╔╝███████╗██║  ██║",
    "╚══════╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝",
]

# Task Scheduler definition: catch up after the PC was off or asleep, and run on battery too.
TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Ledger by Securemetrics: daily Defender for Endpoint snapshot</Description></RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{start}</StartBoundary>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
  </Settings>
  <Actions>
    <Exec><Command>{command}</Command><Arguments>{arguments}</Arguments></Exec>
  </Actions>
</Task>
"""
TASK_FOLDER = "\\Ledger\\"
# Lists the tasks in TASK_FOLDER as JSON; unlike `schtasks /Query` output, this doesn't change with the OS language.
PS_LIST = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$tasks = @(Get-ScheduledTask -TaskPath '\Ledger\' -ErrorAction SilentlyContinue | ForEach-Object {
    $info = $_ | Get-ScheduledTaskInfo
    [pscustomobject]@{
        name = $_.TaskName
        start = [string]$_.Triggers[0].StartBoundary
        args = $_.Actions[0].Arguments
        logon = [string]$_.Principal.LogonType
        state = [string]$_.State
        result = $info.LastTaskResult
        last = $(if ($info.LastRunTime) { $info.LastRunTime.ToString('yyyy-MM-dd HH:mm') } else { '' })
        next = $(if ($info.NextRunTime) { $info.NextRunTime.ToString('yyyy-MM-dd HH:mm') } else { '' })
    }
})
ConvertTo-Json -InputObject $tasks -Compress
"""
NEVER_RAN, RUNNING = 0x41303, 0x41301  # Task Scheduler's LastTaskResult codes
COLOR = bool(sys.stderr and sys.stderr.isatty()) and "NO_COLOR" not in os.environ  # stderr is None under pythonw


def paint(code, s):
    return f"\033[{code}m{s}\033[0m" if COLOR else s


def banner():
    if os.name == "nt":
        os.system("")  # enables ANSI colors in legacy Windows consoles
    blue = "38;5;147"  # periwinkle
    rows = [f"  {paint(blue + ';1', w)}" for w in WORD]
    rows += [
        "",
        f"  {paint(blue + ';1', 'Defender for Endpoint')} {paint(blue, '· daily inventory snapshots')}",
        f"  {paint(blue, 'by')} {paint(blue + ';1', 'Securemetrics')} {paint(blue, f'· v{__version__} · GPLv3')}",
        "",
    ]
    print("\n".join(rows), file=sys.stderr)


def setting(name):
    """Environment variable first, then the OS keystore."""
    return os.environ.get(name) or keystore(name)


def keystore(name):
    """Value saved under service "ledger" in Windows Credential Manager, macOS Keychain or Linux Secret Service."""
    try:
        return keyring.get_password("ledger", name)
    except KeyringError:  # no usable keystore, e.g. headless Linux without Secret Service
        return None


def setup():
    """Prompt for the settings and save them to the OS keystore, then test sign-in."""
    env = {}
    try:
        print(f"  Saving to {keyring.get_keyring().name}. Press Enter to keep a saved value.\n", file=sys.stderr)
        for name, label in SETTINGS.items():
            saved = keyring.get_password("ledger", name)
            if name == "AZURE_CLIENT_SECRET":
                value = getpass.getpass(f"  {label}{' [saved]' if saved else ''}: ")
            else:
                value = input(f"  {label}{f' [{saved}]' if saved else ''}: ")
            value = value.strip()
            if value:
                keyring.set_password("ledger", name, value)
            elif not saved:
                sys.exit(f"{label} is required")
            env[name] = value or saved
    except KeyringError as e:
        sys.exit(f"no usable OS keystore: {e}")
    except (KeyboardInterrupt, EOFError):
        sys.exit("\ncancelled")
    print("\n  Saved. Testing sign-in...", file=sys.stderr)
    token(env)
    print(f"  {paint('32', '✓')} signed in. Run: ledger snapshot", file=sys.stderr)
    for name in SETTINGS:
        if os.environ.get(name):
            print(f"  note: environment variable {name} is set and overrides the saved value", file=sys.stderr)
    return 0


def ask(label, default):
    return input(f"  {label} [{default}]: ").strip() or str(default)


def table(headers, rows, file=None):
    file = file or sys.stderr
    style = paint if file.isatty() else (lambda code, s: s)
    widths = [max(len(str(cell)) for cell in col) for col in zip(headers, *rows)]
    fmt = lambda cells: ("  " + "  ".join(str(c).ljust(w) for c, w in zip(cells, widths))).rstrip()
    print(style("1", fmt(headers)), file=file)
    print(style("2", fmt("─" * w for w in widths)), file=file)
    for row in rows:
        print(fmt(row), file=file)


def scheduled():
    """Ledger's tasks in Task Scheduler; none on other OSes, where `ledger schedule` isn't supported yet."""
    if os.name != "nt":
        return []
    result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_LIST],
                            capture_output=True, text=True, encoding="utf-8")
    return json.loads(result.stdout or "[]")


def task_folder(task):
    match = re.search(r'-o ("[^"]*"|\S+)', task["args"] or "")
    return match.group(1).strip('"') if match else "?"


def pick_folder():
    """Ask which snapshot folder to use: one a schedule saves to, or another."""
    default = Path("snapshots").resolve()
    if not (sys.stdin and sys.stdin.isatty()):
        return default  # nobody to ask, e.g. cron or a pipe
    folders = {}
    for task in scheduled():
        if task_folder(task) != "?":
            folders.setdefault(task_folder(task), []).append(task["start"][11:16])
    try:
        if not folders:
            return Path(ask("Snapshot folder", default))
        choices = list(folders)
        print("  Snapshot folder:", file=sys.stderr)
        for i, folder in enumerate(choices, 1):
            print(f"    {i}  {folder}  ({', '.join(folders[folder])} schedule)", file=sys.stderr)
        print(f"    {len(choices) + 1}  a different folder", file=sys.stderr)
        while True:
            pick = ask("Choose", 1)
            if pick.isdigit() and 1 <= int(pick) <= len(choices) + 1:
                break
            print(f"  pick a number from 1 to {len(choices) + 1}", file=sys.stderr)
        if int(pick) <= len(choices):
            return Path(choices[int(pick) - 1])
        return Path(ask("Folder", default))
    except (KeyboardInterrupt, EOFError):
        sys.exit("\ncancelled")


def dataset_list(s):
    """'all', or dataset names and/or their numbers in DATASETS, comma-separated, e.g. machines,3."""
    names = list(DATASETS)
    if s.strip().lower() == "all":
        return names
    picked = set()
    for item in filter(None, (x.strip() for x in s.split(","))):
        name = names[int(item) - 1] if item.isdigit() and 1 <= int(item) <= len(names) else item
        if name not in DATASETS:
            raise argparse.ArgumentTypeError(f"unknown dataset {item!r}, choose from: {', '.join(names)}")
        picked.add(name)
    if not picked:
        raise argparse.ArgumentTypeError("name at least one dataset, or 'all'")
    return [name for name in names if name in picked]


def schedule_rows(tasks):
    rows = []
    for t in tasks:
        fmt = re.search(r"--format (\S+)", t["args"] or "")
        datasets = re.search(r"--datasets (\S+)", t["args"] or "")
        mark = {0: "✓", RUNNING: "running"}.get(t["result"], "✗ see log")
        rows.append([
            t["name"], t["start"][11:16], task_folder(t), fmt.group(1) if fmt else "json",
            datasets.group(1) if datasets else "all",
            "always" if t["logon"] == "Password" else "signed in", t["state"],
            "never" if t["result"] == NEVER_RAN else f"{t['last']} {mark}", t["next"] or "-",
        ])
    return rows


def unschedule(tasks):
    while True:
        pick = input("  Remove which #? (Enter to cancel): ").strip()
        if not pick:
            return 0
        if pick.isdigit() and 1 <= int(pick) <= len(tasks):
            break
        print(f"  pick a number from 1 to {len(tasks)}", file=sys.stderr)
    name = TASK_FOLDER + tasks[int(pick) - 1]["name"]
    result = subprocess.run(["schtasks", "/Delete", "/TN", name, "/F"], capture_output=True, text=True)
    if result.returncode:
        sys.exit(f"couldn't remove {name}: {result.stderr.strip()}")
    print(f"  {paint('32', '✓')} removed {name}", file=sys.stderr)
    return 0


def schedule(out, at, password, fmt, datasets):
    """Show Ledger's scheduled snapshots to add or remove one; any flag skips straight to adding."""
    if os.name != "nt":  # ponytail: Windows only for now; cron support was removed until it's tested on real machines
        sys.exit("`ledger schedule` is Windows-only for now. On Linux and macOS, schedule `ledger snapshot` "
                 "with cron: see README, Run it daily")
    try:
        if (out, at, password, fmt, datasets) == (None,) * 5:
            tasks = scheduled()
            if not tasks:
                print("  No scheduled snapshots yet.\n", file=sys.stderr)
                if not ask("Add a schedule? (y/n)", "y").lower().startswith("y"):
                    return 0
            else:
                print("  Scheduled snapshots\n", file=sys.stderr)
                table(["#", "Name", "Time", "Folder", "Format", "Datasets", "Runs", "State", "Last run", "Next run"],
                      [[i, *row] for i, row in enumerate(schedule_rows(tasks), 1)])
                print(f"\n  Run one now: schtasks /Run /TN \"{TASK_FOLDER}<name>\"\n", file=sys.stderr)
                choice = ask("Add (a), remove (r) or quit (q)", "q").lower()
                if choice.startswith("r"):
                    return unschedule(tasks)
                if not choice.startswith("a"):
                    return 0
        while at is None:
            try:
                at = hhmm(ask("Time to run each day (HH:MM)", "02:15"))
            except ValueError:
                print("  use 24-hour HH:MM, e.g. 02:15 or 18:30", file=sys.stderr)
        if out is None:
            out = ask("Snapshot folder", Path("snapshots").resolve())
        while fmt not in FORMATS:
            fmt = ask(f"Format ({'/'.join(FORMATS)})", "json").lower()
        if datasets is None:
            print("  Datasets:", file=sys.stderr)
            for i, name in enumerate(DATASETS, 1):
                print(f"    {i}  {name}", file=sys.stderr)
        while datasets is None:
            try:
                datasets = dataset_list(ask("Which ones? Numbers or names, comma-separated", "all"))
            except argparse.ArgumentTypeError as e:
                print(f"  {e}", file=sys.stderr)
        if password is None:
            answer = ask("Also run while signed out? Needs your Windows password (y/n)", "y")
            password = not answer.lower().startswith("n")
    except (KeyboardInterrupt, EOFError):
        sys.exit("\ncancelled")
    out = Path(out).resolve()  # scheduled runs start in another working directory
    cmd = [sys.executable, str(Path(__file__).resolve()), "snapshot", "-o", str(out), "--format", fmt]
    if datasets != list(DATASETS):  # no flag means all, so datasets added to Ledger later are picked up too
        cmd += ["--datasets", ",".join(datasets)]
    cmd.append("--log")
    missing = [name for name in SETTINGS if not keystore(name)]
    if missing:
        print(f"  {paint('33', 'note:')} {', '.join(missing)} not in Credential Manager. Scheduled runs can't see "
              f"this window's environment variables, so run `ledger setup` first.\n", file=sys.stderr)
    user = f"{os.environ.get('USERDOMAIN', '.')}\\{getpass.getuser()}"
    if password:
        signin = ["/RU", user, "/RP", "*"]
        print(f"  Scheduling a daily snapshot at {at} as {user}.\n"
              f"  Enter your Windows password so it also runs while you're signed out.\n", file=sys.stderr)
    else:
        signin = []  # without /RU, Windows runs the task only while this user is signed in
        print(f"  Scheduling a daily snapshot at {at} while {user} is signed in.\n", file=sys.stderr)
    pythonw = Path(sys.executable).with_name("pythonw.exe")  # no console window popping up
    xml = TASK_XML.format(start=f"{datetime.date.today()}T{at}:00",
                          command=escape(str(pythonw if pythonw.exists() else sys.executable)),
                          arguments=escape(subprocess.list2cmdline(cmd[1:])))
    name = f"{TASK_FOLDER}snapshot-{at.replace(':', '')}"  # one task per time: re-adding a time replaces it
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ledger-task.xml"
        path.write_text(xml, encoding="utf-16")
        result = subprocess.run(["schtasks", "/Create", "/F", "/TN", name, "/XML", str(path), *signin])
    if result.returncode == 0:
        if not password:
            print("\n  Runs only while you're signed in; a missed run starts after you next sign in.", file=sys.stderr)
        print(f"\n  {paint('32', '✓')} scheduled. Log: {out / 'ledger.log'}\n"
              f"  Run now: schtasks /Run /TN \"{name}\"    Remove: schtasks /Delete /TN \"{name}\" /F", file=sys.stderr)
    return result.returncode


def token(env):
    # ponytail: one token per run (~60-90 min life); refresh on 401 if a huge tenant outlives it
    form = {"grant_type": "client_credentials", "client_id": env["AZURE_CLIENT_ID"],
            "client_secret": env["AZURE_CLIENT_SECRET"], "scope": SCOPE}
    try:
        with urllib.request.urlopen(TOKEN_URL.format(env["AZURE_TENANT_ID"]),
                                    urllib.parse.urlencode(form).encode(), timeout=30) as r:
            return json.load(r)["access_token"]
    except urllib.error.HTTPError as e:
        sys.exit(f"auth failed: HTTP {e.code} {e.read().decode(errors='replace')[:300]}")
    except OSError as e:  # unreachable login endpoint
        sys.exit(f"auth failed: {e}")


def get(url, tok):
    for attempt in range(5):
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {tok}"})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or attempt == 4:
                raise
            time.sleep(float(e.headers.get("Retry-After") or 5 * 2 ** attempt))  # API caps at 100 calls/min


def fetch(path, tok):
    # ponytail: whole dataset in memory; stream pages to disk if tenants get huge
    url, rows = API + path, []
    while url:
        page = get(url, tok)
        if "value" not in page:
            return page  # single-object endpoints (scores)
        rows += page["value"]
        url = page.get("@odata.nextLink")
    return rows


def flatten(row, prefix=""):
    """One row of columns: nested objects become dotted columns, lists become JSON text."""
    flat = {}
    for key, value in row.items():
        if key.startswith("@odata"):
            continue
        if isinstance(value, dict):
            flat.update(flatten(value, f"{prefix}{key}."))
        else:
            flat[prefix + key] = json.dumps(value) if isinstance(value, list) else value
    return flat


def write_parquet(path, rows, columns):
    import pyarrow as pa  # imported here: it adds ~0.5s to startup and only parquet needs it
    import pyarrow.parquet as pq
    arrays = {}
    for column in columns:
        values = [row.get(column) for row in rows]
        try:
            arrays[column] = pa.array(values)
        except (pa.ArrowInvalid, pa.ArrowTypeError):  # mixed types, e.g. a number in some rows and text in others
            arrays[column] = pa.array([None if v is None else str(v) for v in values])
    pq.write_table(pa.table(arrays), path)


def save(path, data):
    """Write in the format the file name says."""
    tmp = path.with_name(path.name + ".tmp")
    if path.suffix in (".csv", ".parquet"):
        rows = [flatten(row) for row in (data if isinstance(data, list) else [data])]
        columns = list(dict.fromkeys(key for row in rows for key in row))  # every row's keys, first-seen order
        if path.suffix == ".csv":
            with open(tmp, "w", newline="", encoding="utf-8-sig") as f:  # BOM so Excel reads it as UTF-8
                writer = csv.DictWriter(f, columns)
                writer.writeheader()
                writer.writerows(rows)
        else:
            write_parquet(tmp, rows, columns)
    else:
        gz = path.suffix == ".gz"
        with (gzip.open if gz else open)(tmp, "wt", encoding="utf-8") as f:
            json.dump(data, f, indent=None if gz else 2)
    os.replace(tmp, path)  # atomic: an interrupted run never corrupts an existing snapshot


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def snapshot(out, tok, fmt="json", datasets=tuple(DATASETS)):
    start = now()
    day = Path(out) / start.date().isoformat()
    day.mkdir(parents=True, exist_ok=True)
    mf = day / "manifest.json"
    manifest = json.loads(mf.read_text(encoding="utf-8")) if mf.exists() else {}  # same-day re-runs keep earlier successes
    failed = 0
    for name in datasets:
        try:
            data = fetch(DATASETS[name], tok)
            save(day / f"{name}{FORMATS[fmt]}", data)
        except Exception as e:  # e.g. a missing API permission; the other datasets still land
            body = e.read().decode(errors="replace")[:200] if isinstance(e, urllib.error.HTTPError) else ""
            print(f"  {paint('31', '✗')} {name:<22} {paint('31', f'{e} {body}')}", file=sys.stderr)
            failed += 1
            continue
        count = len(data) if isinstance(data, list) else 1
        manifest[name] = {"count": count, "format": fmt, "fetched": now().isoformat(timespec="seconds")}
        save(mf, manifest)
        print(f"  {paint('32', '✓')} {name:<22} {count:>10,}", file=sys.stderr)
    took = (now() - start).total_seconds()
    print(f"\n  {len(datasets) - failed}/{len(datasets)} datasets → {day}  ({took:.0f}s)", file=sys.stderr)
    return failed


def list_snapshots(out):
    manifests = sorted(Path(out).glob("*/manifest.json"))
    if not manifests:
        print(f"no snapshots in {out}")
    for mf in manifests:
        m = json.loads(mf.read_text(encoding="utf-8"))
        print(f"{mf.parent.name}  " + "  ".join(f"{k}={v['count']:,}" for k, v in m.items()))
    return 0


def load(path):
    """Records from a snapshot file in any of the FORMATS."""
    if path.suffix == ".parquet":
        import pyarrow.parquet as pq
        return pq.read_table(path).to_pylist()
    if path.suffix == ".csv":
        with open(path, newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))
    with gzip.open(path, "rt", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else [data]


def text(value):
    return "" if value is None else str(value)


def query(out, dataset, date, where, columns, limit):
    """Print one dataset from a snapshot (the latest unless `date`) as a table."""
    # ponytail: filter + pick columns only; DuckDB (see README) covers sorting, grouping and joins
    files = [f for ext in FORMATS.values() for f in Path(out).glob(f"{date or '*'}/{dataset}{ext}")]
    if not files:
        sys.exit(f"no {dataset} snapshot{f' for {date}' if date else ''} in {Path(out).resolve()}")
    path = max(files, key=lambda f: f.parent.name)
    rows = [flatten(row) for row in load(path)]
    available = list(dict.fromkeys(key for row in rows for key in row))
    filters = []
    for condition in where:
        match = re.fullmatch(r"([^=~]+)([=~])(.*)", condition)
        if not match:
            sys.exit(f"--where takes FIELD=VALUE (exact) or FIELD~TEXT (contains), not {condition!r}")
        filters.append(match.groups())
    if columns == "all":
        columns = available
    elif columns:
        columns = columns.split(",")
    else:
        columns = [c for c in QUERY_COLUMNS.get(dataset, []) if c in available] or available[:6]
    unknown = [c for c in columns + [field for field, _, _ in filters] if c not in available]
    if rows and unknown:
        sys.exit(f"unknown column {', '.join(unknown)}. {dataset} has: {', '.join(available)}")
    for field, op, value in filters:
        value = value.lower()
        rows = [r for r in rows if (text(r.get(field)).lower() == value if op == "=" else
                                    value in text(r.get(field)).lower())]
    shown = rows[:limit or None]
    if shown:
        clip = lambda s: s if len(s) <= 40 else s[:39] + "…"
        table(columns, [[clip(text(r.get(c))) for c in columns] for r in shown], file=sys.stdout)
        sys.stdout.flush()  # keep the table above the footer when stdout is buffered
    print(f"\n  {len(shown):,} of {len(rows):,} rows from {path}", file=sys.stderr)
    return 0


def hhmm(s):
    return datetime.datetime.strptime(s, "%H:%M").strftime("%H:%M")


def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-o", "--out", help="snapshot folder (asks if omitted)")
    p = argparse.ArgumentParser(prog="ledger", description=__doc__)
    p.add_argument("--version", action="version", version=f"ledger {__version__}")
    sub = p.add_subparsers(dest="cmd")
    snap = sub.add_parser("snapshot", parents=[common], help="pull every dataset into today's snapshot")
    snap.add_argument("--log", action="store_true", help="append output to <out>/ledger.log instead of the terminal")
    snap.add_argument("--format", choices=FORMATS, default="json", help="file format (default: json)")
    snap.add_argument("--datasets", type=dataset_list, default=list(DATASETS), metavar="NAMES",
                      help="comma-separated, e.g. machines,vulnerabilities (default: all)")
    sub.add_parser("list", parents=[common], help="list stored snapshots")
    q = sub.add_parser("query", parents=[common], help="show a dataset from a snapshot as a table")
    q.add_argument("dataset", choices=DATASETS)
    q.add_argument("--date", help="snapshot day, YYYY-MM-DD (default: latest)")
    q.add_argument("--where", action="append", default=[], metavar="FIELD=VALUE",
                   help="keep rows where FIELD equals VALUE, or FIELD~TEXT contains TEXT; case-insensitive, repeatable")
    q.add_argument("--columns", help="comma-separated column names, or 'all' (default: a useful few)")
    q.add_argument("--limit", type=int, default=50, help="rows to show, 0 for all (default: 50)")
    sub.add_parser("setup", help="save credentials to the OS keystore and test sign-in")
    sched = sub.add_parser("schedule", parents=[common], help="run a snapshot every day (Windows)")
    sched.add_argument("--at", type=hhmm, help="local time, HH:MM (prompts if omitted)")
    sched.add_argument("--format", choices=FORMATS, help="file format (prompts if omitted)")
    sched.add_argument("--datasets", type=dataset_list, metavar="NAMES",
                       help="comma-separated, or 'all' (prompts if omitted)")
    sched.add_argument("--password", action=argparse.BooleanOptionalAction,
                       help="Windows: --password also runs while signed out (asks for your Windows password), "
                            "--no-password runs only while signed in (prompts if omitted)")
    sub.add_parser("help", help="show this help, or a command's").add_argument("command", nargs="?",
                                                                               choices=list(sub.choices))
    args = p.parse_args(argv)

    if getattr(args, "log", False):
        global COLOR
        args.out = args.out or "snapshots"  # output goes to the log, so there's no one to ask
        Path(args.out).mkdir(parents=True, exist_ok=True)
        sys.stderr, COLOR = open(Path(args.out) / "ledger.log", "a", encoding="utf-8"), False
        print(f"\n--- {now():%Y-%m-%d %H:%M:%S} UTC", file=sys.stderr)
    if sys.stdout and not sys.stdout.isatty():
        sys.stdout.reconfigure(encoding="utf-8")  # redirected output on Windows is cp1252 and chokes on "─" or names
    if sys.stderr and sys.stderr.isatty():
        banner()
    if args.cmd in ("snapshot", "list", "query") and args.out is None:
        args.out = pick_folder()
    if args.cmd == "list":
        return list_snapshots(args.out)
    if args.cmd == "query":
        return query(args.out, args.dataset, args.date, args.where, args.columns, args.limit)
    if args.cmd == "setup":
        return setup()
    if args.cmd == "schedule":
        return schedule(args.out, args.at, args.password, args.format, args.datasets)
    if args.cmd != "snapshot":
        (sub.choices[args.command] if getattr(args, "command", None) else p).print_help()
        return 0

    env = {name: setting(name) for name in SETTINGS}
    missing = [name for name in SETTINGS if not env[name]]
    if missing:
        sys.exit(f"missing {', '.join(missing)}: run `ledger setup` or set environment variables")
    return 1 if snapshot(args.out, token(env), args.format, args.datasets) else 0


if __name__ == "__main__":
    sys.exit(main())
