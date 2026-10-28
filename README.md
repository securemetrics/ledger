# Ledger

```
██╗     ███████╗██████╗  ██████╗ ███████╗██████╗
██║     ██╔════╝██╔══██╗██╔════╝ ██╔════╝██╔══██╗
██║     █████╗  ██║  ██║██║  ███╗█████╗  ██████╔╝
██║     ██╔══╝  ██║  ██║██║   ██║██╔══╝  ██╔══██╗
███████╗███████╗██████╔╝╚██████╔╝███████╗██║  ██║
╚══════╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
```

**Daily snapshots of your Microsoft Defender for Endpoint inventory.** By [Securemetrics](https://securemetrics.io).

Defender shows you the state of your estate *now*. Ledger keeps a dated record of it, so you can answer
"which devices dropped off last week?", "when did that CVE first appear?", or "what was our exposure score
at audit time?". It pulls inventory and posture data only: no alerts and no hunting telemetry.

Single file, Python 3.9+. Installing it also installs `keyring` (OS keystore) and `pyarrow` (Parquet output).

## What it captures

| Dataset | API | Permission |
|---|---|---|
| `machines` | `/api/machines` | `Machine.Read.All` |
| `av_health` | `/api/deviceavinfo` | `Machine.Read.All` |
| `software` | `/api/Software` | `Software.Read.All` |
| `software_by_machine` | `/api/machines/SoftwareInventoryByMachine` | `Software.Read.All` |
| `vulnerabilities` | `/api/machines/SoftwareVulnerabilitiesByMachine` | `Vulnerability.Read.All` |
| `recommendations` | `/api/recommendations` | `SecurityRecommendation.Read.All` |
| `exposure_score` | `/api/exposureScore` | `Score.Read.All` |
| `configuration_score` | `/api/configurationScore` | `Score.Read.All` |
| `indicators` | `/api/indicators` | `Ti.Read.All` |

Pull only some with `--datasets machines,vulnerabilities` (on `snapshot` and `schedule`); the app then only
needs those permissions. Edit `DATASETS` in `ledger.py` to add endpoints. If a permission is missing, that
dataset fails and the others still land; the exit code is non-zero.

## Setup

1. **Entra ID → App registrations → New registration.**
2. **API permissions → Add → APIs my organization uses → `WindowsDefenderATP` → Application permissions.**
   Add the permissions above, then **Grant admin consent**.
3. **Certificates & secrets → New client secret.**

Ledger needs `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`, and looks each one up as an
**environment variable first, then in the OS keystore**.

### Environment variables

```sh
pipx install git+https://github.com/securemetrics/ledger   # or: pip install .
export AZURE_TENANT_ID=...  AZURE_CLIENT_ID=...  AZURE_CLIENT_SECRET=...
```

### OS keystore

Keep the values out of environment variables and shell history by storing them in Windows Credential Manager,
macOS Keychain, or Linux Secret Service (GNOME Keyring / KWallet), under service `ledger`:

```sh
ledger setup                 # prompts for tenant ID, client ID and secret (hidden), saves them, tests sign-in
ledger snapshot              # no env vars needed
```

Re-run `ledger setup` to change a value (Enter keeps the saved one). Remove one with
`python -m keyring del ledger AZURE_CLIENT_SECRET`.

Combine freely: an environment variable always overrides the keystore entry of the same name. Keystores are
per user, so for a scheduled task, store the values while logged in as the account the task runs as
(`runas /user:svc-ledger cmd` on Windows). Headless Linux usually has no Secret Service; use environment
variables there.

## Usage

```sh
ledger setup                 # save credentials to the OS keystore and test sign-in
ledger snapshot              # pull today's snapshot into ./snapshots/YYYY-MM-DD/
ledger snapshot --format csv # or parquet; default json
ledger snapshot --datasets machines,av_health   # only these; default all
ledger snapshot --log        # output appended to ./snapshots/ledger.log
ledger schedule              # run it every day (see below)
ledger snapshot -o /data/mde # choose the folder (without -o, Ledger asks)
ledger list                  # one line per stored day with record counts
ledger query machines        # look at a dataset (see "Query your history")
ledger help query            # every option of a command
```

Each day is a folder with one file per dataset, plus a manifest:

```
snapshots/
└── 2026-10-26/
    ├── manifest.json            {"machines": {"count": 1843, "format": "json", "fetched": "2026-10-26T02:15:09+00:00"}, ...}
    ├── machines.json.gz
    ├── vulnerabilities.json.gz
    └── ...
```

Pick the file format with `--format` (on `snapshot` and `schedule`):

| Format | Files | Shape |
|---|---|---|
| `json` (default) | `.json.gz` | exactly what the API returned, nested |
| `csv` | `.csv` | one row per record; nested objects become dotted columns (`vmMetadata.cloudProvider`), lists become JSON text. UTF-8 with BOM so Excel opens it cleanly |
| `parquet` | `.parquet` | same columns as CSV, typed |

JSON is lossless; choose CSV or Parquet when the data goes straight into Excel, Power BI, pandas or a data lake.

Dates are UTC. Running twice on the same day overwrites that day's data. Writes are atomic, so an
interrupted run never corrupts a previous snapshot. Regional endpoint? Set `LEDGER_API_URL`
(e.g. `https://eu.api.security.microsoft.com`).

## Run it daily

```powershell
ledger setup       # once, as the account the schedule will run as
ledger schedule    # list your schedules, add or remove one
```

`ledger schedule` shows what's scheduled, then asks what to do:

```
  Scheduled snapshots

  #  Name           Time   Folder     Format  Datasets            Runs       State  Last run            Next run
  ─  ─────────────  ─────  ─────────  ──────  ──────────────────  ─────────  ─────  ──────────────────  ────────────────
  1  snapshot-0215  02:15  C:\Ledger  json    all                 always     Ready  2026-10-28 02:15 ✓  2026-10-29 02:15
  2  snapshot-1800  18:00  D:\mde     csv     machines,av_health  signed in  Ready  never               2026-10-28 18:00

  Run one now: schtasks /Run /TN "\Ledger\<name>"

  Add (a), remove (r) or quit (q) [q]:
```

- **Last run**: ✓ means every dataset was saved. `✗ see log` means at least one failed; the log is
  `ledger.log` in the snapshot folder.
- **Runs**: `always` runs even while you're signed out. `signed in` only runs while you're signed in.

### Skip the questions

Adding a schedule asks a few questions. Give a flag to answer one up front:

| Question | Flag |
|---|---|
| What time? | `--at 02:15` |
| Which folder? | `-o C:\Ledger` |
| Which format? | `--format json` |
| Which datasets? | `--datasets all` |
| Run while signed out? (Windows) | `--password` or `--no-password` |

For example, this adds schedule 1 from the table above:

```powershell
ledger schedule --at 02:15 -o C:\Ledger --format json --datasets all --password
```

Adding a schedule at a time that already has one replaces it.

### Windows

Schedules are tasks in Task Scheduler, under `\Ledger\`. If the PC is off or asleep at the scheduled time, the
snapshot runs as soon as it's back. It also runs on battery.

Choose whether it runs while you're signed out:

- **`--password`** (the default): runs even when you're signed out. Windows asks for your password once.
  If you change your Windows password, add the schedule again.
- **`--no-password`**: only runs while you're signed in. No password needed.

### Linux and macOS

Schedules are lines in your crontab. Ledger only changes its own lines (they end in `# ledger:snapshot-HHMM`).

- If the machine is off or asleep at the scheduled time, that day's run is skipped.
- Cron keeps no history, so the **Last run** column says `see log`.
- Cron can't read the keystore, so give it your credentials. Run `crontab -e` and add these lines at the top
  (only you and root can read them):

  ```cron
  AZURE_TENANT_ID=...
  AZURE_CLIENT_ID=...
  AZURE_CLIENT_SECRET=...
  ```

- On macOS, cron can't write to Desktop, Documents or Downloads. Use another folder, or give `/usr/sbin/cron`
  Full Disk Access in System Settings → Privacy & Security.

## Query your history

For a quick look, `ledger query` prints a dataset from the latest snapshot (or `--date`) as a table:

```sh
ledger query machines                                   # useful columns, first 50 rows
ledger query machines --where healthStatus=Inactive     # exact match, case-insensitive
ledger query software_by_machine --where deviceName~web --where softwareName~chrome   # ~ means "contains"
ledger query vulnerabilities --where vulnerabilitySeverityLevel=Critical --limit 0  # every row
ledger query machines --columns computerDnsName,lastIpAddress,vmMetadata.cloudProvider
ledger query machines --columns all                     # or ask for a bad name to see them all listed
```

It reads any format. Nested fields are addressed with dots, e.g. `vmMetadata.cloudProvider`.
For sorting, grouping, or comparing days, use a real query engine.

The snapshots are plain files, so any tool works. [DuckDB](https://duckdb.org) reads them directly:

```sql
-- device count over time
SELECT filename, count(*) FROM read_json('snapshots/*/machines.json.gz', filename = true) GROUP BY ALL ORDER BY 1;

-- devices that disappeared between two days
SELECT id, computerDnsName FROM read_json('snapshots/2026-10-25/machines.json.gz')
EXCEPT
SELECT id, computerDnsName FROM read_json('snapshots/2026-10-26/machines.json.gz');
```

For CSV or Parquet snapshots, swap in `read_csv('snapshots/*/machines.csv')` or
`read_parquet('snapshots/*/machines.parquet')`.

Or jq: `gzip -dc snapshots/2026-10-26/machines.json.gz | jq '.[] | select(.healthStatus != "Active") | .computerDnsName'`

## Security

Snapshots contain your full device and vulnerability inventory. Store them like you'd store the Defender
console itself: restricted access, encrypted at rest. Keep the client secret in a secret store, not in shell
history. The app only needs the read permissions listed above.

## Development

```sh
pip install -e .     # editable install with all dependencies
```

## License

Copyright © 2026 Securemetrics. Licensed under the [GNU General Public License v3.0](LICENSE).
