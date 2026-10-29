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

Defender shows your estate as it is *now*. Ledger keeps a dated copy every day, so you can answer questions like
"which devices dropped off last week?", "when did this CVE first appear?" or "what was our exposure score at
audit time?". It saves inventory and posture data only, not alerts or hunting telemetry.

## Getting started

### 1. Create an app in Entra ID

1. **Entra ID → App registrations → New registration.**
2. **API permissions → Add a permission → APIs my organization uses → WindowsDefenderATP → Application
   permissions.** Add the permissions for the datasets you want (see [What it saves](#what-it-saves)), then
   **Grant admin consent**.
3. **Certificates & secrets → New client secret.** Copy the secret's value.

### 2. Install

Requires Python 3.9 or later.

```sh
pipx install git+https://github.com/securemetrics/ledger
```

No pipx? `pip install git+https://github.com/securemetrics/ledger` works too.

### 3. Save your credentials

```sh
ledger setup
```

This asks for the tenant ID, client ID and client secret, saves them in your OS keystore (Windows Credential
Manager, macOS Keychain or Linux Secret Service) and checks that they work. Run it again to change a value.

You can use environment variables instead: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`.
They take priority over the keystore. Use them on Linux servers without a desktop, which usually have no
keystore.

### 4. Take a snapshot

```sh
ledger snapshot
```

Ledger asks which folder to save to (or give one with `-o`), then saves today's data there.

## Commands

| Command | What it does |
|---|---|
| `ledger setup` | Save your credentials and check they work |
| `ledger snapshot` | Save today's snapshot |
| `ledger list` | List saved days, with record counts |
| `ledger query DATASET` | Show a dataset as a table |
| `ledger schedule` | Take a snapshot every day (Windows) |
| `ledger help COMMAND` | Show every option of a command |

## What it saves

| Dataset | Contents | Permission |
|---|---|---|
| `machines` | Devices | `Machine.Read.All` |
| `av_health` | Antivirus health per device | `Machine.Read.All` |
| `software` | Software across your organization | `Software.Read.All` |
| `software_by_machine` | Installed software per device | `Software.Read.All` |
| `vulnerabilities` | Vulnerabilities per device, with CVSS score and exploitability | `Vulnerability.Read.All` |
| `recommendations` | Security recommendations | `SecurityRecommendation.Read.All` |
| `exposure_score` | Exposure score | `Score.Read.All` |
| `configuration_score` | Secure configuration score | `Score.Read.All` |
| `indicators` | Custom indicators (IoCs) | `Ti.Read.All` |

Ledger saves all of them unless you choose with `--datasets`, e.g. `ledger snapshot --datasets
machines,vulnerabilities`. If the app is missing a permission, that dataset fails, the others are still saved,
and Ledger exits with code 1.

Each day gets its own folder, named by its UTC date:

```
snapshots/
└── 2026-10-28/
    ├── manifest.json          record counts and fetch times
    ├── machines.json.gz
    ├── vulnerabilities.json.gz
    └── ...
```

Choose the file format with `--format`:

| Format | Best for |
|---|---|
| `json` (default) | Keeping everything exactly as Defender returned it. Files are gzipped. |
| `csv` | Excel. Nested fields become their own columns, like `vmMetadata.cloudProvider`. |
| `parquet` | Power BI, pandas and data lakes. Same columns as CSV, with data types. |

Taking another snapshot on the same day replaces that day's files. An interrupted run never damages earlier
snapshots.

If your tenant uses a regional API endpoint, set `LEDGER_API_URL`, e.g.
`https://eu.api.security.microsoft.com`.

## Run it daily

### Windows

```powershell
ledger schedule
```

This shows your schedules and lets you add or remove one:

```
  Scheduled snapshots

  #  Name           Time   Folder     Format  Datasets            Runs       State  Last run            Next run
  ─  ─────────────  ─────  ─────────  ──────  ──────────────────  ─────────  ─────  ──────────────────  ────────────────
  1  snapshot-0215  02:15  C:\Ledger  json    all                 always     Ready  2026-10-28 02:15 ✓  2026-10-29 02:15
  2  snapshot-1800  18:00  D:\mde     csv     machines,av_health  signed in  Ready  never               2026-10-28 18:00

  Run one now: schtasks /Run /TN "\Ledger\<name>"

  Add (a), remove (r) or quit (q) [q]:
```

- **Runs**: `always` runs even while you're signed out. `signed in` only runs while you're signed in.
- **Last run**: ✓ means every dataset was saved. `✗ see log` means at least one failed. The log is
  `ledger.log` in the snapshot folder.

Adding a schedule asks a few questions. To answer them up front, use flags:

| Question | Flag |
|---|---|
| What time? | `--at 02:15` |
| Which folder? | `-o C:\Ledger` |
| Which format? | `--format json` |
| Which datasets? | `--datasets all` |
| Run while signed out? | `--password` or `--no-password` |

```powershell
ledger schedule --at 02:15 -o C:\Ledger --format json --datasets all --password
```

Good to know:

- Running while signed out (`--password`) needs your Windows password once. If you change your password,
  add the schedule again.
- Adding a schedule at a time that already has one replaces it.
- If the PC is off or asleep at the scheduled time, the snapshot runs as soon as it can.
- Schedules use the credentials you saved with `ledger setup`.

### Linux and macOS

`ledger schedule` works on Windows only, so use cron. Run `crontab -e` and add:

```cron
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
15 2 * * *  /full/path/to/ledger snapshot -o /var/lib/ledger --log
```

- Get the full path with `which ledger`. Cron doesn't use your shell's `PATH`.
- The credentials go in the crontab because cron can't read the keystore. Only you and root can read your
  crontab.
- `--log` writes output to `ledger.log` in the snapshot folder.
- On macOS, cron can't write to Desktop, Documents or Downloads. Use another folder.

## Look at your data

`ledger query` shows a dataset from your latest snapshot as a table:

```sh
ledger query machines                                         # a few useful columns, first 50 rows
ledger query machines --where healthStatus=Inactive           # exact match, ignoring case
ledger query software_by_machine --where softwareName~chrome  # ~ means "contains"
ledger query vulnerabilities --date 2026-10-27 --limit 0      # an earlier day, every row
ledger query machines --columns computerDnsName,lastIpAddress  # choose columns
ledger query machines --columns all                           # every column
```

To sort, group or compare days, use a query engine. Snapshots are plain files, so [DuckDB](https://duckdb.org)
reads them directly:

```sql
-- device count per day
SELECT filename, count(*) FROM read_json('snapshots/*/machines.json.gz', filename = true) GROUP BY ALL ORDER BY 1;

-- devices that disappeared between two days
SELECT id, computerDnsName FROM read_json('snapshots/2026-10-27/machines.json.gz')
EXCEPT
SELECT id, computerDnsName FROM read_json('snapshots/2026-10-28/machines.json.gz');
```

For CSV or Parquet snapshots, use `read_csv` or `read_parquet` instead.

## Security

- Snapshots contain your full device and vulnerability inventory. Protect them like the Defender console:
  limit who can read them and encrypt the disk.
- Give the app only the permissions for the datasets you save. It never needs write access.
- Prefer `ledger setup` over environment variables, so the client secret stays out of your shell history.

## Development

```sh
git clone https://github.com/securemetrics/ledger && cd ledger
pip install -e .
```

## License

Copyright © 2026 Securemetrics. Licensed under the [GNU General Public License v3.0](LICENSE).
