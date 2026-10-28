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

- **Last run**: ✓ means every dataset landed, `✗ see log` means at least one failed (details in `<folder>/ledger.log`).
- **Runs**: `always` also runs while you're signed out; `signed in` only runs while you are (see below).

Adding asks for the time, folder, format, datasets and, on Windows, how it signs in. Flags answer the questions
up front. This adds the first schedule above; because of `--password`, Windows then asks for your password once:

```powershell
ledger schedule --at 02:15 -o C:\Ledger --format json --datasets all --password
```

On Windows each schedule is a Task Scheduler task in the `\Ledger\` folder, named after its time; adding the same
time again replaces it. It catches up if the PC was off or asleep at that time, and also runs on battery. How it
signs in:

| Answer | Runs while signed out | Windows password |
|---|---|---|
| `--password` (default) | yes | asked once and stored by Windows; re-run `ledger schedule` after you change it |
| `--no-password` | no; a missed run starts after you next sign in | not needed |

On Linux and macOS, `ledger schedule` works the same way (table, add, remove) using your crontab. Ledger's lines
end in `# ledger:snapshot-HHMM`, and it never touches your other lines. Differences from Windows:

- Cron skips a run missed while the machine was off or asleep; the next one runs as usual.
- Cron keeps no run history, so the table says `see log` instead of a last-run result.
- Cron can't see your shell's environment and usually can't reach the keystore. Put the values at the top of
  `crontab -e` (only you and root can read your crontab):

  ```cron
  AZURE_TENANT_ID=...
  AZURE_CLIENT_ID=...
  AZURE_CLIENT_SECRET=...
  ```
- macOS: cron needs Full Disk Access to write into Desktop, Documents or Downloads. Pick another folder, or
  allow `/usr/sbin/cron` under System Settings → Privacy & Security → Full Disk Access.

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
