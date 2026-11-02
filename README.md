# SSH auth.log analyser

Reads the SSH logs in `data/`, finds failed / invalid / accepted logins, locates the attacking IPs with ipinfo.io,
stores everything in MySQL/MariaDB and shows a dashboard.

```
ingestion/raw.py                 read every log file (plain or gzip)        -> lines
process/extract_transform.py     regex on each line                         -> events
process/geolocation.py           ipinfo.io, 16 requests in parallel         -> country / city / org
storage/database.py              tables ssh_events + ip_locations           -> SQL queries
serving/charts.py                terminal report + 6 matplotlib charts
```

## Run

1. Start MySQL or MariaDB (port 3306).
2. Put the database login in `.env` (`DB_PASSWORD=` stays empty for a default XAMPP install).
3. `uv sync` then `uv run main.py`

The first run fills the database and calls ipinfo; the next runs only read the database.
After changing the files in `data/`: `uv run main.py --reload`.
