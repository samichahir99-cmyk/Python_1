import sys

from ingestion import raw
from process import extract_transform, geolocation
from storage import database as db
from serving import dashboard

LOCATE_LIMIT = 100   # ipinfo free plan is rate-limited

if __name__ == '__main__':
    db.connect()

    if db.is_empty() or '--reload' in sys.argv:
        events = extract_transform.extract(raw.toRows('./data'))
        print(f'{db.replace_events(events)} SSH events saved')

        missing = db.unlocated_ips(LOCATE_LIMIT)
        if missing:
            db.save_locations(geolocation.get_locations(missing))
            print(f'{len(missing)} IPs located')

    dashboard.report(db)
    dashboard.dashboard(db)


# run:  uv run main.py            (add --reload after changing ./data)