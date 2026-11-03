from ingestion import raw
from process import extract_transform, geolocation
from serving import dashboard

LOCATE_LIMIT = 100   # ipinfo free plan is rate-limited

if __name__ == '__main__':
    events = extract_transform.extract(raw.toRows('./data'))
    print(f'{len(events)} SSH events read')

    locations = geolocation.get_locations(geolocation.ips_to_locate(events, LOCATE_LIMIT))
    print(f'{len(locations)} IPs located')

    stats = dashboard.stats(events, locations)
    dashboard.report(stats)
    dashboard.dashboard(stats)


# run:  uv run main.py