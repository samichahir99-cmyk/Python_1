import os
import sys
import logging

from ingestion import raw
from process import extract_transform, geolocation
from storage import storage
from serving import dashboard

LOG_FOLDER = 'logs'
MODULES = ['main', 'ingestion', 'process', 'storage', 'serving']


def setup_logs():
    # one log file per module in logs/ (logs/ingestion.log, logs/process.log ...)
    # the console only shows the warnings and errors
    os.makedirs(LOG_FOLDER, exist_ok=True)
    format = logging.Formatter('%(asctime)s | %(levelname)-7s | %(name)s | %(message)s')
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING)
    console.setFormatter(format)
    for module in MODULES:
        logger = logging.getLogger(module)
        logger.setLevel(logging.INFO)
        file = logging.FileHandler(os.path.join(LOG_FOLDER, module + '.log'), encoding='utf-8')
        file.setFormatter(format)
        logger.addHandler(file)
        logger.addHandler(console)


def run():
    log = logging.getLogger('main')
    log.info('start')

    # first run, or "uv run main.py reload": logs -> events.csv
    if storage.is_empty() or 'reload' in sys.argv:
        events = extract_transform.extract(raw.toRows('./data'))
        if not events:
            log.error('no event found in ./data, nothing to analyse')
            sys.exit(1)
        storage.save_events(events)
    else:
        events = storage.load_events()
        if not events:
            sys.exit(1)
    print(f'{len(events)} SSH events read')

    # ipinfo is only called for the ips not in locations.csv, the most active ips first
    locations = geolocation.get_locations(geolocation.ips_to_locate(events), storage.load_locations())
    storage.save_locations(locations)
    print(f'{len(locations)} IPs located')

    stats = dashboard.stats(events, locations)
    dashboard.report(stats)
    dashboard.dashboard(stats)
    log.info('end')


if __name__ == '__main__':
    setup_logs()
    try:
        run()
    except KeyboardInterrupt:
        logging.getLogger('main').warning('stopped with ctrl+c')
    except Exception as e:
        # unexpected error : the full traceback goes in logs/main.log
        logging.getLogger('main').exception(f'unexpected error : {e}')
        sys.exit(1)


# run:  uv run main.py          (reads storage/events.csv if it exists)
#       uv run main.py reload   (reads data/ again)
