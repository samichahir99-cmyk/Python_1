import re
from datetime import datetime

YEAR = 2026  # syslog lines don't carry the year

# "May  3 00:01:21 ns sshd[975159]: Failed password for root from 1.2.3.4 port 22 ssh2"
LINE = re.compile(r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s(?P<message>.*)$')

# (event name, regex) - the first one that matches wins
EVENTS = [
    ('FAILED',   re.compile(r'Failed \w+ for (?:invalid user )?(?P<user>\S*) from (?P<ip>[\d.]+) port (?P<port>\d+)')),
    ('ACCEPTED', re.compile(r'Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)')),
    ('INVALID',  re.compile(r'Invalid user (?P<user>\S*)\s+from (?P<ip>[\d.]+)(?: port (?P<port>\d+))?')),
]
REPEATED = re.compile(r'message repeated (\d+) times')


def extract_from_row(row):
    """returns a dict for an SSH authentication event, or None for any other line"""
    line = LINE.match(row)
    if not line:
        return None
    message = line['message']
    for name, regex in EVENTS:
        found = regex.search(message)
        if found:
            repeated = REPEATED.search(message)
            return {
                'happened_at': datetime.strptime(f"{YEAR} {line['month']} {line['day']} {line['time']}", '%Y %b %d %H:%M:%S'),
                'event': name,
                'user': found['user'] or '(empty)',
                'ip': found['ip'],
                'port': int(found['port']) if found['port'] else None,
                'count': int(repeated.group(1)) if repeated else 1,
            }
    return None


def extract(rows):
    return [event for event in map(extract_from_row, rows) if event]


if __name__ == '__main__':
    print(extract_from_row('May  3 00:01:21 ns sshd[1]: message repeated 4 times: [ Failed password for root from 45.148.10.147 port 8868 ssh2]'))
