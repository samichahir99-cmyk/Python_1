import os
import requests
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

URL = "https://ipinfo.io/{}/json"
ENV_FILE = os.path.join(os.path.dirname(__file__), '..', '.env')


def read_env():
    """KEY=value lines of .env -> os.environ (values already set in the shell win)"""
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, encoding='utf-8') as f:
            for line in f:
                key, sep, value = line.strip().partition('=')
                if sep and not key.startswith('#'):
                    os.environ.setdefault(key.strip(), value.strip())


def ips_to_locate(events, limit):
    """the IPs that logged in successfully first, then the worst attackers"""
    hits, accepted = Counter(), set()
    for e in events:
        if e['event'] in ('FAILED', 'ACCEPTED'):
            hits[e['ip']] += e['count']
            if e['event'] == 'ACCEPTED':
                accepted.add(e['ip'])
    return sorted(hits, key=lambda ip: (ip not in accepted, -hits[ip]))[:limit]


def get_location(ip):
    """country / city / organisation of an IP, using ipinfo.io"""
    token = os.environ.get('IPINFO_TOKEN')     # optional, lifts the free rate limit
    try:
        response = requests.get(URL.format(ip), params={'token': token} if token else None, timeout=10)
        data = response.json() if response.status_code == 200 else {}
    except (requests.RequestException, ValueError):
        data = {}
    return {
        'ip': ip,
        'country': 'LAN' if data.get('bogon') else data.get('country', '??'),
        'city': data.get('city'),
        'org': data.get('org'),
    }


def get_locations(ips, threads=16):
    read_env()
    with ThreadPoolExecutor(threads) as pool:
        return list(pool.map(get_location, ips))


if __name__ == "__main__":
    print(get_location("2.57.121.112"))