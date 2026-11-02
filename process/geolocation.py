import os
import requests
from concurrent.futures import ThreadPoolExecutor

URL = "https://ipinfo.io/{}/json"


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
    with ThreadPoolExecutor(threads) as pool:
        return list(pool.map(get_location, ips))


if __name__ == "__main__":
    print(get_location("2.57.121.112"))
