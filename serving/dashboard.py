import math
from collections import Counter

import matplotlib.dates as mdates
import matplotlib.pyplot as plt


def stats(events, locations):
    """everything the report and the charts show, computed from the parsed events"""
    where = {l['ip']: l for l in locations}

    def country(ip):
        return where[ip]['country'][:8] if ip in where else None

    def org(ip):
        return (where[ip]['org'] or '')[:200] or None if ip in where else None

    totals = {'FAILED': 0, 'INVALID': 0, 'ACCEPTED': 0}
    hours, days, ips, countries = Counter(), {}, Counter(), Counter()
    users = {'FAILED': Counter(), 'INVALID': Counter()}
    for e in events:
        kind, n = e['event'], e['count']
        totals[kind] += n
        day = days.setdefault(e['happened_at'].date(), {'failed': 0, 'invalid': 0})
        if kind == 'FAILED':
            day['failed'] += n
            hours[e['happened_at'].hour] += n
            ips[e['ip']] += n
            if e['ip'] in where:
                countries[country(e['ip'])] += n
        elif kind == 'INVALID':
            day['invalid'] += n
        if kind in users:
            users[kind][e['user']] += n
    totals['IPS'] = len(ips)

    return {
        'totals': totals,
        'by_hour': hours,
        'by_day': [{'day': d, **days[d]} for d in sorted(days)],
        'top_ips': [{'ip': ip, 'country': country(ip), 'org': org(ip), 'n': n} for ip, n in ips.most_common()],
        'by_country': [{'country': c, 'n': n} for c, n in countries.most_common()],
        'top_users': {k: [{'user': u, 'n': n} for u, n in c.most_common()] for k, c in users.items()},
        'accepted': [{'happened_at': e['happened_at'], 'user': e['user'], 'ip': e['ip'], 'country': country(e['ip'])}
                     for e in sorted((e for e in events if e['event'] == 'ACCEPTED'), key=lambda e: e['happened_at'])],
    }


def report(s):
    t = s['totals']
    print('=' * 50)
    print(f"failed passwords : {t['FAILED']}")
    print(f"invalid users    : {t['INVALID']}")
    print(f"accepted logins  : {t['ACCEPTED']}")
    print(f"attacking IPs    : {t['IPS']}")
    for a in s['accepted']:
        print(f"  accepted -> {a['happened_at']}  {a['user']}@{a['ip']} [{a['country']}]")
    print('-' * 50)
    for r in s['top_ips'][:10]:
        line = f"{r['ip']:<16}{int(r['n']):>6}  {r['country'] or '??':<4}{r['org'] or ''}"
        print(line.encode('ascii', 'replace').decode())   # Windows console = cp1252
    print('=' * 50)


def _hbar(ax, labels, values, title, color):
    ax.barh(labels, values, color=color)
    ax.invert_yaxis()
    ax.set_title(title)
    ax.grid(axis='x', alpha=0.3)


def dashboard(s):
    t = s['totals']
    fig, ax = plt.subplots(2, 3, figsize=(20, 11), layout='constrained')
    fig.suptitle(f"SSH attacks - {t['FAILED'] + t['INVALID']} bad attempts from {t['IPS']} IPs, "
                 f"{t['ACCEPTED']} accepted login(s)", fontsize=15, fontweight='bold')

    # 1. share of each event type
    wedges, _, _ = ax[0, 0].pie([t['FAILED'], t['INVALID'], t['ACCEPTED']],
                                colors=['tomato', 'gold', 'limegreen'], autopct=lambda p: f'{p:.1f}%' if p > 1 else '',
                                pctdistance=0.78, startangle=90, wedgeprops={'width': 0.45})
    ax[0, 0].legend(wedges, [f"failed password: {t['FAILED']}", f"invalid user: {t['INVALID']}", f"accepted: {t['ACCEPTED']}"],
                    loc='upper center', bbox_to_anchor=(0.5, 0.02), ncol=1, frameon=False)
    # the accepted slice is too thin to see: point at it with a short line
    middle = math.radians((wedges[2].theta1 + wedges[2].theta2) / 2)
    ax[0, 0].annotate(f"accepted: {t['ACCEPTED']}", xy=(math.cos(middle), math.sin(middle)), xytext=(-1.25, 1.2),
                      ha='right', va='center', fontsize=10, annotation_clip=False,
                      arrowprops={'arrowstyle': '-', 'color': 'limegreen', 'lw': 1.5})
    ax[0, 0].set_title('Login outcomes', pad=20)

    # 2. evolution per day (stacked)
    days = s['by_day']
    x = [d['day'] for d in days]
    ax[0, 1].stackplot(x, [int(d['failed']) for d in days], [int(d['invalid']) for d in days],
                       labels=['failed password', 'invalid user'], colors=['tomato', 'gold'], alpha=0.85)
    ax[0, 1].legend(loc='upper right')
    ax[0, 1].set_title('Attempts per day')
    ax[0, 1].xaxis.set_major_locator(mdates.DayLocator(interval=7))   # one date per week: never overlapping
    ax[0, 1].xaxis.set_major_formatter(mdates.DateFormatter('%d %b'))
    ax[0, 1].margins(x=0)
    ax[0, 1].set_ylabel('attempts')
    ax[0, 1].grid(axis='y', alpha=0.3)

    # 3. hour of the day
    hours = s['by_hour']
    ax[0, 2].bar(range(24), [hours.get(h, 0) for h in range(24)], color='slateblue')
    ax[0, 2].set_xticks(range(0, 24, 2))
    ax[0, 2].set_title('Failed passwords by hour of day')
    ax[0, 2].set_xlabel('hour')
    ax[0, 2].set_ylabel('failed passwords')
    ax[0, 2].grid(axis='y', alpha=0.3)

    # 4. worst IPs with their country
    ips = s['top_ips'][:12]
    _hbar(ax[1, 0], [f"{r['ip']} [{r['country'] or '??'}]" for r in ips], [int(r['n']) for r in ips],
          'Top attacking IPs', 'indianred')

    # 5. countries
    countries = s['by_country'][:12]
    _hbar(ax[1, 1], [r['country'] for r in countries], [int(r['n']) for r in countries],
          'Failed passwords by country (located IPs)', 'teal')

    # 6. usernames: wrong password vs non-existing account
    failed = s['top_users']['FAILED'][:8]
    invalid = s['top_users']['INVALID'][:8]
    _hbar(ax[1, 2], [f"{r['user']} (pwd)" for r in failed] + [f"{r['user']} (no account)" for r in invalid],
          [int(r['n']) for r in failed] + [int(r['n']) for r in invalid],
          'Most targeted usernames', ['tomato'] * len(failed) + ['gold'] * len(invalid))
    ax[1, 2].set_xscale('log')   # root is far ahead of the others

    plt.show()