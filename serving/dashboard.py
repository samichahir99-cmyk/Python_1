import logging

import matplotlib.pyplot as plt

log = logging.getLogger('serving')


def _add(counts, key, n):
    counts[key] = counts.get(key, 0) + n


def _most_common(counts):
    return sorted(counts.items(), key=lambda item: -item[1])


def stats(events, locations):
    """everything the report and the charts show, computed from the parsed events"""
    where = {l['ip']: l for l in locations}

    def country(ip):
        return where[ip]['country'][:8] if ip in where else None

    def org(ip):
        return (where[ip]['org'] or '')[:200] or None if ip in where else None

    totals = {'FAILED': 0, 'INVALID': 0, 'ACCEPTED': 0}
    hours, days, ips, countries = {}, {}, {}, {}
    users = {'FAILED': {}, 'INVALID': {}}
    accepted_users, located_failed = {}, 0
    for e in events:
        kind, n = e['event'], e['count']
        totals[kind] += n
        day = days.setdefault(e['happened_at'].date(), {'failed': 0, 'invalid': 0})
        if kind == 'FAILED':
            day['failed'] += n
            _add(hours, e['happened_at'].hour, n)
            _add(ips, e['ip'], n)
            if e['ip'] in where:
                _add(countries, country(e['ip']), n)
                located_failed += n
        elif kind == 'INVALID':
            day['invalid'] += n
        else:
            _add(accepted_users, e['user'], n)
        if kind in users:
            _add(users[kind], e['user'], n)
    totals['IPS'] = len(ips)

    return {
        'totals': totals,
        'by_hour': hours,
        'by_day': [{'day': d, **days[d]} for d in sorted(days)],
        'top_ips': [{'ip': ip, 'country': country(ip), 'org': org(ip), 'n': n} for ip, n in _most_common(ips)],
        'by_country': [{'country': c, 'n': n} for c, n in _most_common(countries)],
        'located_failed': located_failed,
        'accepted_by_user': [{'user': u, 'n': n} for u, n in _most_common(accepted_users)],
        'top_users': {k: [{'user': u, 'n': n} for u, n in _most_common(c)] for k, c in users.items()},
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
    print('failed attempts per country:')
    for r in s['by_country'][:15]:
        print(f"  {r['country']:<10}{int(r['n'])}")
    print('successful attempts per user:')
    for r in s['accepted_by_user'][:15]:
        print(f"  {r['user']:<16}{int(r['n'])}")
    print('top invalid usernames:')
    for r in s['top_users']['INVALID'][:10]:
        print(f"  {r['user']:<16}{int(r['n'])}")
    print('top usernames tried (failed password):')
    for r in s['top_users']['FAILED'][:10]:
        print(f"  {r['user']:<16}{int(r['n'])}")
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


def _empty(ax, title):
    log.warning(f'graph "{title.splitlines()[0]}" is empty')
    ax.set_title(title)
    ax.text(0.5, 0.5, 'no data', ha='center', va='center', transform=ax.transAxes)
    ax.set_axis_off()


def dashboard(s):
    t = s['totals']
    fig, axes = plt.subplots(1, 3, figsize=(18, 6), layout='constrained')
    fig.suptitle(f"SSH log analyser - {t['FAILED']} failed passwords, {t['INVALID']} invalid users, "
                 f"{t['ACCEPTED']} accepted login(s)", fontsize=15, fontweight='bold')

    # 1. failed attempts per country
    countries = s['by_country'][:15]
    title = f"Failed attempts per country\n({s['located_failed']} of {t['FAILED']} located)"
    if countries:
        _hbar(axes[0], [r['country'] for r in countries], [int(r['n']) for r in countries], title, 'teal')
        axes[0].set_xlabel('failed attempts')
    else:
        _empty(axes[0], title)

    # 2. successful attempts per user
    accepted = s['accepted_by_user'][:15]
    title = 'Successful attempts per user'
    if accepted:
        _hbar(axes[1], [r['user'] for r in accepted], [int(r['n']) for r in accepted], title, 'limegreen')
        axes[1].set_xlabel('successful logins')
        axes[1].xaxis.get_major_locator().set_params(integer=True)
        axes[1].set_ylim(max(len(accepted), 4) - 0.5, -0.5)   # keep bars thin when there are few users
    else:
        _empty(axes[1], title)

    # 3. failed attempts with an invalid user (account does not exist)
    invalid = s['top_users']['INVALID'][:15]
    title = f"Failed attempts with invalid user\n(total {t['INVALID']})"
    if invalid:
        _hbar(axes[2], [r['user'] for r in invalid], [int(r['n']) for r in invalid], title, 'gold')
        axes[2].set_xlabel('attempts')
    else:
        _empty(axes[2], title)

    plt.show()