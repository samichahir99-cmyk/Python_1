import matplotlib.pyplot as plt


def report(db):
    t = db.totals()
    print('=' * 50)
    print(f"failed passwords : {t['FAILED']}")
    print(f"invalid users    : {t['INVALID']}")
    print(f"accepted logins  : {t['ACCEPTED']}")
    print(f"attacking IPs    : {t['IPS']}")
    for a in db.accepted():
        print(f"  accepted -> {a['happened_at']}  {a['user']}@{a['ip']} [{a['country']}]")
    print('-' * 50)
    for r in db.top_ips(10):
        line = f"{r['ip']:<16}{int(r['n']):>6}  {r['country'] or '??':<4}{r['org'] or ''}"
        print(line.encode('ascii', 'replace').decode())   # Windows console = cp1252
    print('=' * 50)


def _hbar(ax, labels, values, title, color):
    ax.barh(labels, values, color=color)
    ax.invert_yaxis()
    ax.set_title(title)
    ax.grid(axis='x', alpha=0.3)


def dashboard(db):
    t = db.totals()
    fig, ax = plt.subplots(2, 3, figsize=(19, 10))
    fig.suptitle(f"SSH attacks - {t['FAILED'] + t['INVALID']} bad attempts from {t['IPS']} IPs, "
                 f"{t['ACCEPTED']} accepted login(s)", fontsize=14)

    # 1. share of each event type
    ax[0, 0].pie([t['FAILED'], t['INVALID'], t['ACCEPTED']],
                 labels=[f"failed password\n{t['FAILED']}", f"invalid user\n{t['INVALID']}", f"accepted\n{t['ACCEPTED']}"],
                 colors=['tomato', 'gold', 'limegreen'], autopct=lambda p: f'{p:.1f}%' if p > 1 else '',
                 startangle=90, wedgeprops={'width': 0.45})
    ax[0, 0].set_title('Login outcomes')

    # 2. evolution per day (stacked)
    days = db.by_day()
    x = [d['day'] for d in days]
    ax[0, 1].stackplot(x, [int(d['failed']) for d in days], [int(d['invalid']) for d in days],
                       labels=['failed password', 'invalid user'], colors=['tomato', 'gold'], alpha=0.85)
    ax[0, 1].legend(loc='upper right')
    ax[0, 1].set_title('Attempts per day')
    ax[0, 1].tick_params(axis='x', rotation=45)

    # 3. hour of the day
    hours = {r['hour']: int(r['n']) for r in db.by_hour()}
    ax[0, 2].bar(range(24), [hours.get(h, 0) for h in range(24)], color='slateblue')
    ax[0, 2].set_xticks(range(0, 24, 2))
    ax[0, 2].set_title('Failed passwords by hour of day')
    ax[0, 2].set_xlabel('hour')

    # 4. worst IPs with their country
    ips = db.top_ips(12)
    _hbar(ax[1, 0], [f"{r['ip']} [{r['country'] or '??'}]" for r in ips], [int(r['n']) for r in ips],
          'Top attacking IPs', 'indianred')

    # 5. countries
    countries = db.by_country(12)
    _hbar(ax[1, 1], [r['country'] for r in countries], [int(r['n']) for r in countries],
          'Failed passwords by country (located IPs)', 'teal')

    # 6. usernames: wrong password vs non-existing account
    failed = db.top_users('FAILED', 8)
    invalid = db.top_users('INVALID', 8)
    _hbar(ax[1, 2], [f"{r['user']} (pwd)" for r in failed] + [f"{r['user']} (no account)" for r in invalid],
          [int(r['n']) for r in failed] + [int(r['n']) for r in invalid],
          'Most targeted usernames', ['tomato'] * len(failed) + ['gold'] * len(invalid))
    ax[1, 2].set_xscale('log')   # root is far ahead of the others

    fig.tight_layout()
    plt.show()
