import os
import pymysql

ENV_FILE = os.path.join(os.path.dirname(__file__), '..', '.env')

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS ip_locations (
           ip      VARCHAR(45) PRIMARY KEY,
           country VARCHAR(8),
           city    VARCHAR(100),
           org     VARCHAR(200)
       )""",
    """CREATE TABLE IF NOT EXISTS ssh_events (
           id          INT AUTO_INCREMENT PRIMARY KEY,
           happened_at DATETIME    NOT NULL,
           event       ENUM('FAILED', 'INVALID', 'ACCEPTED') NOT NULL,
           user        VARCHAR(100) COLLATE utf8mb4_bin,
           ip          VARCHAR(45) NOT NULL,
           port        INT,
           count       INT NOT NULL DEFAULT 1,
           INDEX (event), INDEX (ip)
       )""",
]


def read_env():
    """KEY=value lines of .env -> os.environ (values already set in the shell win)"""
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, encoding='utf-8') as f:
            for line in f:
                key, sep, value = line.strip().partition('=')
                if sep and not key.startswith('#'):
                    os.environ.setdefault(key.strip(), value.strip())


conn = None   # set by connect()
name = None


def connect():
    """open the connection (creates the database and tables when missing)"""
    global conn, name
    read_env()
    name = os.environ.get('DB_NAME', 'log_analyser')
    login = dict(host=os.environ.get('DB_HOST', 'localhost'),
                 port=int(os.environ.get('DB_PORT', 3306)),
                 user=os.environ.get('DB_USER', 'root'),
                 password=os.environ.get('DB_PASSWORD', ''),
                 charset='utf8mb4', autocommit=True,
                 cursorclass=pymysql.cursors.DictCursor)
    try:
        server = pymysql.connect(**login)
    except pymysql.err.OperationalError as error:
        raise SystemExit(f"Database server unreachable at {login['host']}:{login['port']} -> {error}\n"
                         "Start MySQL/MariaDB and check the login in .env")
    with server.cursor() as cur:
        cur.execute(f'CREATE DATABASE IF NOT EXISTS `{name}` CHARACTER SET utf8mb4')
    server.close()
    conn = pymysql.connect(database=name, **login)
    for statement in SCHEMA:
        run(statement)


def run(sql, params=None):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


# ---------------- writing ----------------

def replace_events(events, chunk=4000):
    run('TRUNCATE TABLE ssh_events')
    rows = [(e['happened_at'], e['event'], e['user'], e['ip'], e['port'], e['count']) for e in events]
    with conn.cursor() as cur:
        for start in range(0, len(rows), chunk):
            cur.executemany('INSERT INTO ssh_events (happened_at, event, user, ip, port, count)'
                            ' VALUES (%s, %s, %s, %s, %s, %s)', rows[start:start + chunk])
    return len(rows)


def save_locations(locations):
    with conn.cursor() as cur:
        cur.executemany('REPLACE INTO ip_locations (ip, country, city, org) VALUES (%s, %s, %s, %s)',
                        [(l['ip'], l['country'][:8], (l['city'] or '')[:100] or None, (l['org'] or '')[:200] or None)
                         for l in locations])


def unlocated_ips(limit):
    """the worst attackers + every accepted IP that have no location yet"""
    rows = run("""SELECT e.ip, SUM(e.count) AS hits FROM ssh_events e
                       LEFT JOIN ip_locations l ON l.ip = e.ip
                       WHERE l.ip IS NULL AND e.event IN ('FAILED', 'ACCEPTED')
                       GROUP BY e.ip ORDER BY MAX(e.event = 'ACCEPTED') DESC, hits DESC LIMIT %s""", (limit,))
    return [r['ip'] for r in rows]


def is_empty():
    return run('SELECT COUNT(*) AS n FROM ssh_events')[0]['n'] == 0


# ---------------- reading ----------------

def totals():
    result = {'FAILED': 0, 'INVALID': 0, 'ACCEPTED': 0}
    for r in run('SELECT event, SUM(count) AS n FROM ssh_events GROUP BY event'):
        result[r['event']] = int(r['n'])
    result['IPS'] = run("SELECT COUNT(DISTINCT ip) AS n FROM ssh_events WHERE event = 'FAILED'")[0]['n']
    return result


def by_hour():
    return run("""SELECT HOUR(happened_at) AS hour, SUM(count) AS n FROM ssh_events
                       WHERE event = 'FAILED' GROUP BY hour ORDER BY hour""")


def by_day():
    return run("""SELECT DATE(happened_at) AS day,
                              SUM(CASE WHEN event = 'FAILED'  THEN count ELSE 0 END) AS failed,
                              SUM(CASE WHEN event = 'INVALID' THEN count ELSE 0 END) AS invalid
                       FROM ssh_events GROUP BY day ORDER BY day""")


def top_ips(limit=10):
    return run("""SELECT e.ip, l.country, l.org, SUM(e.count) AS n FROM ssh_events e
                       LEFT JOIN ip_locations l ON l.ip = e.ip
                       WHERE e.event = 'FAILED' GROUP BY e.ip, l.country, l.org
                       ORDER BY n DESC LIMIT %s""", (limit,))


def by_country(limit=10):
    return run("""SELECT l.country, SUM(e.count) AS n FROM ssh_events e
                       JOIN ip_locations l ON l.ip = e.ip
                       WHERE e.event = 'FAILED' GROUP BY l.country ORDER BY n DESC LIMIT %s""", (limit,))


def top_users(event, limit=10):
    return run("""SELECT user, SUM(count) AS n FROM ssh_events
                       WHERE event = %s GROUP BY user ORDER BY n DESC LIMIT %s""", (event, limit))


def accepted():
    return run("""SELECT e.happened_at, e.user, e.ip, l.country FROM ssh_events e
                       LEFT JOIN ip_locations l ON l.ip = e.ip
                       WHERE e.event = 'ACCEPTED' ORDER BY e.happened_at""")