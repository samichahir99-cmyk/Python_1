import gzip
import os

"""
    read data logs from data directory as rows
"""

GZIP_MAGIC = b'\x1f\x8b'


def open_log(file_path):
    with open(file_path, 'rb') as f:
        compressed = f.read(2) == GZIP_MAGIC
    if compressed:
        return gzip.open(filename=file_path, mode='rt', encoding='utf-8', errors='replace')
    return open(file_path, encoding='utf-8', errors='replace')


def toRows(path):
    rows = []
    for file in sorted(os.listdir(path)):
        file_path = path + '/' + file
        # only rotated logs: auth.log.1, auth.log.2, auth.log.3.gz ...
        if not os.path.isfile(file_path) or not file.startswith('auth.log.'):
            continue
        with open_log(file_path) as f:
            rows.extend(line.rstrip('\n') for line in f)
    return rows


if __name__ == '__main__':
    print(toRows('./data')[:10])
