import gzip
import logging
import os

log = logging.getLogger('ingestion')

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


def read_file(file_path):
    try:
        with open_log(file_path) as f:
            lines = [line.rstrip('\n') for line in f]
    except PermissionError:
        log.error(f'no permission to read {file_path}')
        return []
    except (gzip.BadGzipFile, EOFError):
        # .gz file cut in the middle
        log.error(f'{file_path} is not a valid .gz file (corrupted ?)')
        return []
    except OSError as e:
        log.error(f'cannot read {file_path} : {e}')
        return []
    if not lines:
        log.warning(f'{file_path} is empty')
    else:
        log.info(f'{file_path} : {len(lines)} lines')
    return lines


def toRows(path):
    if not os.path.isdir(path):
        log.error(f'the folder {path} does not exist')
        return []
    rows, files = [], 0
    for file in sorted(os.listdir(path)):
        file_path = path + '/' + file
        # only rotated logs: auth.log.1, auth.log.2, auth.log.3.gz ...
        if not os.path.isfile(file_path) or not file.startswith('auth.log.'):
            continue
        rows.extend(read_file(file_path))
        files += 1
    if files == 0:
        log.error(f'no auth.log file in {path}')
    log.info(f'{files} files read, {len(rows)} lines in total')
    return rows


if __name__ == '__main__':
    print(toRows('./data')[:10])
