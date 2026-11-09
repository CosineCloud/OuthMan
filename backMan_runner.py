#!/usr/bin/env python3
"""BackMan runner: a small persistent scheduler/supervisor for backMan.py (Unix)."""
import argparse
import calendar
from datetime import datetime, timedelta
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from zoneinfo import ZoneInfo

import backMan


def next_run(schedule, now):
    frequency = schedule.get('frequency', 'daily')
    if frequency == 'interval':
        interval = schedule.get('interval_minutes')
        if type(interval) is not int or not 5 <= interval <= 43200:
            raise ValueError('Interval must be 5–43200 minutes.')
        return now + interval*60
    if frequency not in ('daily', 'weekly', 'monthly'):
        raise ValueError('Choose daily, weekly, monthly, or interval.')
    clock = schedule.get('time', '01:00')
    if not isinstance(clock, str) or not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', clock):
        raise ValueError('Use HH:MM for backup time.')
    weekdays = schedule.get('weekdays', [])
    if frequency == 'weekly' and (not isinstance(weekdays, list) or not weekdays or any(type(d) is not int or not 0 <= d <= 6 for d in weekdays)):
        raise ValueError('Weekly schedules require weekdays 0 (Monday) through 6 (Sunday).')
    day_of_month = schedule.get('day_of_month', 1)
    if frequency == 'monthly' and (type(day_of_month) is not int or not 1 <= day_of_month <= 31):
        raise ValueError('Monthly dates must be 1–31.')
    zone = ZoneInfo(schedule.get('timezone', 'America/Chicago'))
    hour, minute = map(int, clock.split(':'))
    first = datetime.fromtimestamp(now, zone).date()
    for offset in range(370):
        day = first + timedelta(days=offset)
        if frequency == 'weekly' and day.weekday() not in weekdays:
            continue
        if frequency == 'monthly' and day.day != min(day_of_month, calendar.monthrange(day.year, day.month)[1]):
            continue
        wall = datetime.combine(day, datetime.min.time()).replace(hour=hour, minute=minute)
        for adjustment in range(1441):
            candidate = wall + timedelta(minutes=adjustment)
            if candidate.date() != day:
                break
            stamp = candidate.replace(tzinfo=zone, fold=0).timestamp()
            if datetime.fromtimestamp(stamp, zone).replace(tzinfo=None) == candidate:
                if stamp > now:
                    return stamp
                break
    raise ValueError('Could not calculate the next backup time.')


def run(config_path, once=False):
    os.umask(0o077)
    config_path = Path(config_path).resolve()
    config = backMan.load_json(config_path)
    directory = backMan.work_directory(config, config_path)
    with backMan.lock(directory, 'runner.lock'):
        main_script = Path(__file__).with_name('backMan.py')
        if once:
            return subprocess.run([sys.executable, str(main_script), '--config', str(config_path)]).returncode
        state_path = directory / 'runner-state.json'
        state = backMan.load_json(state_path) if state_path.exists() else {}
        print('BackMan runner started. Stop with Ctrl+C.', flush=True)
        while True:
            schedule = backMan.load_json(config_path).get('schedule', {})
            # Validate before reusing a persisted deadline.
            next_time = next_run(schedule, time.time())
            if state.get('schedule') != schedule or 'next_run' not in state:
                state = {'schedule': schedule, 'next_run': next_time}
                backMan.write_json(state_path, state)
            if time.time() < state['next_run']:
                time.sleep(max(0, min(30, state['next_run'] - time.time())))
                continue
            completed = subprocess.run([sys.executable, str(main_script), '--config', str(config_path)])
            state['last_attempt'] = time.time()
            if completed.returncode == 0:
                state['last_success'] = state['last_attempt']
                state['next_run'] = next_run(schedule, time.time())
            else:
                # Retry the persisted pending job, not a new backup; at most once per minute.
                state['next_run'] = time.time() + 60
                print('Pending backup will be retried in one minute.', flush=True)
            backMan.write_json(state_path, state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--once', action='store_true', help='Run the main script once immediately, then exit.')
    args = parser.parse_args()
    try:
        return run(args.config, args.once)
    except KeyboardInterrupt:
        return 0
    except (backMan.TransferError, OSError, ValueError, KeyError, TypeError):
        print('BackMan runner stopped: check configuration and local state. Secrets were not logged.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
