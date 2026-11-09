from datetime import datetime
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import backup_service


def stamp(value):
    return datetime.fromisoformat(value).timestamp()


class CalendarSchedule(unittest.TestCase):
    def schedule(self, frequency='daily', **kwargs):
        return {'frequency': frequency, 'time': '01:00', 'timezone': 'America/Chicago', **kwargs}

    def test_daily_and_weekly(self):
        daily = self.schedule()
        self.assertEqual(backup_service.next_run(daily, stamp('2026-11-08T00:00:00-06:00')), stamp('2026-11-08T01:00:00-06:00'))
        self.assertEqual(backup_service.next_run(daily, stamp('2026-11-08T01:00:00-06:00')), stamp('2026-11-09T01:00:00-06:00'))
        weekly = self.schedule('weekly', weekdays=[5, 6])
        self.assertEqual(backup_service.next_run(weekly, stamp('2026-11-06T15:00:00-06:00')), stamp('2026-11-07T01:00:00-06:00'))
        self.assertEqual(backup_service.next_run(weekly, stamp('2026-11-07T01:00:00-06:00')), stamp('2026-11-08T01:00:00-06:00'))
        self.assertEqual(backup_service.next_run(weekly, stamp('2026-11-08T01:00:00-06:00')), stamp('2026-11-14T01:00:00-06:00'))

    def test_monthly_short_month_leap_year_and_rollover(self):
        monthly = self.schedule('monthly', day_of_month=31, time='00:00')
        for after, expected in [
            ('2026-01-31T00:00:00-06:00', '2026-02-28T00:00:00-06:00'),
            ('2028-01-31T00:00:00-06:00', '2028-02-29T00:00:00-06:00'),
            ('2026-04-01T00:00:00-05:00', '2026-04-30T00:00:00-05:00'),
            ('2026-12-31T00:00:00-06:00', '2027-01-31T00:00:00-06:00'),
        ]:
            self.assertEqual(backup_service.next_run(monthly, stamp(after)), stamp(expected))

    def test_dst_and_timezone(self):
        gap = self.schedule(time='02:30')
        self.assertEqual(backup_service.next_run(gap, stamp('2026-03-08T00:00:00-06:00')), stamp('2026-03-08T03:00:00-05:00'))
        fold = self.schedule(time='01:30')
        self.assertEqual(backup_service.next_run(fold, stamp('2026-11-01T00:00:00-05:00')), stamp('2026-11-01T01:30:00-05:00'))
        # The repeated 01:30 after fallback must not generate a second backup.
        self.assertEqual(backup_service.next_run(fold, stamp('2026-11-01T01:30:00-05:00')), stamp('2026-11-02T01:30:00-06:00'))
        self.assertEqual(backup_service.next_run(self.schedule(timezone='Asia/Karachi', time='00:00'), stamp('2026-11-08T18:00:00+00:00')), stamp('2026-11-09T00:00:00+05:00'))

    def test_validation_persistence_and_late_run(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'test.db'
            base = dict(enabled=True, frequency='weekly', time='01:00', timezone='America/Chicago', weekdays=[6], passphrase='a private schedule passphrase')
            for invalid in [dict(weekdays=[]), dict(weekdays=[7]), dict(time='25:00'), dict(timezone='Unknown/Place'), dict(frequency='monthly', day_of_month=32)]:
                with self.assertRaises(ValueError):
                    backup_service.configure(db, {**base, **invalid})
            saved = backup_service.configure(db, base, now=stamp('2026-11-07T12:00:00-06:00'))
            self.assertEqual(saved['schedule']['next_run'], stamp('2026-11-08T01:00:00-06:00'))
            self.assertEqual(backup_service.status(db)['schedule']['frequency'], 'weekly')
            with patch('backup_service.backups.create', return_value={'id': 'test'} ) as create:
                backup_service.tick(db, now=stamp('2026-11-10T12:00:00-06:00'))
                create.assert_called_once()
                self.assertEqual(backup_service.status(db)['schedule']['next_run'], stamp('2026-11-15T01:00:00-06:00'))
                self.assertIsNone(backup_service.tick(db, now=stamp('2026-11-10T12:01:00-06:00')))
                create.assert_called_once()


if __name__ == '__main__':
    unittest.main()
