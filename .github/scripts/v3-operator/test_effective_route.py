import importlib.util
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('route', Path(__file__).with_name('effective-route.py'))
route = importlib.util.module_from_spec(spec)
spec.loader.exec_module(route)


class EffectiveRouteTests(unittest.TestCase):
    def properties(self, managed):
        values = {(route.TIMER, key): value for key, value in {
            'LoadState': 'loaded', 'FragmentPath': '/etc/systemd/system/' + route.TIMER,
            'DropInPaths': '', 'Unit': route.SERVICE, 'UnitFileState': 'enabled', 'ActiveState': 'active',
            'TimersCalendar': '{ OnCalendar=*-*-* 01:02:03 } { OnCalendar=*-*-* 13:02:03 }'}.items()}
        values.update({(route.SERVICE, key): value for key, value in {
            'LoadState': 'loaded', 'FragmentPath': '/etc/systemd/system/' + route.SERVICE,
            'NeedDaemonReload': 'no', 'DropInPaths': route.DROP_IN if managed else '',
            'ExecStart': ('{ path=/usr/local/bin/sbxr ; argv[]=/usr/local/bin/sbxr --certbot-recorder ; ignore_errors=no }'
                          if managed else '{ path=/usr/bin/snap ; argv[]=/usr/bin/snap run --timer=00:00~24:00/2 certbot.renew ; ignore_errors=no }')}.items()})
        return values

    def inspect(self, managed, values=None, altered=None):
        values = values or self.properties(managed)
        def read(path, mode):
            expected_mode, body = route.OWNED[str(path)]
            self.assertEqual(mode, expected_mode)
            return body if altered is None else altered(body)
        with mock.patch.object(route.os.path, 'lexists', return_value=False):
            return route.inspect(managed, lambda unit, key: values[(unit, key)], read)

    def test_absent_subscription_requires_official_route_and_enabled_requires_exact_owned_hooks(self):
        self.assertEqual(self.inspect(False)['route'], 'official-snap')
        result = self.inspect(True)
        self.assertEqual(result['route'], 'owned-recorder')
        self.assertEqual(set(result['owned_artifacts_sha256']), set(route.OWNED))

    def test_wrong_effective_route_extra_dropin_or_stopped_timer_is_refused(self):
        for key, value in (((route.SERVICE, 'ExecStart'), '{ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no }'),
                           ((route.SERVICE, 'DropInPaths'), route.DROP_IN + ' /tmp/other.conf'),
                           ((route.SERVICE, 'NeedDaemonReload'), 'yes'),
                           ((route.TIMER, 'ActiveState'), 'inactive'),
                           ((route.TIMER, 'Unit'), 'other.service')):
            values = self.properties(True)
            values[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.inspect(True, values)
        with self.assertRaisesRegex(ValueError, 'artifact'):
            self.inspect(True, altered=lambda body: body + b'changed')

    def test_same_halfday_or_invalid_timer_calendar_is_refused(self):
        for calendar in ('{ OnCalendar=*-*-* 01:02:03 }',
                         '{ OnCalendar=*-*-* 01:02:03 } { OnCalendar=*-*-* 05:02:03 }',
                         '{ OnCalendar=*-*-* 01:62:03 } { OnCalendar=*-*-* 13:02:03 }'):
            with self.subTest(calendar=calendar), self.assertRaises(ValueError):
                route.calendar(calendar)


if __name__ == '__main__':
    unittest.main()
