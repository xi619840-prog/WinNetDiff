"""Host/family probes run concurrently, bounded, cancellable and in a stable order."""
import socket
import threading
import time
import types
import unittest
from unittest.mock import patch

from winnetdiff.core import engine, i18n
from winnetdiff.core.models import Probe
from winnetdiff.probes import transport

HOSTS = ['one.example', 'two.example', 'three.example']
EXPECTED_ORDER = [(h, f) for h in HOSTS for f in ('IPv4', 'IPv6')]


class FakeProber:
    def __init__(self, delay=0.3, reverse=False, fail=None, on_start=None):
        self.delay, self.reverse, self.fail, self.on_start = delay, reverse, fail, on_start
        self.lock = threading.Lock()
        self.active = self.peak = self.calls = 0
        self.languages = []

    def __call__(self, host, family, retries=2, cancel=None, retry_mode='same-ip'):
        label = 'IPv4' if family == socket.AF_INET else 'IPv6'
        with self.lock:
            index = self.calls
            self.calls += 1
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.languages.append(i18n.get_language())
        try:
            if self.on_start:
                self.on_start(index)
            if self.fail == (host, label):
                raise OSError('synthetic probe failure')
            # Later tasks finish first when reversed, to prove ordering is not completion order.
            position = EXPECTED_ORDER.index((host, label))
            time.sleep(self.delay * ((len(EXPECTED_ORDER) - position) / len(EXPECTED_ORDER) if self.reverse else 1))
            return Probe(host, label, stage='http_ok', dns_ms=1.0, tcp_ms=2.0, tls_ms=3.0, http_ms=4.0)
        finally:
            with self.lock:
                self.active -= 1


def scan_with(prober, hosts=HOSTS, cancel=None, locale='en'):
    with patch.object(engine, 'os', types.SimpleNamespace(name='nt')), \
            patch.object(engine, 'collect_proxy', return_value={}), \
            patch.object(engine, 'collect_routes', return_value={}), \
            patch.object(engine, 'collect_security', return_value={}), \
            patch.object(engine, 'analyze', return_value=[]), \
            patch.object(engine, 'is_admin', return_value=False), \
            patch.object(engine, 'probe_host_family', prober):
        return engine.scan(hosts, do_network=True, cancel=cancel, locale=locale)


class ParallelProbeTests(unittest.TestCase):
    def tearDown(self):
        i18n.set_language('en')

    def test_wall_time_is_bounded_by_the_slowest_pair_not_the_sum(self):
        prober = FakeProber(delay=0.3)
        started = time.perf_counter()
        report = scan_with(prober)
        elapsed = time.perf_counter() - started
        self.assertEqual(6, len(report.probes))
        # Sequential execution needs at least 6 x 0.3 s = 1.8 s.
        self.assertLess(elapsed, 1.2)
        self.assertGreater(prober.peak, 1)
        self.assertLessEqual(prober.peak, engine.PROBE_CONCURRENCY)

    def test_results_keep_host_then_family_order_regardless_of_completion(self):
        report = scan_with(FakeProber(delay=0.2, reverse=True))
        self.assertEqual(EXPECTED_ORDER, [(p.host, p.family) for p in report.probes])

    def test_one_failing_pair_is_recorded_without_losing_the_others(self):
        report = scan_with(FakeProber(delay=0.01, fail=('two.example', 'IPv6')))
        stages = {(p.host, p.family): p.stage for p in report.probes}
        self.assertEqual('probe_error', stages[('two.example', 'IPv6')])
        self.assertEqual(5, sum(stage == 'http_ok' for stage in stages.values()))
        self.assertEqual(EXPECTED_ORDER, [(p.host, p.family) for p in report.probes])

    def test_cancellation_skips_pairs_that_have_not_started(self):
        cancel = threading.Event()
        prober = FakeProber(delay=0.01, on_start=lambda index: cancel.set() if index == 0 else None)
        with patch.object(engine, 'PROBE_CONCURRENCY', 1):
            report = scan_with(prober, cancel=cancel)
        self.assertEqual(1, prober.calls)
        self.assertEqual([('one.example', 'IPv4')], [(p.host, p.family) for p in report.probes])
        self.assertTrue(report.cancelled)

    def test_workers_inherit_the_scan_language(self):
        prober = FakeProber(delay=0.01)
        scan_with(prober, locale='zh-TW')
        self.assertEqual({'zh-TW'}, set(prober.languages))

    def test_progress_callbacks_never_overlap(self):
        lines, state, guard = [], {'active': 0, 'peak': 0}, threading.Lock()

        def progress(text):
            with guard:
                state['active'] += 1
                state['peak'] = max(state['peak'], state['active'])
            time.sleep(0.02)  # Wide window: unserialized callers would overlap here.
            lines.append(text)
            with guard:
                state['active'] -= 1

        with patch.object(engine, 'probe_host_family', FakeProber(delay=0.05)):
            engine.run_probes(HOSTS, 2, threading.Event(), progress)
        self.assertEqual(1, state['peak'])
        self.assertEqual(6, len(lines))
        self.assertTrue(all(line.startswith('[3/5] ') for line in lines))

    def test_no_hosts_means_no_worker_pool(self):
        self.assertEqual([], engine.run_probes([], 2, threading.Event(), lambda _: None))


class ResolverSlotTests(unittest.TestCase):
    def resolve_now(self, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('203.0.113.9', 443))]

    def test_waits_for_a_slot_and_excludes_the_wait_from_dns_time(self):
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        threading.Timer(0.3, slots.release).start()
        with patch.object(transport, '_DNS_SLOTS', slots), \
                patch.object(transport.socket, 'getaddrinfo', side_effect=self.resolve_now):
            started = time.perf_counter()
            addresses, error, dns_ms = transport.timeout_dns('example.com', socket.AF_INET, timeout=2)
            elapsed = time.perf_counter() - started
        self.assertEqual('', error)
        self.assertEqual(1, len(addresses))
        self.assertGreaterEqual(elapsed, 0.25)
        self.assertLess(dns_ms, 200)

    def test_reports_busy_when_no_slot_frees_within_budget(self):
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        with patch.object(transport, '_DNS_SLOTS', slots), patch.object(transport.socket, 'getaddrinfo') as resolver:
            started = time.perf_counter()
            addresses, error, waited = transport.timeout_dns('example.com', socket.AF_INET, timeout=0.3)
            elapsed = time.perf_counter() - started
        resolver.assert_not_called()
        self.assertEqual([], addresses)
        self.assertTrue(error.startswith('DNSBusy:'), error)
        self.assertGreaterEqual(elapsed, 0.28)
        self.assertLess(elapsed, 1.5)
        self.assertGreaterEqual(waited, 250)

    def test_cancellation_interrupts_a_slot_wait(self):
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        cancel = threading.Event()
        threading.Timer(0.1, cancel.set).start()
        with patch.object(transport, '_DNS_SLOTS', slots):
            started = time.perf_counter()
            _, error, _ = transport.timeout_dns('example.com', socket.AF_INET, timeout=5, cancel=cancel)
        self.assertTrue(error.startswith('Cancelled:'), error)
        self.assertLess(time.perf_counter() - started, 1.0)

    def test_busy_maps_to_a_dns_error_stage_not_a_dns_timeout(self):
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        with patch.object(transport, '_DNS_SLOTS', slots):
            probe = transport.probe_host_family('example.com', socket.AF_INET, dns_timeout=0.2, overall_timeout=5)
        self.assertEqual('dns_error', probe.stage)
        self.assertEqual('DNSBusy', probe.error_type)

    def test_six_concurrent_lookups_with_four_slots_all_succeed(self):
        slow = lambda *a, **k: (time.sleep(0.1), self.resolve_now())[1]
        results = []
        with patch.object(transport, '_DNS_SLOTS', threading.BoundedSemaphore(transport.DNS_RESOLVER_SLOTS)), \
                patch.object(transport.socket, 'getaddrinfo', side_effect=slow):
            threads = [threading.Thread(target=lambda: results.append(
                transport.timeout_dns('example.com', socket.AF_INET, timeout=2))) for _ in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(5)
        self.assertEqual(6, len(results))
        self.assertEqual([''] * 6, [error for _, error, _ in results])
        self.assertTrue(all(dns_ms < 400 for _, _, dns_ms in results), results)


if __name__ == '__main__':
    unittest.main()
