import io
import json
import subprocess
import sys
import tempfile
import time
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from smbdiag.console import ConsoleDisplay
from smbdiag.eventlog import EventLog
from smbdiag.metadata import inspect
from smbdiag.client import probe
import test_diagnostic as fixtures


def row(event, cid='a' * 32, port=62069, **fields):
    item = dict(event=event, connection_id=cid, source_ip='192.168.56.10', source_port=port)
    item.update(fields)
    return item


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.console = ConsoleDisplay(self.output)

    def test_start_dialect_type2_and_existing_classifier_results(self):
        self.console(dict(event='listen', bind='0.0.0.0', port=8446, drop_ssp=True))
        self.console(row('connect'))
        self.console(row('smb_negotiate', dialect='0x0202'))
        self.console(row('ntlm', message_type=2, direction='server_to_client', ess=False))
        for token, negotiated in ((fixtures.type3(), False),
                                  (fixtures.type3(nt=fixtures.v2_response()), False),
                                  (fixtures.type3(lm=b'C' * 8 + b'\x00' * 16, flags=0x80000), True)):
            self.console(row('ntlm', direction='client_to_server', **inspect(token, negotiated)))
        output = self.output.getvalue()
        for text in ('Listening: 0.0.0.0:8446', 'DropSSP: Enabled', '192.168.56.10:62069',
                     'SMB 2.0.2', 'ESS: OFF', '>>> NTLMv1 detected', '>>> NTLMv2 detected', '>>> NTLMv1 (ESS) detected'):
            self.assertIn(text, output)
        output.encode('ascii')

    def test_unknown_reasons_are_from_existing_classification(self):
        for token, ess, message in ((fixtures.type3(), None, 'Type 1/2 metadata missing'),
                                    (fixtures.type3(flags=0x80000), False, 'ESS flags inconsistent'),
                                    (fixtures.type3(nt=b''), False, 'empty NT response')):
            self.console(row('ntlm', direction='client_to_server', **inspect(token, ess)))
            self.assertIn(message, self.output.getvalue())
        self.assertIn('>>> Unknown (', self.output.getvalue())

    def test_parallel_same_ip_and_reused_endpoint_have_isolated_state(self):
        self.console(row('connect', cid='a' * 32))
        self.console(row('connect', cid='b' * 32, port=62070))
        self.console(row('connect', cid='c' * 32))  # Same endpoint, separate connection ID.
        self.console(row('ntlm', cid='a' * 32, message_type=3, direction='client_to_server', response_format='NTLMv2'))
        workers = [threading.Thread(target=self.console, args=(row('disconnect', cid=cid * 32,
                    port=port, reason='peer_closed'),)) for cid, port in [('a', 62069), ('b', 62070), ('c', 62069)]]
        for thread in workers:
            thread.start()
        for thread in workers:
            thread.join()
        lines = self.output.getvalue().splitlines()
        first = [line for line in lines if 'Disconnected' in line and 'id=aaaaaaaa' in line][0]
        self.assertNotIn('undetermined', first)
        for cid in ('bbbbbbbb', 'cccccccc'):
            self.assertIn('undetermined', [line for line in lines if 'Disconnected' in line and cid in line][0])
        self.assertEqual(self.console.connections, {})

    def test_console_does_not_print_unapproved_values_or_control_sequences(self):
        secret = 'SECRET_SENTINEL\x1b[31m'
        self.console(row('error', reason=secret, error_type=secret))
        self.console(row('ntlm', message_type=3, direction='client_to_server',
                         response_format=secret, classification_basis=secret, flag_names=[secret]))
        self.console(row('connect', cid=secret, source_ip=secret))
        self.assertNotIn('SECRET', self.output.getvalue())
        self.assertNotIn('\x1b', self.output.getvalue())

    def test_quiet_and_closed_console_do_not_stop_file_logging(self):
        console = ConsoleDisplay(self.output, quiet=True)
        console(row('connect'))
        self.assertEqual(self.output.getvalue(), '')
        broken = io.StringIO()
        broken.close()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.jsonl'
            # A closed stream disables console output without changing file logging.
            events = EventLog(path, observer=ConsoleDisplay(broken))
            try:
                for _ in range(2):
                    events.emit('connect', connection_id='a', source_ip='127.0.0.1', source_port=10)
            finally:
                events.close()
            self.assertEqual(len(path.read_text().splitlines()), 2)

    def test_log_bytes_are_unchanged_with_console(self):
        fixed = datetime(2026, 10, 31, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch('smbdiag.eventlog.datetime') as clock:
                clock.now.return_value = fixed
                for name, observer in [('before', None), ('after', self.console)]:
                    events = EventLog(root / (name + '.jsonl'), root / (name + '.txt'), observer=observer)
                    try:
                        events.emit('connect', connection_id='a' * 32, source_ip='127.0.0.1', source_port=62069)
                        events.emit('ntlm', connection_id='a' * 32, source_ip='127.0.0.1', source_port=62069,
                                    direction='client_to_server', **inspect(fixtures.type3(), False))
                        events.emit('disconnect', connection_id='a' * 32, reason='diagnostic_complete')
                    finally:
                        events.close()
            for suffix in ('.jsonl', '.txt'):
                self.assertEqual((root / ('before' + suffix)).read_bytes(), (root / ('after' + suffix)).read_bytes())


class ConsoleNetworkTests(unittest.TestCase):
    setUp = fixtures.NetworkTests.setUp
    tearDown = fixtures.NetworkTests.tearDown
    wait_disconnected = fixtures.NetworkTests.wait_disconnected

    def test_realtime_display_uses_protocol_events(self):
        output = io.StringIO()
        self.events.observer = ConsoleDisplay(output)
        probe(port=self.server.server_address[1])
        self.wait_disconnected()
        text = output.getvalue()
        for value in ('Connected', 'SMB 2.0.2', 'NTLM Type 2 sent', '>>> NTLMv2 detected', 'Disconnected'):
            self.assertIn(value, text)
        self.assertNotIn('undetermined', text)
        self.assertNotIn('PROOF', text)

    def test_quiet_cli_runtime_error_keeps_logs_and_exit_status(self):
        result = subprocess.run([sys.executable, '-m', 'smbdiag', '--quiet',
                                 '--port', str(self.server.server_address[1]), '--jsonl', str(self.json.parent / 'quiet.jsonl'),
                                 '--text', str(self.json.parent / 'quiet.txt')], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'')
        rows = [json.loads(line) for line in (self.json.parent / 'quiet.jsonl').read_text().splitlines()]
        self.assertEqual(rows[0]['reason'], 'startup_or_server_failure')


    def test_quiet_cli_success_keeps_full_diagnostic_flow(self):
        path = self.json.parent / 'quiet-success.jsonl'
        # The probe fixture occupies a port; use an OS-selected separate port for the CLI.
        import socket
        with socket.socket() as temporary:
            temporary.bind(('127.0.0.1', 0))
            port = temporary.getsockname()[1]
        child = subprocess.Popen([sys.executable, '-m', 'smbdiag', '--quiet', '--port', str(port),
                                  '--jsonl', str(path), '--format', 'jsonl'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while not path.exists() or not path.read_text():
                self.assertIsNone(child.poll())
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.02)
            probe(port=port)
            deadline = time.monotonic() + 5
            while 'disconnect' not in path.read_text():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.02)
        finally:
            child.terminate()
            stdout, stderr = child.communicate(timeout=10)
        self.assertEqual(stdout, b'')
        self.assertEqual(stderr, b'')
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual([r['message_type'] for r in rows if r['event'] == 'ntlm'], [1, 2, 3])
        self.assertTrue(any(r['event'] == 'session_result' for r in rows))
