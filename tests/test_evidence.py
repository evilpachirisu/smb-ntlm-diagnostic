import io
import json
import socket
import subprocess
import sys
import time
import struct
import unittest
from unittest.mock import patch
from impacket import ntlm, smb3structs as smb2
from smbdiag.console import ConsoleDisplay
from smbdiag.evidence import format_response
from smbdiag.client import probe
import test_diagnostic as fixtures
from test_diagnostic import exchange, negotiate, setup


def authenticate(lm, nt, flags=1):
    fields = [lm, nt, 'LAB'.encode('utf-16le'), 'evidence-user'.encode('utf-16le'), b'', b'']
    header = b'NTLMSSP\x00' + struct.pack('<I', 3)
    pos = 64
    for value in fields:
        header += struct.pack('<HHI', len(value), len(value), pos)
        pos += len(value)
    return header + struct.pack('<I', flags) + b''.join(fields)


class EvidenceUnitTests(unittest.TestCase):
    def test_format_v1_v2_and_ess_using_upstream(self):
        challenge = bytes.fromhex('0123456789abcdef')
        lm, nt = b'L' * 24, b'N' * 24
        token = authenticate(lm, nt)
        label, value = format_response(token, challenge, 'NTLMv1')
        self.assertEqual(label, 'NetNTLMv1')
        self.assertEqual(value, f'evidence-user::LAB:{lm.hex()}:{nt.hex()}:{challenge.hex()}')
        self.assertEqual(format_response(token, challenge, 'NTLMv1-ESS')[0], 'NetNTLMv1 (ESS)')
        nt = fixtures.v2_response()
        label, value = format_response(authenticate(lm, nt), challenge, 'NTLMv2')
        self.assertEqual(label, 'NetNTLMv2')
        self.assertEqual(value, f'evidence-user::LAB:{challenge.hex()}:{nt[:16].hex()}:{nt[16:].hex()}')

    def test_no_format_for_unknown_empty_or_missing_challenge(self):
        with patch('smbdiag.evidence.outputToJohnFormat') as upstream:
            for form in ('unknown', 'empty_or_anonymous'):
                self.assertIsNone(format_response(b'', b'C' * 8, form))
            self.assertIsNone(format_response(b'', b'', 'NTLMv2'))
            upstream.assert_not_called()

    def test_opt_in_quiet_and_terminal_escaping(self):
        text = io.StringIO()
        secret = 'USER\x1b[31m\n::LAB:00'
        ConsoleDisplay(text).show_response('a' * 32, '127.0.0.1', 62069, 'NetNTLMv1', secret)
        self.assertEqual(text.getvalue(), '')
        ConsoleDisplay(text, quiet=True, show_netntlm=True).show_response('a' * 32, '127.0.0.1', 62069, 'NetNTLMv1', secret)
        self.assertEqual(text.getvalue(), '')
        ConsoleDisplay(text, show_netntlm=True).show_response('a' * 32, '127.0.0.1', 62069, 'NetNTLMv1', secret)
        self.assertIn('NetNTLMv1:', text.getvalue())
        self.assertNotIn('\x1b', text.getvalue())
        self.assertEqual(len(text.getvalue().splitlines()), 1)


class EvidenceNetworkTests(unittest.TestCase):
    setUp = fixtures.NetworkTests.setUp
    tearDown = fixtures.NetworkTests.tearDown
    wait_disconnected = fixtures.NetworkTests.wait_disconnected
    connect = fixtures.NetworkTests.connect
    rows = fixtures.NetworkTests.rows

    def enable(self):
        self.output = io.StringIO()
        console = ConsoleDisplay(self.output, show_netntlm=True)
        self.events.observer = console
        self.server.response_observer = console.show_response

    def test_opt_in_v1_v2_still_rejects_and_keeps_metadata_logs(self):
        self.enable()
        for is_v2 in (False, True):
            with self.connect() as sock:
                exchange(sock, negotiate())
                first = ntlm.getNTLMSSPType1()
                first['flags'] &= ~0x80000
                answer = exchange(sock, setup(first.getData()))
                self.assertEqual(answer['Status'], 0xc0000016)
                token = smb2.SMB2SessionSetup_Response(answer['Data'])['Buffer']
                challenge = token[24:32]
                lm = b'L' * 24
                nt = fixtures.v2_response() if is_v2 else b'N' * 24
                answer = exchange(sock, setup(authenticate(lm, nt), 2, answer['SessionID']))
                self.assertEqual(answer['Status'], 0xc000006d)
            self.wait_disconnected()
            value = (f'evidence-user::LAB:{challenge.hex()}:{nt[:16].hex()}:{nt[16:].hex()}' if is_v2 else
                     f'evidence-user::LAB:{lm.hex()}:{nt.hex()}:{challenge.hex()}')
            self.assertIn(value, self.output.getvalue())
            logs = self.json.read_text() + self.text.read_text()
            for secret in (value, 'evidence-user', challenge.hex(), nt.hex()):
                self.assertNotIn(secret, logs)
        text = self.output.getvalue()
        for label in ('NetNTLMv1:', 'NetNTLMv2:', '>>> NTLMv1 detected', '>>> NTLMv2 detected', 'Disconnected'):
            self.assertIn(label, text)
        self.assertEqual(len([r for r in self.rows() if r.get('message_type') == 3]), 2)

    def test_unknown_and_out_of_sequence_have_no_evidence(self):
        self.enable()
        with self.connect() as sock:
            exchange(sock, negotiate())
            answer = exchange(sock, setup(authenticate(b'L' * 24, b'N' * 24)))
            self.assertEqual(answer['Status'], 0xc000006d)
        self.wait_disconnected()
        with self.connect() as sock:
            exchange(sock, negotiate())
            answer = exchange(sock, setup(ntlm.getNTLMSSPType1().getData()))
            answer = exchange(sock, setup(authenticate(b'L' * 24, b'N' * 10), 2, answer['SessionID']))
            self.assertEqual(answer['Status'], 0xc000006d)
        self.wait_disconnected()
        self.assertIn('Unknown', self.output.getvalue())
        self.assertNotIn('NetNTLMv1:', self.output.getvalue())
        self.assertNotIn('NetNTLMv2:', self.output.getvalue())

    def test_display_failure_does_not_affect_diagnostics(self):
        def failing(*args):
            raise OSError('synthetic console failure')
        self.server.response_observer = failing
        with patch('impacket.smbserver.writeJohnOutputToFile') as write:
            result = probe(port=self.server.server_address[1])
            self.assertTrue(result[-1]['expected_diagnostic_rejection'])
            self.wait_disconnected()
            write.assert_not_called()
        self.assertTrue(any(r['event'] == 'session_result' for r in self.rows()))


    def test_runtime_option_and_quiet_precedence(self):
        for quiet in (False, True):
            with socket.socket() as temporary:
                temporary.bind(('127.0.0.1', 0))
                port = temporary.getsockname()[1]
            path = self.json.parent / ('option-' + str(quiet) + '.jsonl')
            command = [sys.executable, '-m', 'smbdiag', '--show-netntlm', '--port', str(port),
                       '--format', 'jsonl', '--jsonl', str(path)]
            if quiet:
                command.append('--quiet')
            child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
            self.assertEqual(stderr, b'')
            if quiet:
                self.assertEqual(stdout, b'')
            else:
                self.assertIn(b'NetNTLMv2:', stdout)
                self.assertIn(b'>>> NTLMv2 detected', stdout)
                self.assertIn(b'Connected', stdout)
            self.assertNotIn('hash_string', path.read_text())
            self.assertNotIn('NetNTLMv2:', path.read_text())
