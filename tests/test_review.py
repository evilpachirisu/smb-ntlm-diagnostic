import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from impacket import ntlm, smb3structs as smb2
from smbdiag.client import probe, ProbeFailure
from smbdiag.server import Handler
import test_diagnostic as fixtures
from test_diagnostic import exchange, negotiate, setup

# Reuse only fixture methods; do not duplicate the inherited test suite.
class ReviewTests(unittest.TestCase):
    setUp = fixtures.NetworkTests.setUp
    tearDown = fixtures.NetworkTests.tearDown
    wait_disconnected = fixtures.NetworkTests.wait_disconnected
    connect = fixtures.NetworkTests.connect
    rows = fixtures.NetworkTests.rows

    def test_probe_native_and_bootstrap(self):
        for bootstrap in (False, True):
            rows = probe(port=self.server.server_address[1], bootstrap=bootstrap)
            self.assertTrue(rows[-1]['expected_diagnostic_rejection'])
            self.wait_disconnected()
        rows = self.rows()
        self.assertTrue(any(r['protocol_version'] == 'SMB1-bootstrap' for r in rows))
        for row in rows:
            self.assertIn('source_ip', row)
            self.assertIn('timestamp', row)
            self.assertIn('protocol_version', row)
        stages = [r.get('stage') for r in rows[:11]]
        expected = ['tcp_accepted', 'smb_negotiate_received', 'smb_negotiate_sent',
                    'smb_session_setup_received', 'ntlm_type1_received', 'ntlm_type2_sent',
                    'smb_session_setup_received', 'ntlm_type3_received', 'authentication_finished']
        self.assertEqual(stages[:9], expected)
        self.assertEqual(rows[9]['last_stage'], 'authentication_finished')

    def test_default_impacket_client_bootstrap(self):
        from impacket.smbconnection import SMBConnection
        client = SMBConnection('SMBDIAG', '127.0.0.1', sess_port=self.server.server_address[1], timeout=2)
        try:
            self.assertEqual(client.getDialect(), 0x0202)
        finally:
            client.close()
        self.wait_disconnected()

    def test_drop_ssp_matches_upstream_and_default_is_preserved(self):
        for enabled in (False, True):
            self.server.getServerConfig().set('global', 'DropSSP', str(enabled))
            self.server.processConfigFile()
            with self.connect() as sock:
                exchange(sock, negotiate())
                answer = exchange(sock, setup(ntlm.getNTLMSSPType1().getData()))
                token = smb2.SMB2SessionSetup_Response(answer['Data'])['Buffer']
                flags = int.from_bytes(token[20:24], 'little')
                if enabled:
                    self.assertEqual(flags, ntlm.NTLMSSP_DROP_SSP_STATIC)
                    self.assertFalse(flags & 0x80000)
                else:
                    self.assertTrue(flags & 0x80000)
            self.wait_disconnected()

    def test_dialect_count_ignores_trailing_context_like_bytes(self):
        request = bytearray(negotiate([0x0311]))
        request.extend(b'\x02\x02')  # Not part of the declared list.
        with self.connect() as sock:
            self.assertEqual(exchange(sock, bytes(request))['Status'], 0xc00000bb)
        self.wait_disconnected()
        row = [r for r in self.rows() if r['event'] == 'smb_negotiate'][0]
        self.assertEqual(row['offered_dialects'], ['0x0311'])

    def test_multi_dialect_and_signing_required(self):
        request = bytearray(negotiate([0x0311, 0x0300, 0x0210, 0x0202]))
        request[68:70] = b'\x03\x00'
        with self.connect() as sock:
            self.assertEqual(exchange(sock, bytes(request))['Status'], 0)
        self.wait_disconnected()
        row = [r for r in self.rows() if r['event'] == 'smb_negotiate'][0]
        self.assertTrue(row['signing_required_client'])
        self.assertEqual(row['offered_dialects'], ['0x0311', '0x0300', '0x0210', '0x0202'])
        self.assertEqual(row['dialect'], '0x0202')

    def test_disconnect_after_type2_records_last_stage(self):
        with self.connect() as sock:
            exchange(sock, negotiate())
            exchange(sock, setup(ntlm.getNTLMSSPType1().getData()))
        self.wait_disconnected()
        self.assertEqual(self.rows()[-1]['last_stage'], 'ntlm_type2_sent')
        self.assertFalse(any(r['event'] == 'session_result' for r in self.rows()))

    def test_send_failure_is_not_reported_as_sent(self):
        with patch.object(Handler, 'read_exact', side_effect=[b'\x00\x00\x00\x40', b'x' * 64]):
            with patch.object(self.server, 'processRequest') as process:
                def build(cid, data):
                    self.server.state[cid]['stage'] = 'ntlm_type1_received'
                    self.server.pending(cid, 'ntlm', stage='ntlm_type2_sent', message_type=2)
                    return [b'response']
                process.side_effect = build
                fake = unittest.mock.Mock()
                fake.getsockname.return_value = ('127.0.0.1', self.server.server_address[1])
                fake.sendall.side_effect = ConnectionResetError(10054, 'not logged')
                Handler(fake, ('127.0.0.1', 12345), self.server)
        self.assertFalse(any(r.get('message_type') == 2 for r in self.rows()))
        self.assertEqual(self.rows()[-1]['last_stage'], 'ntlm_type1_received')

    def test_local_probe_cli(self):
        result = subprocess.run([sys.executable, '-m', 'smbdiag.client', '--port', str(self.server.server_address[1])],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(rows[-1]['expected_diagnostic_rejection'])
        self.wait_disconnected()

    @unittest.skipUnless(os.name == 'nt', 'Windows-only: SO_EXCLUSIVEADDRUSE')
    def test_windows_exclusive_bind(self):
        self.assertEqual(self.server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE), 1)
        with socket.socket() as duplicate:
            duplicate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            with self.assertRaises(OSError) as failure:
                duplicate.bind(self.server.server_address)
            self.assertIn(failure.exception.winerror, (10013, 10048))


class ClientFailureTests(unittest.TestCase):
    def test_connection_failure_reports_stage_without_exception_text(self):
        rows = []
        with patch('socket.create_connection', side_effect=OSError(10061, 'SECRET_SENTINEL')):
            with self.assertRaises(ProbeFailure):
                probe(report=rows.append)
        self.assertEqual(rows[-1]['stage'], 'tcp_connect')
        self.assertNotIn('SECRET_SENTINEL', json.dumps(rows))

    def test_cli_unicode_log_path_and_reserved_port(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '日本語 logs'
            result = subprocess.run([sys.executable, '-m', 'smbdiag', '--port', '445'],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            # Bind failure has deterministic Windows errno/winerror metadata and tests UTF-8 paths.
            with socket.socket() as occupied:
                occupied.bind(('127.0.0.1', 0))
                occupied.listen()
                port = occupied.getsockname()[1]
                result = subprocess.run([sys.executable, '-m', 'smbdiag', '--port', str(port),
                                         '--jsonl', str(path / 'events.jsonl'), '--text', str(path / 'events.txt')],
                                        capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            rows = [json.loads(line) for line in (path / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
            self.assertEqual(rows[0]['reason'], 'startup_or_server_failure')
            self.assertEqual(rows[0]['port'], port)
            self.assertIn(rows[0]['error_type'], ('OSError', 'PermissionError'))
            if os.name == 'nt':
                self.assertIn(rows[0]['win_error'], (10013, 10048))

    @unittest.skipUnless(os.name == 'nt', 'Windows-only: PowerShell entry point')
    def test_windows_powershell_entrypoint(self):
        script = Path('Start-SmbDiagnostic.ps1').resolve()
        result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                                 '-File', str(script), '-Port', '445'], capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Use a port other than', result.stderr)

class ConstructorAndSPNEGOTests(unittest.TestCase):
    def test_drop_ssp_constructor(self):
        from smbdiag.server import DiagnosticServer
        from smbdiag.eventlog import EventLog
        import threading
        with tempfile.TemporaryDirectory() as directory:
            events = EventLog(Path(directory) / 'events.jsonl')
            server = DiagnosticServer(('127.0.0.1', 0), events, drop_ssp=True)
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
            thread.start()
            try:
                rows = probe(port=server.server_address[1])
                flags = [r['flags_hex'] for r in rows if r.get('message_type') == 2][0]
                self.assertEqual(flags, f'0x{ntlm.NTLMSSP_DROP_SSP_STATIC:08x}')
            finally:
                server.shutdown()
                server.close_clients()
                server.server_close()
                thread.join(2)
                events.close()
            rows = [json.loads(line) for line in (Path(directory) / 'events.jsonl').read_text().splitlines()]
            self.assertTrue([r for r in rows if r.get('message_type') == 2][0]['drop_ssp'])
            self.assertFalse([r for r in rows if r.get('message_type') == 3][0]['negotiated_ess'])

    def test_spnego_ntlm_first_multiple_mechanisms(self):
        from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
        from smbdiag.metadata import unwrap
        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider'],
                             TypesMech['KRB5 - Kerberos 5']]
        blob['MechToken'] = ntlm.getNTLMSSPType1().getData()
        token, raw = unwrap(blob.getData())
        self.assertFalse(raw)
        self.assertEqual(token, blob['MechToken'])
