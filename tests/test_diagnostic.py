import contextlib
import io
import json
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from impacket import ntlm, smb3structs as smb2
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from smbdiag.eventlog import EventLog
from smbdiag.metadata import inspect, InvalidToken, ESS
from smbdiag.server import DiagnosticServer, validate_port


def type3(lm=b'L' * 24, nt=b'N' * 24, flags=0):
    fields = [lm, nt, b'DOMAIN_SENTINEL', b'USER_SENTINEL', b'HOST_SENTINEL', b'KEY_SENTINEL']
    header = b'NTLMSSP\x00' + struct.pack('<I', 3)
    pos = 64
    for value in fields:
        header += struct.pack('<HHI', len(value), len(value), pos)
        pos += len(value)
    return header + struct.pack('<I', flags) + b''.join(fields)


def v2_response():
    return b'PROOF_SENTINEL!!' + b'\x01\x01' + b'\x00' * 6 + b'T' * 8 + b'C' * 8 + b'\x00' * 12


def packet(command, data, message_id=0, session_id=0):
    item = smb2.SMB2Packet()
    item['Command'] = command
    item['MessageID'] = message_id
    item['SessionID'] = session_id
    item['Data'] = data
    return item.getData()


def negotiate(dialects=None):
    request = smb2.SMB2Negotiate()
    request['Dialects'] = dialects or [smb2.SMB2_DIALECT_002]
    request['DialectCount'] = len(request['Dialects'])
    return packet(smb2.SMB2_NEGOTIATE, request)


def setup(token, mid=1, sid=0):
    request = smb2.SMB2SessionSetup()
    request['SecurityBufferOffset'] = 88
    request['SecurityBufferLength'] = len(token)
    request['Buffer'] = token
    return packet(smb2.SMB2_SESSION_SETUP, request, mid, sid)


def recv_exact(sock, size):
    value = b''
    while len(value) < size:
        chunk = sock.recv(size - len(value))
        if not chunk:
            raise EOFError()
        value += chunk
    return value


def exchange(sock, data):
    sock.sendall(b'\x00' + len(data).to_bytes(3, 'big') + data)
    header = recv_exact(sock, 4)
    return smb2.SMB2Packet(recv_exact(sock, int.from_bytes(header[1:], 'big')))


class MetadataTests(unittest.TestCase):
    def test_formats_and_uncertainty(self):
        self.assertEqual(inspect(type3(), False)['response_format'], 'NTLMv1')
        self.assertEqual(inspect(type3(b'C' * 8 + b'\x00' * 16, flags=ESS), True)['response_format'], 'NTLMv1-ESS')
        self.assertEqual(inspect(type3(nt=v2_response()), False)['response_format'], 'NTLMv2')
        self.assertEqual(inspect(type3(), None)['response_format'], 'unknown')
        self.assertEqual(inspect(type3(flags=ESS), False)['response_format'], 'unknown')
        self.assertEqual(inspect(type3(nt=b''), False)['response_format'], 'empty_or_anonymous')
        self.assertEqual(inspect(type3(nt=v2_response()[:-1]), False)['response_format'], 'unknown')
        self.assertEqual(inspect(type3(nt=v2_response()[:-4]), False)['response_format'], 'NTLMv2')

    def test_malformed(self):
        for value in (b'', b'NTLMSSP\x00' + b'\x03\x00\x00\x00', type3()[:63]):
            with self.assertRaises(InvalidToken):
                inspect(value)
        corrupt = bytearray(type3())
        struct.pack_into('<I', corrupt, 16, 99999)
        with self.assertRaises(InvalidToken):
            inspect(bytes(corrupt))

    def test_reserved_ports(self):
        for port in (0, 139, 445, -1, 65536):
            with self.assertRaises(ValueError):
                validate_port(port)
        self.assertEqual(validate_port(8446), 8446)

    def test_event_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            log = EventLog(Path(directory) / 'events.jsonl')
            try:
                with self.assertRaises(ValueError):
                    log.emit('ntlm', password='SECRET_SENTINEL')
            finally:
                log.close()


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.json = Path(self.tmp.name) / 'events.jsonl'
        self.text = Path(self.tmp.name) / 'events.txt'
        self.events = EventLog(self.json, self.text)
        self.server = DiagnosticServer(('127.0.0.1', 0), self.events, idle_timeout=2)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.02})
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.close_clients()
        self.server.server_close()
        self.thread.join(2)
        self.wait_disconnected()
        self.events.close()
        self.tmp.cleanup()

    def wait_disconnected(self):
        deadline = time.monotonic() + 2
        while self.server.state and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(self.server.state)

    def connect(self):
        return socket.create_connection(self.server.server_address, timeout=2)

    def rows(self):
        return [json.loads(row) for row in self.json.read_text().splitlines()]

    def test_tcp_only(self):
        with self.connect():
            time.sleep(0.03)
        self.wait_disconnected()
        self.assertEqual([r['event'] for r in self.rows()], ['connect', 'disconnect'])

    def test_smb_negotiate(self):
        with self.connect() as sock:
            response = exchange(sock, negotiate())
            self.assertEqual(response['Status'], 0)
            info = smb2.SMB2Negotiate_Response(response['Data'])
            self.assertEqual(info['DialectRevision'], 0x0202)
        self.wait_disconnected()
        self.assertTrue(any(row['event'] == 'smb_negotiate' for row in self.rows()))

    def test_no_common_dialect(self):
        with self.connect() as sock:
            self.assertEqual(exchange(sock, negotiate([0x0311]))['Status'], 0xc00000bb)
        self.wait_disconnected()
        self.assertEqual([r for r in self.rows() if r['event'] == 'smb_negotiate'][0]['reason'], 'no_common_dialect')

    def test_ntlm_and_no_secret_output(self):
        captured = io.StringIO()
        with patch('impacket.smbserver.outputToJohnFormat', side_effect=AssertionError('must never run')) as dump:
            with patch('impacket.smbserver.writeJohnOutputToFile') as write_dump:
                with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                    with self.connect() as sock:
                        exchange(sock, negotiate())
                        token = ntlm.getNTLMSSPType1().getData()
                        response = exchange(sock, setup(token))
                        self.assertEqual(response['Status'], 0xc0000016)
                        auth = smb2.SMB2SessionSetup_Response(response['Data'])
                        self.assertEqual(inspect(auth['Buffer'])['message_type'], 2)
                        response = exchange(sock, setup(type3(nt=v2_response()), 2, response['SessionID']))
                        self.assertEqual(response['Status'], 0xc000006d)
                    self.wait_disconnected()
                dump.assert_not_called()
                write_dump.assert_not_called()
        rows = self.rows()
        self.assertEqual([r['message_type'] for r in rows if r['event'] == 'ntlm'], [1, 2, 3])
        self.assertEqual([r for r in rows if r.get('message_type') == 3][0]['response_format'], 'NTLMv2')
        output = self.json.read_text() + self.text.read_text() + captured.getvalue()
        for secret in ('DOMAIN_SENTINEL', 'USER_SENTINEL', 'HOST_SENTINEL', 'KEY_SENTINEL',
                       'PROOF_SENTINEL', b'PROOF_SENTINEL!!'.hex(), '4e' * 24):
            self.assertNotIn(secret, output)
        self.assertEqual({p.name for p in Path(self.tmp.name).iterdir()}, {'events.jsonl', 'events.txt'})

    def test_upstream_client_negotiate(self):
        from impacket.smbconnection import SMBConnection
        client = SMBConnection('SMBDIAG', '127.0.0.1', sess_port=self.server.server_address[1],
                               preferredDialect=smb2.SMB2_DIALECT_002, timeout=2)
        self.assertEqual(client.getDialect(), smb2.SMB2_DIALECT_002)
        client.close()
        self.wait_disconnected()

    def test_type3_ess_and_v1_network(self):
        for use_ess, expected in ((False, 'NTLMv1'), (True, 'NTLMv1-ESS')):
            with self.connect() as sock:
                exchange(sock, negotiate())
                first = ntlm.getNTLMSSPType1()
                if use_ess:
                    first['flags'] |= ESS
                else:
                    first['flags'] &= ~ESS
                response = exchange(sock, setup(first.getData()))
                self.assertEqual(response['Status'], 0xc0000016)
                blob = SPNEGO_NegTokenResp()
                blob['ResponseToken'] = type3(
                    lm=b'C' * 8 + b'\x00' * 16 if use_ess else b'L' * 24,
                    flags=ESS if use_ess else 0)
                response = exchange(sock, setup(blob.getData(), 2, response['SessionID']))
                self.assertEqual(response['Status'], 0xc000006d)
            self.wait_disconnected()
            row = [r for r in self.rows() if r.get('message_type') == 3][-1]
            self.assertEqual(row['response_format'], expected)

    def test_port_busy(self):
        with self.assertRaises(OSError):
            duplicate = DiagnosticServer(self.server.server_address, self.events)
            duplicate.server_close()

    def test_spnego_type1(self):
        with self.connect() as sock:
            exchange(sock, negotiate())
            blob = SPNEGO_NegTokenInit()
            blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
            blob['MechToken'] = ntlm.getNTLMSSPType1().getData()
            response = exchange(sock, setup(blob.getData()))
            self.assertEqual(response['Status'], 0xc0000016)
        self.wait_disconnected()
        self.assertEqual([r['message_type'] for r in self.rows() if r['event'] == 'ntlm'], [1, 2])

    def test_timeout_and_truncated_frame(self):
        self.server.idle_timeout = 0.1
        with self.connect() as sock:
            self.assertEqual(sock.recv(1), b'')
        self.wait_disconnected()
        with self.connect() as sock:
            sock.sendall(b'\x00\x00\x00\x40short')
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(sock.recv(1), b'')
        self.wait_disconnected()
        reasons = [r.get('reason') for r in self.rows()]
        self.assertIn('timeout', reasons)
        self.assertIn('truncated_frame', reasons)

    def test_bad_frame_and_auth(self):
        with self.connect() as sock:
            sock.sendall(b'\x00\xff\xff\xff')
            self.assertEqual(sock.recv(1), b'')
        self.wait_disconnected()
        with self.connect() as sock:
            exchange(sock, negotiate())
            self.assertEqual(exchange(sock, setup(b'SECRET_SENTINEL'))['Status'], 0xc000000d)
        self.wait_disconnected()
        self.assertNotIn('SECRET_SENTINEL', self.json.read_text() + self.text.read_text())


if __name__ == '__main__':
    unittest.main()
