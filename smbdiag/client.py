"""Synthetic diagnostic client: no credential inputs, no raw token output."""
import argparse
import json
import socket
import struct
from impacket import ntlm, smb, smb3structs as smb2
from .metadata import unwrap, inspect, ESS


class ProbeFailure(Exception):
    pass


def recv_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError()
        data.extend(part)
    return bytes(data)


def exchange(sock, payload):
    sock.sendall(b'\x00' + len(payload).to_bytes(3, 'big') + payload)
    header = recv_exact(sock, 4)
    size = int.from_bytes(header[1:], 'big')
    if header[0] or size < 64 or size > 1024 * 1024:
        raise ProbeFailure()
    return smb2.SMB2Packet(recv_exact(sock, size))


def request(command, body, mid=0, sid=0):
    packet = smb2.SMB2Packet()
    packet['Command'], packet['Data'] = command, body
    packet['MessageID'], packet['SessionID'] = mid, sid
    return packet.getData()


def session(token, mid=1, sid=0):
    body = smb2.SMB2SessionSetup()
    body['Buffer'], body['SecurityBufferLength'] = token, len(token)
    return request(smb2.SMB2_SESSION_SETUP, body, mid, sid)


def synthetic_type3(ess):
    # Deliberately invalid proof; structured v2 blob, empty identity/key fields.
    response = b'\x00' * 16 + b'\x01\x01' + b'\x00' * 30
    fields = [b'', response, b'', b'', b'', b'']
    header = b'NTLMSSP\x00' + struct.pack('<I', 3)
    offset = 64
    for item in fields:
        header += struct.pack('<HHI', len(item), len(item), offset)
        offset += len(item)
    return header + struct.pack('<I', ntlm.NTLMSSP_NEGOTIATE_UNICODE | (ESS if ess else 0)) + b''.join(fields)


def probe(host='127.0.0.1', port=8446, timeout=5, bootstrap=False, report=None):
    """Return only safe stage/status metadata; report progress even on failure."""
    report = report or (lambda row: None)
    rows = []
    stage = 'tcp_connect'

    def record(**fields):
        row = dict(stage=stage, **fields)
        rows.append(row)
        report(row)

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            record(result='connected')
            stage = 'smb_negotiate'
            if bootstrap:
                packet = smb.NewSMBPacket()
                packet['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS
                body = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)
                body['Data'] = b'\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00'
                packet.addCommand(body)
                payload = packet.getData()
            else:
                body = smb2.SMB2Negotiate()
                body['Dialects'] = [0x0202, 0x0210]
                body['DialectCount'] = 2
                payload = request(smb2.SMB2_NEGOTIATE, body)
            answer = exchange(sock, payload)
            record(status=f"0x{answer['Status']:08x}")
            if answer['Status'] != 0:
                raise ProbeFailure()
            dialect = smb2.SMB2Negotiate_Response(answer['Data'])['DialectRevision']
            if dialect != 0x0202:
                raise ProbeFailure()
            record(dialect=f'0x{dialect:04x}')
            stage = 'ntlm_type1_to_type2'
            first = ntlm.getNTLMSSPType1().getData()
            answer = exchange(sock, session(first))
            record(status=f"0x{answer['Status']:08x}")
            if answer['Status'] != 0xc0000016:
                raise ProbeFailure()
            response = smb2.SMB2SessionSetup_Response(answer['Data'])
            token, _ = unwrap(response['Buffer'])
            metadata = inspect(token)
            if metadata['message_type'] != 2:
                raise ProbeFailure()
            record(message_type=2, flags_hex=metadata['flags_hex'], ess=metadata['ess'])
            stage = 'ntlm_type3_to_finish'
            answer = exchange(sock, session(synthetic_type3(metadata['ess']), 2, answer['SessionID']))
            record(status=f"0x{answer['Status']:08x}", expected_diagnostic_rejection=answer['Status'] == 0xc000006d)
            if answer['Status'] != 0xc000006d:
                raise ProbeFailure()
        return rows
    except Exception as exc:
        record(result='failed', error_type=type(exc).__name__, os_error=getattr(exc, 'errno', None),
               win_error=getattr(exc, 'winerror', None))
        raise ProbeFailure() from None


def main():
    parser = argparse.ArgumentParser(description='Synthetic SMB/NTLM probe for the diagnostic listener')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8446)
    parser.add_argument('--timeout', type=float, default=5)
    parser.add_argument('--bootstrap', action='store_true', help='Start with SMB1-format multi-protocol Negotiate')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or args.timeout <= 0:
        parser.error('Invalid port or timeout')
    try:
        probe(args.host, args.port, args.timeout, args.bootstrap,
              report=lambda row: print(json.dumps(row), flush=True))
    except ProbeFailure:
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
