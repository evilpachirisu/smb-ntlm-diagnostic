"""Pinned Impacket protocol engine with a metadata-only authentication boundary."""
import configparser
import importlib.metadata
import os
import socket
import socketserver
import struct
import threading
import uuid
from impacket import smbserver, smb, smb3structs as smb2
from impacket.nt_errors import STATUS_LOGON_FAILURE, STATUS_INVALID_PARAMETER
from .metadata import inspect, unwrap, InvalidToken

MAX_FRAME = 1024 * 1024


class ProtocolError(ValueError):
    pass


def validate_port(port, ephemeral=False):
    if port in (139, 445) or not (0 if ephemeral else 1) <= port <= 65535:
        raise ValueError('Use a port from 1..65535 other than 139/445')
    return port


class Handler(socketserver.BaseRequestHandler):
    def read_exact(self, size, header=False):
        chunks = bytearray()
        while len(chunks) < size:
            part = self.request.recv(size - len(chunks))
            if not part:
                if header and not chunks:
                    return None
                raise EOFError()
            chunks.extend(part)
        return bytes(chunks)

    def handle(self):
        server = self.server
        cid = uuid.uuid4().hex
        reason = 'peer_closed'
        self.request.settimeout(server.idle_timeout)
        server.addConnection(cid, *self.client_address[:2])
        with server.clients_lock:
            server.clients.add(self.request)
        local_ip, local_port = self.request.getsockname()[:2]
        server.event(cid, 'connect', stage='tcp_accepted', local_ip=local_ip, local_port=local_port)
        try:
            while not server.stopping:
                header = self.read_exact(4, header=True)
                if header is None:
                    break
                size = int.from_bytes(header[1:], 'big')
                if header[0] != 0 or size < 32 or size > MAX_FRAME:
                    raise ProtocolError()
                data = self.read_exact(size)
                replies = server.processRequest(cid, data)
                for reply in replies:
                    payload = reply.getData() if hasattr(reply, 'getData') else reply
                    self.request.sendall(b'\x00' + len(payload).to_bytes(3, 'big') + payload)
                server.sent(cid)
                if server.state[cid]['done']:
                    reason = 'diagnostic_complete'
                    break
        except Exception as exc:
            reason = ('timeout' if isinstance(exc, socket.timeout) else
                      'truncated_frame' if isinstance(exc, EOFError) else
                      'invalid_protocol' if isinstance(exc, (ProtocolError, InvalidToken)) else
                      'connection_reset' if isinstance(exc, ConnectionResetError) else 'transport_or_protocol_error')
            server.event(cid, 'error', reason=reason, error_type=type(exc).__name__,
                         os_error=getattr(exc, 'errno', None), win_error=getattr(exc, 'winerror', None))
        finally:
            if server.stopping:
                reason = 'server_shutdown'
            server.event(cid, 'disconnect', reason=reason)
            server.removeConnection(cid)
            with server.clients_lock:
                server.clients.discard(self.request)


class DiagnosticServer(smbserver.SMBSERVER):
    daemon_threads = False
    block_on_close = True

    def __init__(self, address, events, idle_timeout=15, drop_ssp=False, response_observer=None):
        if importlib.metadata.version('impacket') != '0.13.1':
            raise RuntimeError('Impacket 0.13.1 required')
        validate_port(address[1], ephemeral=True)
        self.events = events
        self.response_observer = response_observer
        self.idle_timeout = idle_timeout
        self.state = {}
        self.clients = set()
        self.clients_lock = threading.Lock()
        self.stopping = False
        self.drop_ssp = bool(drop_ssp)
        config = configparser.ConfigParser()
        config['global'] = {
            'server_name': 'SMBDIAG', 'server_os': 'Diagnostic', 'server_domain': 'WORKGROUP',
            'log_file': 'None', 'credentials_file': '', 'jtr_dump_path': '', 'dump_hashes': 'False',
            'SMB2Support': 'True', 'DropSSP': str(bool(drop_ssp)), 'KerberosSupport': 'False',
            'NTLMSupport': 'True', 'anonymous_logon': 'False', 'challenge': os.urandom(8).hex(),
        }
        super().__init__(address, handler_class=Handler, config_parser=config)
        try:
            self.processConfigFile()
            self.hookSmb2Command(smb2.SMB2_NEGOTIATE, self.negotiate)
            self.hookSmb2Command(smb2.SMB2_SESSION_SETUP, self.session_setup)
        except Exception:
            self.server_close()
            raise

    def server_bind(self):
        if os.name == 'nt':
            # Windows SO_REUSEADDR can permit another listener on the same port.
            # Do not call TCPServer.server_bind here: upstream enables reuseaddr.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            self.socket.bind(self.server_address)
            self.server_address = self.socket.getsockname()
        else:
            super().server_bind()

    def log(self, msg, level=20, connData=None):
        # Upstream free-form strings may contain identities or response material.
        # Never forward them, even to an application's configured root logger.
        pass

    def handle_error(self, request, client_address):
        self.events.emit('error', source_ip=client_address[0], reason='handler_failure')

    def event(self, cid, event, **fields):
        state = self.state[cid]
        previous = state['stage']
        if 'stage' in fields:
            state['stage'] = fields['stage']
        self.events.emit(event, connection_id=cid, source_ip=state['ip'],
                         source_port=state['port'], protocol_version=state['protocol'],
                         last_stage=previous, **fields)

    def pending(self, cid, event, **fields):
        self.state[cid]['pending'].append((event, fields))

    def sent(self, cid):
        state = self.state[cid]
        for event, fields in state['pending']:
            self.event(cid, event, **fields)
        state['pending'].clear()

    def addConnection(self, name, ip, port):
        super().addConnection(name, ip, port)
        self.state[name] = dict(ip=ip, port=port, negotiated=False, done=False, ess1=None,
                                ess2=None, stage='tcp_accepted', protocol='unknown', pending=[])

    def removeConnection(self, name):
        super().removeConnection(name)
        self.state.pop(name, None)

    def processRequest(self, cid, data):
        if data[:4] == b'\xffSMB':
            packet = smb.NewSMBPacket(data=data)
            if packet['Command'] != smb.SMB.SMB_COM_NEGOTIATE or self.state[cid]['negotiated']:
                raise ProtocolError()
            command = smb.SMBCommand(packet['Data'][0])
            dialects = command['Data'].split(b'\x02')
            self.state[cid]['protocol'] = 'SMB1-bootstrap'
            self.event(cid, 'smb_negotiate_received', stage='smb_negotiate_received',
                       offered_dialects=[name for wire, name in
                           ((b'SMB 2.002\x00', '0x0202'), (b'SMB 2.???\x00', 'SMB2-wildcard'))
                           if wire in dialects])
            if not any(d in dialects for d in (b'SMB 2.002\x00', b'SMB 2.???\x00')):
                raise ProtocolError()
            result = self.negotiate(cid, self, packet, isSMB1=True)
            return result[1]
        packet = smb2.SMB2Packet(data=data)
        self.state[cid]['protocol'] = 'SMB2.0.2' if self.state[cid]['negotiated'] else 'SMB2'
        if packet['Command'] == smb2.SMB2_NEGOTIATE:
            self.event(cid, 'smb_negotiate_received', stage='smb_negotiate_received')
        elif packet['Command'] == smb2.SMB2_SESSION_SETUP:
            self.event(cid, 'smb_session_setup', stage='smb_session_setup_received')
        if (data[:4] != b'\xfeSMB' or packet['StructureSize'] != 64 or packet['NextCommand'] or
                packet['Flags'] & smb2.SMB2_FLAGS_SERVER_TO_REDIR or
                packet['Command'] not in (smb2.SMB2_NEGOTIATE, smb2.SMB2_SESSION_SETUP)):
            raise ProtocolError()
        if packet['Command'] == smb2.SMB2_NEGOTIATE:
            if len(data) < 100:
                raise ProtocolError()
            size, count = struct.unpack_from('<HH', data, 64)
            if size != 36 or count == 0 or 100 + 2 * count > len(data):
                raise ProtocolError()
        else:
            if len(data) < 88:
                raise ProtocolError()
            size = int.from_bytes(data[64:66], 'little')
            offset = int.from_bytes(data[76:78], 'little')
            length = int.from_bytes(data[78:80], 'little')
            if size != 25 or offset < 88 or not length or offset + length > len(data):
                raise ProtocolError()
        return super().processRequest(cid, data)

    def negotiate(self, cid, server, packet, isSMB1=False):
        state = self.state[cid]
        if state['negotiated']:
            raise ProtocolError()
        if isSMB1:
            offered = ['SMB2-bootstrap']
            signing_required = False
        else:
            count = struct.unpack_from('<H', packet['Data'], 2)[0]
            # Read exactly DialectCount entries; contexts must not become dialects.
            offered = [f'0x{v:04x}' for v in struct.unpack_from('<' + 'H' * count, packet['Data'], 36)]
            signing_required = bool(struct.unpack_from('<H', packet['Data'], 4)[0] & 2)
        # Upstream always selects 0x0202; check it was actually offered.
        if not isSMB1 and '0x0202' not in offered:
            from impacket.nt_errors import STATUS_NOT_SUPPORTED
            state['done'] = True
            self.pending(cid, 'smb_negotiate', stage='smb_negotiate_sent', status=f'0x{STATUS_NOT_SUPPORTED:08x}',
                         reason='no_common_dialect', offered_dialects=offered)
            return [smb2.SMB2Error()], None, STATUS_NOT_SUPPORTED
        result = smbserver.SMB2Commands.smb2Negotiate(cid, self, packet, isSMB1)
        response = smb2.SMB2Negotiate_Response(result[1][0]['Data'].getData())
        state['negotiated'] = True
        state['protocol'] = 'SMB2.0.2'
        # Fresh challenge per connection, never written to logs.
        conn = self.getConnectionData(cid, False)
        conn['_diag_challenge'] = os.urandom(8)
        self.pending(cid, 'smb_negotiate', stage='smb_negotiate_sent', status=f'0x{result[2]:08x}',
                   offered_dialects=offered, signing_required_client=signing_required,
                   dialect=f"0x{response['DialectRevision']:04x}", security_mode=response['SecurityMode'])
        return result

    def session_setup(self, cid, server, packet):
        state = self.state[cid]
        status = STATUS_INVALID_PARAMETER
        try:
            if not state['negotiated']:
                raise InvalidToken()
            setup = smb2.SMB2SessionSetup(packet['Data'])
            token, raw = unwrap(setup['Buffer'])
            ess = None if state['ess1'] is None or state['ess2'] is None else state['ess1'] and state['ess2']
            meta = inspect(token, ess)
            self.event(cid, 'ntlm', stage=f"ntlm_type{meta['message_type']}_received", direction='client_to_server', **meta)
            if meta['message_type'] == 1 and state['ess1'] is None:
                conn = self.getConnectionData(cid, False)
                # Reuse Type 2 construction only; Type 3 never reaches upstream.
                response, status = smbserver.SMB2Commands._ntlm_auth(token, conn, self, raw)
                conn['CHALLENGE_MESSAGE']['challenge'] = conn['_diag_challenge']
                # Rebuild the response token after replacing the per-server challenge.
                challenge = conn['CHALLENGE_MESSAGE'].getData()
                if raw:
                    response['Buffer'] = challenge
                else:
                    from impacket.spnego import SPNEGO_NegTokenResp
                    wrapper = SPNEGO_NegTokenResp(response['Buffer'])
                    wrapper['ResponseToken'] = challenge
                    response['Buffer'] = wrapper.getData()
                response['SecurityBufferLength'] = len(response['Buffer'])
                state['ess1'] = meta['ess']
                meta2 = inspect(challenge)
                state['ess2'] = meta2['ess']
                self.pending(cid, 'ntlm', stage='ntlm_type2_sent', direction='server_to_client',
                             status=f'0x{status:08x}', drop_ssp=self.drop_ssp, **meta2)
                return [response], None, status
            if meta['message_type'] == 3:
                if ess is not None and self.response_observer is not None:
                    # Never send response material through EventLog or authentication.
                    # Formatting/display failures must not affect diagnostics.
                    try:
                        from .evidence import format_response
                        conn = self.getConnectionData(cid, False)
                        evidence = format_response(token, conn['CHALLENGE_MESSAGE']['challenge'], meta['response_format'])
                        if evidence is not None:
                            self.response_observer(cid, state['ip'], state['port'], *evidence)
                    except Exception:
                        pass
                status = STATUS_LOGON_FAILURE
                reason = 'diagnostic_only_no_credential_validation' if ess is not None else 'type3_out_of_sequence'
            else:
                reason = 'unexpected_ntlm_message'
        except Exception as exc:
            # Exception messages can contain attacker-controlled bytes.
            reason = 'invalid_auth_token'
            self.event(cid, 'error', reason=reason, error_type=type(exc).__name__)
        state['done'] = True
        self.pending(cid, 'session_result', stage='authentication_finished', status=f'0x{status:08x}', reason=reason)
        return [smb2.SMB2Error()], None, status

    def close_clients(self):
        self.stopping = True
        with self.clients_lock:
            for client in self.clients:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
