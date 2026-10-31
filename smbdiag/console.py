"""ASCII event and opt-in evidence presentation; no protocol parsing or classification."""
import ipaddress
import json
import re
import sys
import threading

REASONS = {
    'peer_closed': 'peer closed', 'diagnostic_complete': 'diagnostic complete',
    'timeout': 'timeout', 'truncated_frame': 'incomplete frame',
    'invalid_protocol': 'invalid/unsupported protocol', 'connection_reset': 'connection reset',
    'transport_or_protocol_error': 'transport/protocol error', 'server_shutdown': 'server shutdown',
    'handler_failure': 'connection handler failed', 'startup_or_server_failure': 'startup/server failed; see log',
    'invalid_auth_token': 'invalid/unsupported auth token', 'no_common_dialect': 'no common SMB dialect',
    'type3_out_of_sequence': 'Type 3 out of sequence',
    'unexpected_ntlm_message': 'unexpected NTLM message',
    'diagnostic_only_no_credential_validation': 'diagnostic rejection; credentials not validated',
}
BASES = {
    'unrecognized_nt_response_structure': 'unrecognized NT response structure',
    'missing_type1_or_type2': 'Type 1/2 metadata missing',
    'ess_response_inconsistent': 'response structure inconsistent with ESS',
    'ess_flags_inconsistent': 'ESS flags inconsistent',
    'no_nt_response': 'empty NT response; anonymous not established',
}
DIALECTS = {'0x0202': '2.0.2', '0x0210': '2.1', '0x0300': '3.0',
            '0x0302': '3.0.2', '0x0311': '3.1.1'}


def endpoint(ip, port):
    # Never render arbitrary event values, identities, or terminal escape sequences.
    try:
        host = str(ipaddress.ip_address(ip))
    except (ValueError, TypeError):
        host = '?'
    number = str(port) if type(port) is int and 0 <= port <= 65535 else '?'
    return f'[{host}]:{number}' if ':' in host else f'{host}:{number}'


class ConsoleDisplay:
    def __init__(self, stream=None, quiet=False, show_netntlm=False):
        self.stream = stream if stream is not None else sys.stdout
        self.quiet = quiet
        self.show_netntlm = show_netntlm
        self.lock = threading.Lock()
        self.connections = {}
        self.disabled = False

    def __call__(self, row):
        if self.quiet or self.disabled:
            return
        with self.lock:
            lines = self.render(row)
            if lines:
                try:
                    self.stream.write('\n'.join(lines) + '\n')
                    self.stream.flush()
                except (OSError, UnicodeError, ValueError):
                    # A closed console/pipe must not interrupt diagnostics or file logging.
                    self.disabled = True
                    self.connections.clear()

    def render(self, row):
        event = row.get('event')
        cid = row.get('connection_id')
        if event == 'listen':
            return ['[*] SMB Diagnostic Server started',
                    '[*] Listening: ' + endpoint(row.get('bind'), row.get('port')),
                    '[*] DropSSP: ' + ('Enabled' if row.get('drop_ssp') else 'Disabled')] + (
                    ['[!] NetNTLM evidence display: Enabled'] if self.show_netntlm else [])
        if event == 'stop':
            self.connections.clear()
            return ['[*] SMB Diagnostic Server stopped']
        tag = endpoint(row.get('source_ip', row.get('bind')), row.get('source_port', row.get('port')))
        if isinstance(cid, str) and re.fullmatch(r'[0-9a-fA-F]+', cid):
            tag += ' [id=' + cid[:8] + ']'
        if event == 'connect':
            self.connections[cid] = False
            return ['[+] ' + tag + ' Connected']
        if event == 'smb_negotiate':
            dialect = DIALECTS.get(row.get('dialect'))
            if dialect:
                return ['[*] ' + tag + ' SMB ' + dialect]
            return ['[!] ' + tag + ' SMB negotiation failed (' + self.reason(row) + ')']
        if event == 'ntlm' and row.get('message_type') == 2 and row.get('direction') == 'server_to_client':
            ess = 'ON' if row.get('ess') is True else 'OFF' if row.get('ess') is False else 'Unknown'
            return ['[*] ' + tag + ' NTLM Type 2 sent (ESS: ' + ess + ')']
        if event == 'ntlm' and row.get('message_type') == 3 and row.get('direction') == 'client_to_server':
            self.connections[cid] = True
            # This is a label mapping of the existing classifier result, not another classifier.
            form = row.get('response_format')
            label = {'NTLMv1': 'NTLMv1', 'NTLMv1-ESS': 'NTLMv1 (ESS)', 'NTLMv2': 'NTLMv2'}.get(form)
            if label:
                marker = '[+]' if form == 'NTLMv2' else '[!]'
                return [marker + ' ' + tag + ' >>> ' + label + ' detected (format estimate) <<<']
            basis = BASES.get(row.get('classification_basis'), 'classification unavailable; see log')
            return ['[!] ' + tag + ' >>> Unknown (' + basis + ') <<<']
        if event == 'error':
            return ['[!] ' + tag + ' Error (' + self.reason(row) + ')']
        if event == 'disconnect':
            received = self.connections.pop(cid, False)
            result = '' if received else '; NTLM version undetermined: Type 3 not parsed'
            return ['[-] ' + tag + ' Disconnected (' + self.reason(row) + result + ')']
        return []

    def show_response(self, cid, ip, port, label, hash_string):
        """Separate opt-in console channel; never submits secrets to EventLog."""
        if not self.show_netntlm or self.quiet or self.disabled:
            return
        if label not in ('NetNTLMv1', 'NetNTLMv1 (ESS)', 'NetNTLMv2'):
            return
        tag = endpoint(ip, port)
        if isinstance(cid, str) and re.fullmatch(r'[0-9a-fA-F]+', cid):
            tag += ' [id=' + cid[:8] + ']'
        # Escape controls/Unicode for terminal safety, preserving colon/hex fields.
        safe = json.dumps(hash_string, ensure_ascii=True)[1:-1]
        with self.lock:
            try:
                self.stream.write('[!] ' + tag + ' ' + label + ': ' + safe + '\n')
                self.stream.flush()
            except (OSError, UnicodeError, ValueError):
                self.disabled = True
                self.connections.clear()

    @staticmethod
    def reason(row):
        return REASONS.get(row.get('reason'), 'see event log')
