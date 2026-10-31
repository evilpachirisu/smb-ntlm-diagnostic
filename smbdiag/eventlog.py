"""Allowlisted, thread-safe JSONL and text output. No arbitrary message fields."""
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

FIELDS = frozenset('connection_id source_ip source_port message_type direction flags_hex flag_names ess '
                   'response_format classification_basis lm_response_length nt_response_length negotiated_ess '
                   'status dialect security_mode reason error_type os_error port bind stage last_stage protocol_version '
                   'local_ip local_port offered_dialects signing_required_client win_error drop_ssp '.split())
EVENTS = frozenset('listen connect disconnect error ntlm smb_negotiate smb_negotiate_received smb_session_setup session_result stop'.split())


class EventLog:
    def __init__(self, jsonl=None, text=None, observer=None):
        self.lock = threading.Lock()
        self.observer = observer
        self.streams = []
        try:
            for kind, path in (('json', jsonl), ('text', text)):
                if path:
                    path = Path(path)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    self.streams.append((kind, path.open('a', encoding='utf-8')))
        except Exception:
            self.close()
            raise

    def emit(self, event, **fields):
        if event not in EVENTS or fields.keys() - FIELDS:
            raise ValueError('Event schema violation')
        row = dict(timestamp=datetime.now(timezone.utc).isoformat(), event=event, **fields)
        # JSON encoding also escapes control characters in text logs.
        with self.lock:
            for kind, stream in self.streams:
                if kind == 'json':
                    line = json.dumps(row, ensure_ascii=True)
                else:
                    line = row['timestamp'] + ' ' + event + ' ' + ' '.join(
                        f'{key}={json.dumps(value, ensure_ascii=True)}' for key, value in fields.items())
                stream.write(line + '\n')
                stream.flush()
            if self.observer is not None:
                try:
                    self.observer(dict(row))
                except Exception:
                    # Presentation failures must never stop the protocol or change file logs.
                    self.observer = None

    def close(self):
        for _, stream in self.streams:
            stream.close()
        self.streams.clear()
