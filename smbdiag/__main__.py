import argparse
from pathlib import Path
from .eventlog import EventLog
from .console import ConsoleDisplay
from .server import DiagnosticServer, validate_port


def main():
    parser = argparse.ArgumentParser(description='Metadata-only SMB2/NTLM diagnostic listener')
    parser.add_argument('--show-netntlm', action='store_true', help='Display observed NetNTLMv1/v2 challenge-response evidence on console only')
    parser.add_argument('--quiet', action='store_true', help='Suppress runtime console output; keep file logs')
    parser.add_argument('--bind', default='127.0.0.1', help='IPv4 listen address')
    parser.add_argument('--port', type=int, default=8446)
    parser.add_argument('--drop-ssp', action='store_true', help='Use upstream DropSSP Type 2 flags (default: off)')
    parser.add_argument('--jsonl', default='logs/events.jsonl')
    parser.add_argument('--text', default='logs/events.txt')
    parser.add_argument('--format', choices=['both', 'jsonl', 'text'], default='both')
    parser.add_argument('--idle-timeout', type=float, default=15)
    args = parser.parse_args()
    try:
        validate_port(args.port)
        if not 0 < args.idle_timeout <= 300:
            raise ValueError('idle-timeout must be >0 and <=300')
        if args.format == 'both' and Path(args.jsonl).resolve() == Path(args.text).resolve():
            raise ValueError('JSONL and text paths must differ')
    except ValueError as exc:
        parser.error(str(exc))
    console = ConsoleDisplay(quiet=args.quiet, show_netntlm=args.show_netntlm)
    events = EventLog(args.jsonl if args.format != 'text' else None,
                      args.text if args.format != 'jsonl' else None,
                      observer=console)
    server = None
    try:
        server = DiagnosticServer((args.bind, args.port), events, args.idle_timeout, drop_ssp=args.drop_ssp,
                                  response_observer=console.show_response if args.show_netntlm and not args.quiet else None)
        events.emit('listen', stage='listening', bind=args.bind, port=server.server_address[1], drop_ssp=args.drop_ssp)
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        events.emit('error', reason='startup_or_server_failure', error_type=type(exc).__name__,
                    os_error=getattr(exc, 'errno', None), win_error=getattr(exc, 'winerror', None), bind=args.bind, port=args.port)
        return 1
    finally:
        if server:
            server.close_clients()
            server.server_close()
        events.emit('stop', reason='server_stopped')
        events.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
