"""Real scanner smoke test. Run inside worker; never accepts arbitrary targets."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import redis
from app.config.settings import settings
from app.network.scope import LAB_URL, LAB_IP, resolve_lab
from app.scanners.nmap import NmapScanner
from app.scanners.zap import ZAPScanner
from app.scanners.controlled import ToolFailure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authorized-lab', action='store_true', required=True,
                        help='Confirm authorization to test only the included isolated lab.')
    parser.add_argument('--active', action='store_true', help='Explicitly consent to XSS/SQL injection tests against this lab.')
    args = parser.parse_args()
    if not settings.LAB_SCANNING_ENABLED:
        raise ToolFailure('LAB_DISABLED', 'Start using docker-compose.lab.yml first.')
    resolve_lab()
    scanner = NmapScanner(check=resolve_lab)
    version = scanner.health_check()['version']
    ports = scanner.scan(LAB_IP)['ports']
    if not any(p['port'] == 8080 and p['state'] == 'open' for p in ports):
        raise ToolFailure('LAB_NOT_READY', 'The lab HTTP port is not open.')
    print(f'PASS: Nmap {version}: real TCP port 8080 is open.', flush=True)
    connection = redis.Redis.from_url(settings.REDIS_URL, socket_timeout=3, socket_connect_timeout=3)
    lease = connection.lock('ase:lab:zap:exclusive', timeout=900, blocking=False, thread_local=False)
    if not lease.acquire(): raise ToolFailure('ZAP_BUSY', 'Another scan owns ZAP; wait for it to finish.')
    zap, stopped = None, False
    try:
        def check():
            resolve_lab()
            if not lease.owned(): raise PermissionError('ZAP lease lost.')
        zap = ZAPScanner(settings.ZAP_API_KEY.get_secret_value(), check=check)
        version = zap.health_check()['version']
        raw = zap.scan(LAB_URL, active=args.active)
        findings = zap.normalize(raw, None)
        if not findings: raise ToolFailure('NO_LAB_ALERTS', 'The real scan returned no alerts; investigate coverage/add-ons.')
        if args.active and not any(f['tool_rule_id'] in {'40012','40018'} for f in findings):
            raise ToolFailure('SEEDED_ISSUE_NOT_DETECTED', 'Active testing did not detect either seeded XSS or SQL injection issue.')
        zap.stop(); stopped = True
        print(f'PASS: ZAP {version}: {len(raw["endpoints"])} real endpoints; {len(findings)} normalized findings.', flush=True)
        print('PASS: '+('Active' if args.active else 'Crawl/passive')+' lab smoke test. No database findings were written; verify persistence through Web Lab in ASE.')
    finally:
        if zap is not None and not stopped:
            try: zap.stop(); stopped = True
            except ToolFailure: print('STOP UNCONFIRMED: ZAP lease retained until expiry. Restart ZAP before retrying.', file=sys.stderr)
        if (stopped or zap is None) and lease.owned(): lease.release()

if __name__ == '__main__':
    try: main()
    except ToolFailure as exc:
        print(f'FAIL: {exc.code}: {exc.message}', file=sys.stderr); sys.exit(1)
    except Exception as exc:
        print(f'FAIL: {type(exc).__name__}. Check lab/worker connectivity and configuration; details withheld.', file=sys.stderr); sys.exit(1)
