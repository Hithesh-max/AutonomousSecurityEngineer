"""Bounded local scanner execution; no shell or application secrets in child env."""
from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time

RULES_DIR = Path(__file__).parent / 'rules'
RULE_PACK_VERSION = 'ase-static-1.0'
MAX_OUTPUT = 8 * 1024 * 1024
MAX_FINDINGS = 2000


class ToolFailure(RuntimeError):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)


@dataclass
class ProcessResult:
    returncode: int
    stdout: bytes


def run_process(command: list[str], *, cwd: Path, seconds=180, report: Path | None = None, check=None) -> ProcessResult:
    if not command or not Path(command[0]).is_absolute():
        raise ToolFailure('INVALID_ARGUMENTS', 'Scanner executable must be an operator-installed absolute path.')
    # Child HOME is private; cloud credentials, JWT, DB, and broker config are absent.
    with tempfile.TemporaryDirectory(prefix='ase-tool-home-') as home, tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        env = {'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'), 'HOME': home,
               'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TMPDIR': home,
               'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0', 'OMP_NUM_THREADS': '1'}
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, shell=False, start_new_session=True)
        deadline = time.monotonic() + seconds
        next_check = 0.0
        try:
            while True:
                if check is not None and time.monotonic() >= next_check:
                    check()
                    next_check = time.monotonic() + 1
                sizes = [os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size]
                if report is not None and report.exists(): sizes.append(report.stat().st_size)
                if any(size > MAX_OUTPUT for size in sizes):
                    raise ToolFailure('OUTPUT_LIMIT', 'Scanner output exceeded the configured limit.')
                code = process.poll()
                if code is not None:
                    sizes = [os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size]
                    if report is not None and report.exists(): sizes.append(report.stat().st_size)
                    if any(size > MAX_OUTPUT for size in sizes):
                        raise ToolFailure('OUTPUT_LIMIT', 'Scanner output exceeded the configured limit.')
                    out.seek(0)
                    return ProcessResult(code, out.read(MAX_OUTPUT))
                if time.monotonic() > deadline:
                    raise ToolFailure('TOOL_TIMEOUT', 'Scanner exceeded its execution time limit.')
                time.sleep(0.05)
        finally:
            # Also kill lingering children after parent exit, timeout, or task interruption.
            try:
                if hasattr(os, 'killpg'):
                    os.killpg(process.pid, getattr(signal, 'SIGKILL', signal.SIGTERM))
                else:
                    process.kill()
            except (ProcessLookupError, OSError): pass
            try:
                process.wait(timeout=5)
            except Exception:
                pass


class ControlledAdapter(ABC):
    tool: str
    display_name: str

    def validate_environment(self):
        executable = shutil.which(self.tool)
        if not executable:
            raise FileNotFoundError(f'{self.display_name} executable not found. Cannot proceed with scan.')
        return str(Path(executable).resolve())

    def health_check(self):
        executable = self.validate_environment()
        result = run_process([executable, 'version' if self.tool == 'gitleaks' else '--version'], cwd=RULES_DIR, seconds=10)
        if result.returncode != 0: raise ToolFailure('VERSION_CHECK_FAILED', 'Scanner version check failed.')
        version = re.search(rb'\d+\.\d+(?:\.\d+)?', result.stdout)
        if not version: raise ToolFailure('VERSION_CHECK_FAILED', 'Scanner version could not be recorded.')
        return {'tool': self.tool, 'version': version.group().decode(), 'rule_pack': RULE_PACK_VERSION}

    @abstractmethod
    def execute(self, target: Path): ...

    @abstractmethod
    def parse(self, output: bytes): ...

    @abstractmethod
    def normalize(self, raw_data, project_id): ...

    def scan(self, target_path):
        return self.parse(self.execute(Path(target_path)))


def finding_path(path, root: Path) -> str:
    if not isinstance(path, str) or not path:
        raise ToolFailure('MALFORMED_OUTPUT', 'Scanner finding has no valid source path.')
    root = root.resolve()
    candidate = Path(path)
    if not candidate.is_absolute(): candidate = root / candidate
    try: relative = candidate.resolve().relative_to(root).as_posix()
    except ValueError: raise ToolFailure('MALFORMED_OUTPUT', 'Scanner reported a path outside its workspace.') from None
    if not relative or not candidate.is_file() or candidate.is_symlink():
        raise ToolFailure('MALFORMED_OUTPUT', 'Scanner reported an unavailable source file.')
    return relative


def load_json(output: bytes):
    try: return json.loads(output)
    except (ValueError, UnicodeDecodeError):
        raise ToolFailure('MALFORMED_OUTPUT', 'Scanner returned malformed JSON.') from None
