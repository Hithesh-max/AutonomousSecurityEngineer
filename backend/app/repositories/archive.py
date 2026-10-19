"""Bounded, non-executing ZIP extraction. No extractall, shell, or repo imports."""
from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
import shutil
import stat
import struct
import tempfile
import time
import unicodedata
import zipfile
import zlib


class ArchiveRejected(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)  # Static descriptions only; never archive content.


@dataclass(frozen=True)
class ArchiveLimits:
    upload_bytes: int = 20 * 1024 * 1024
    expanded_bytes: int = 100 * 1024 * 1024
    file_bytes: int = 5 * 1024 * 1024
    entries: int = 3000
    compression_ratio: int = 100
    seconds: int = 90


@dataclass(frozen=True)
class ExtractionResult:
    file_count: int
    expanded_bytes: int
    archive_sha256: str


_RESERVED = {'con', 'prn', 'aux', 'nul', *(f'com{i}' for i in range(1, 10)),
             *(f'lpt{i}' for i in range(1, 10))}


def safe_member_path(info: zipfile.ZipInfo) -> tuple[str, bool]:
    # orig_filename preserves NULs which ZipInfo.filename otherwise truncates.
    name = info.orig_filename
    if not name or len(name.encode('utf-8')) > 1024 or '\\' in name or ':' in name:
        raise ArchiveRejected('UNSAFE_PATH', 'ZIP contains an unsafe filename.')
    if any(unicodedata.category(c).startswith('C') for c in name):
        raise ArchiveRejected('UNSAFE_PATH', 'ZIP contains an unsafe filename.')
    is_dir = name.endswith('/')
    parts = name[:-1].split('/') if is_dir else name.split('/')
    if len(parts) > 32 or any(p in ('', '.', '..') for p in parts):
        raise ArchiveRejected('UNSAFE_PATH', 'ZIP contains an unsafe path.')
    for part in parts:
        if len(part.encode('utf-8')) > 240 or part.endswith((' ', '.')):
            raise ArchiveRejected('UNSAFE_PATH', 'ZIP contains an unsafe filename.')
        if part.split('.')[0].casefold() in _RESERVED:
            raise ArchiveRejected('UNSAFE_PATH', 'ZIP contains a reserved filename.')
    mode = (info.external_attr >> 16) & 0o170000
    if mode not in (0, stat.S_IFREG, stat.S_IFDIR) or (mode == stat.S_IFDIR and not is_dir):
        raise ArchiveRejected('SPECIAL_FILE', 'ZIP symlinks and special files are not allowed.')
    if is_dir and (info.file_size or mode == stat.S_IFREG):
        raise ArchiveRejected('SPECIAL_FILE', 'ZIP directory metadata is invalid.')
    if info.flag_bits & 1:
        raise ArchiveRejected('ENCRYPTED_ARCHIVE', 'Encrypted ZIP files are not supported.')
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise ArchiveRejected('UNSUPPORTED_COMPRESSION', 'Use a stored or Deflate ZIP archive.')
    return '/'.join(parts), is_dir


def _check_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise ArchiveRejected('INGESTION_TIMEOUT', 'ZIP extraction exceeded its time limit.')


def _preflight_directory(archive: Path, limits: ArchiveLimits) -> None:
    """Count central-directory records before ZipFile allocates ZipInfo objects.

    Large metadata/ZIP64/multi-volume archives are intentionally unsupported.
    """
    with archive.open('rb') as handle:
        size = archive.stat().st_size
        handle.seek(max(0, size - 65557))
        tail = handle.read(65557)
        offset = tail.rfind(b'PK\x05\x06')
        if offset < 0 or len(tail) - offset < 22:
            raise ArchiveRejected('INVALID_ARCHIVE', 'ZIP end record is invalid.')
        signature, disk, cd_disk, local_count, count, cd_size, cd_offset, comment_length = struct.unpack_from('<4s4H2LH', tail, offset)
        end_offset = max(0, size - 65557) + offset
        if offset + 22 + comment_length != len(tail):
            raise ArchiveRejected('INVALID_ARCHIVE', 'ZIP end record is invalid.')
        if disk or cd_disk or local_count != count or count == 65535 or cd_offset == 0xffffffff or cd_size == 0xffffffff:
            raise ArchiveRejected('UNSUPPORTED_ARCHIVE', 'ZIP64 and multi-volume ZIP files are not supported.')
        if count == 0 or count > limits.entries:
            raise ArchiveRejected('ENTRY_LIMIT', 'ZIP is empty or contains too many entries.')
        if cd_size > limits.entries * 2048 or cd_offset + cd_size != end_offset:
            raise ArchiveRejected('METADATA_LIMIT', 'ZIP directory metadata is excessive or inconsistent.')
        handle.seek(cd_offset)
        actual_count = 0
        while handle.tell() < end_offset:
            header = handle.read(46)
            if len(header) != 46 or header[:4] != b'PK\x01\x02':
                raise ArchiveRejected('INVALID_ARCHIVE', 'ZIP directory records are invalid.')
            name_size, extra_size, comment_size = struct.unpack_from('<3H', header, 28)
            actual_count += 1
            if actual_count > limits.entries:
                raise ArchiveRejected('ENTRY_LIMIT', 'ZIP contains too many entries.')
            handle.seek(name_size + extra_size + comment_size, 1)
            if handle.tell() > end_offset:
                raise ArchiveRejected('INVALID_ARCHIVE', 'ZIP directory records are invalid.')
        if actual_count != count:
            raise ArchiveRejected('INVALID_ARCHIVE', 'ZIP entry count is inconsistent.')


def extract_zip(archive: Path, repository_dir: Path, limits: ArchiveLimits) -> ExtractionResult:
    """Publish source/ only after every member passes validation and CRC checks.

    repository_dir is created exclusively by the server in private managed storage.
    Untrusted contents have no access to that directory during extraction.
    """
    if archive.is_symlink() or not archive.is_file():
        raise ArchiveRejected('WORKSPACE_ERROR', 'Managed upload is missing or unsafe.')
    if repository_dir.is_symlink() or not repository_dir.is_dir():
        raise ArchiveRejected('WORKSPACE_ERROR', 'Managed workspace is missing or unsafe.')
    if archive.stat().st_size > limits.upload_bytes:
        raise ArchiveRejected('UPLOAD_TOO_LARGE', 'ZIP exceeds the upload limit.')
    destination = repository_dir / 'source'
    if destination.exists() or destination.is_symlink():
        raise ArchiveRejected('WORKSPACE_ERROR', 'Source workspace already exists.')
    _preflight_directory(archive, limits)
    deadline = time.monotonic() + limits.seconds
    staging = None
    digest = hashlib.sha256()
    with archive.open('rb') as source:
        for chunk in iter(lambda: source.read(65536), b''):
            _check_deadline(deadline)
            digest.update(chunk)
    try:
        with zipfile.ZipFile(archive, 'r') as bundle:
            entries = bundle.infolist()
            if not entries or len(entries) > limits.entries:
                raise ArchiveRejected('ENTRY_LIMIT', 'ZIP is empty or contains too many entries.')
            validated = []
            seen = {}
            implicit_dirs = set()
            declared_total = 0
            for info in entries:
                _check_deadline(deadline)
                relative, is_dir = safe_member_path(info)
                key = unicodedata.normalize('NFC', relative).casefold()
                if key in seen:
                    raise ArchiveRejected('DUPLICATE_PATH', 'ZIP contains duplicate or ambiguous paths.')
                ancestors = [key.rsplit('/', len(key.split('/')) - i)[0]
                             for i in range(1, len(key.split('/')))]
                if any(seen.get(parent) == 'file' for parent in ancestors):
                    raise ArchiveRejected('PATH_CONFLICT', 'ZIP has conflicting file and directory paths.')
                if not is_dir and key in implicit_dirs:
                    raise ArchiveRejected('PATH_CONFLICT', 'ZIP has conflicting file and directory paths.')
                seen[key] = 'dir' if is_dir else 'file'
                implicit_dirs.update(ancestors)
                if not is_dir:
                    if info.file_size > limits.file_bytes:
                        raise ArchiveRejected('FILE_TOO_LARGE', 'ZIP contains a file exceeding the size limit.')
                    declared_total += info.file_size
                    if declared_total > limits.expanded_bytes:
                        raise ArchiveRejected('EXPANSION_LIMIT', 'ZIP exceeds the expanded-size limit.')
                    if info.file_size > max(info.compress_size, 1) * limits.compression_ratio:
                        raise ArchiveRejected('COMPRESSION_RATIO', 'ZIP exceeds the compression-ratio limit.')
                validated.append((info, relative, is_dir))
            if all(is_dir for _, _, is_dir in validated):
                raise ArchiveRejected('EMPTY_REPOSITORY', 'ZIP contains no files.')
            staging = Path(tempfile.mkdtemp(prefix='.ingesting-', dir=repository_dir))
            total = count = 0
            for info, relative, is_dir in validated:
                _check_deadline(deadline)
                output = staging.joinpath(*relative.split('/'))
                if is_dir:
                    output.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                size = 0
                with bundle.open(info, 'r') as src, output.open('xb') as dst:
                    os.chmod(output, 0o600)  # Never preserve executable/setuid archive permissions.
                    while True:
                        _check_deadline(deadline)
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        size += len(chunk)
                        total += len(chunk)
                        if size > limits.file_bytes or total > limits.expanded_bytes:
                            raise ArchiveRejected('EXPANSION_LIMIT', 'ZIP exceeds extraction limits.')
                        dst.write(chunk)
                if size != info.file_size:
                    raise ArchiveRejected('INVALID_ARCHIVE', 'ZIP member size is inconsistent.')
                count += 1
            _check_deadline(deadline)
            staging.rename(destination)
            staging = None
            return ExtractionResult(count, total, digest.hexdigest())
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, zlib.error, NotImplementedError) as exc:
        raise ArchiveRejected('INVALID_ARCHIVE', 'ZIP is malformed or corrupt.') from None
    finally:
        if staging is not None:
            shutil.rmtree(staging)
