"""Run without PostgreSQL: python -m unittest discover -s tests/unit -v"""
import hashlib
from pathlib import Path
import os
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from dataclasses import replace
from uuid import uuid4

from app.repositories.archive import ArchiveLimits, ArchiveRejected, extract_zip
from app.repositories.storage import repository_directory


class ArchiveSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = repository_directory(str(self.root), uuid4(), create=True)
        self.archive = self.repo / 'upload.zip'
        self.limits = ArchiveLimits()

    def tearDown(self):
        self.temp.cleanup()

    def write_zip(self, members, compression=zipfile.ZIP_STORED):
        with zipfile.ZipFile(self.archive, 'w', compression=compression) as bundle:
            for name, data in members:
                bundle.writestr(name, data)
        if any(isinstance(n, str) and '\\' in n for n, _ in members):
            raw = self.archive.read_bytes()
            for n, _ in members:
                if isinstance(n, str) and '\\' in n:
                    normalized = n.replace('\\', '/')
                    raw = raw.replace(normalized.encode(), n.encode())
            self.archive.write_bytes(raw)

    def rejects(self, expected, limits=None):
        with self.assertRaises(ArchiveRejected) as ctx:
            extract_zip(self.archive, self.repo, limits or self.limits)
        self.assertEqual(ctx.exception.code, expected)
        self.assertFalse((self.repo / 'source').exists())
        self.assertEqual(list(self.repo.glob('.ingesting-*')), [])

    def test_valid_zip_preserves_bytes_and_checksum(self):
        self.write_zip([('app/main.py', b'print("hello")\n'), ('README.md', b'lab')])
        result = extract_zip(self.archive, self.repo, self.limits)
        self.assertEqual(result.file_count, 2)
        self.assertEqual(result.expanded_bytes, 18)
        self.assertEqual(result.archive_sha256, hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertEqual((self.repo / 'source/app/main.py').read_bytes(), b'print("hello")\n')

    def test_path_traversal_and_absolute_paths(self):
        for name in ['../escape', '/escape', 'a/../../escape', 'C:/escape', 'a\\escape', 'a//b', './app.py']:
            with self.subTest(name=name):
                self.write_zip([(name, b'data')])
                self.rejects('UNSAFE_PATH')
        self.assertFalse((self.root / 'escape').exists())

    def test_symlink_is_rejected(self):
        member = zipfile.ZipInfo('link')
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.write_zip([(member, b'/etc/passwd')])
        self.rejects('SPECIAL_FILE')

    def test_special_device_is_rejected(self):
        member = zipfile.ZipInfo('device')
        member.create_system = 3
        member.external_attr = (stat.S_IFCHR | 0o600) << 16
        self.write_zip([(member, b'')])
        self.rejects('SPECIAL_FILE')

    def test_uploaded_size_limit(self):
        self.write_zip([('a', b'data')])
        self.rejects('UPLOAD_TOO_LARGE', replace(self.limits, upload_bytes=10))

    def test_file_size_limit(self):
        self.write_zip([('a', b'12345')])
        self.rejects('FILE_TOO_LARGE', replace(self.limits, file_bytes=4))

    def test_expansion_limit(self):
        self.write_zip([('a', b'123'), ('b', b'456')])
        self.rejects('EXPANSION_LIMIT', replace(self.limits, expanded_bytes=5))

    def test_zip_bomb_ratio(self):
        self.write_zip([('bomb', b'A' * 100000)], zipfile.ZIP_DEFLATED)
        self.rejects('COMPRESSION_RATIO')

    def test_entry_limit(self):
        self.write_zip([('a', b'a'), ('b', b'b')])
        self.rejects('ENTRY_LIMIT', replace(self.limits, entries=1))

    def test_case_and_unicode_collision(self):
        for members in [[('a.py', b'a'), ('A.py', b'b')], [('caf\u00e9.py', b'a'), ('cafe\u0301.py', b'b')]]:
            with self.subTest(members=members):
                self.write_zip(members)
                self.rejects('DUPLICATE_PATH')

    def test_file_directory_conflict_in_both_orders(self):
        for members in [[('a', b'a'), ('a/b', b'b')], [('a/b', b'b'), ('a', b'a')]]:
            with self.subTest(members=members):
                self.write_zip(members)
                self.rejects('PATH_CONFLICT')

    def test_encrypted_header_rejected(self):
        self.write_zip([('a', b'a')])
        content = bytearray(self.archive.read_bytes())
        start = content.index(b'PK\x01\x02')
        flags = struct.unpack_from('<H', content, start + 8)[0]
        struct.pack_into('<H', content, start + 8, flags | 1)
        self.archive.write_bytes(content)
        self.rejects('ENCRYPTED_ARCHIVE')

    def test_unsupported_compression(self):
        self.write_zip([('a', b'a')], zipfile.ZIP_BZIP2)
        self.rejects('UNSUPPORTED_COMPRESSION')

    def test_malformed_and_crc_corruption_cleanup(self):
        self.archive.write_bytes(b'not a ZIP')
        self.rejects('INVALID_ARCHIVE')
        self.write_zip([('a', b'original')])
        self.archive.write_bytes(self.archive.read_bytes().replace(b'original', b'tampered'))
        self.rejects('INVALID_ARCHIVE')

    def test_existing_source_is_not_overwritten(self):
        self.write_zip([('a', b'a')])
        (self.repo / 'source').mkdir()
        (self.repo / 'source/keep').write_text('keep')
        with self.assertRaises(ArchiveRejected):
            extract_zip(self.archive, self.repo, self.limits)
        self.assertEqual((self.repo / 'source/keep').read_text(), 'keep')

    def test_repository_code_is_never_executed(self):
        marker = self.root / 'executed'
        self.write_zip([('setup.py', f'open({str(marker)!r}, "w").write("bad")'.encode()),
                        ('package.json', b'{"scripts":{"install":"exit 1"}}'),
                        ('script.sh', b'#!/bin/sh\nexit 1')])
        with patch('subprocess.run', side_effect=AssertionError('No process execution allowed')):
            extract_zip(self.archive, self.repo, self.limits)
        self.assertFalse(marker.exists())
        self.assertEqual((self.repo / 'source/script.sh').stat().st_mode & 0o111, 0)

    def test_reserved_and_control_filenames(self):
        for name in ['CON', 'a/nul.txt', 'a/b.', 'bad\nname', 'bad\x00name']:
            with self.subTest(name=name):
                self.write_zip([(name, b'a')])
                # zipfile truncates NULs on creation; other control names survive.
                if '\x00' in name:
                    content = self.archive.read_bytes().replace(b'bad', b'b\x00d')
                    self.archive.write_bytes(content)
                self.rejects('UNSAFE_PATH')

    def test_deadline(self):
        self.write_zip([('a', b'a')])
        with patch('app.repositories.archive.time.monotonic', side_effect=[0, 999]):
            self.rejects('INGESTION_TIMEOUT')

    def test_entry_limit_precedes_zipinfo_allocation(self):
        self.write_zip([('a', b'a'), ('b', b'b')])
        with patch('app.repositories.archive.zipfile.ZipFile', side_effect=AssertionError('Must reject before allocation')):
            self.rejects('ENTRY_LIMIT', replace(self.limits, entries=1))

    def test_forged_directory_count_and_metadata_limit(self):
        self.write_zip([('a', b'a')])
        content = bytearray(self.archive.read_bytes())
        end = content.index(b'PK\x05\x06')
        struct.pack_into('<H', content, end + 8, 2)
        struct.pack_into('<H', content, end + 10, 2)
        self.archive.write_bytes(content)
        self.rejects('INVALID_ARCHIVE')
        member = zipfile.ZipInfo('a')
        member.comment = b'x' * 3000
        self.write_zip([(member, b'a')])
        self.rejects('METADATA_LIMIT', replace(self.limits, entries=1))

    def test_no_files(self):
        self.write_zip([('dir/', b'')])
        self.rejects('EMPTY_REPOSITORY')

    def test_storage_rejects_arbitrary_path_and_symlink(self):
        with self.assertRaises(ValueError):
            repository_directory(str(self.root), '../../etc')
        alias = self.root / 'alias'
        try:
            alias.symlink_to(self.repo, target_is_directory=True)
            with self.assertRaises(ValueError):
                repository_directory(str(alias), uuid4(), create=True)
        except OSError as e:
            if getattr(e, 'winerror', None) == 1314:
                return  # Skip symlink verification on Windows when client lacks privilege
            raise


if __name__ == '__main__':
    unittest.main()
