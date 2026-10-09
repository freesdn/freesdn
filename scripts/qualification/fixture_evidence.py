# SPDX-License-Identifier: AGPL-3.0-only
"""Retain one disposable-engine attempt, including uncertain outcomes.

This is a trusted local-filesystem/engine protocol, not containment of a
privileged administrator. Descriptor acquisition and synchronization are normal
OS operations, not hard realtime calls. No directory is removed automatically.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time
import uuid
from pathlib import Path

from qualification.migration_io import IOPolicy, operate, seconds

MIB = 1024**2


def _parent(path):
    """Pin every existing directory component without following symlinks."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in path.parts[1:]:
            if name in {'.', '..'}:
                raise ValueError('Unsafe evidence path')
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('Evidence parent must be owned and not group/world writable')
        return fd
    except BaseException:
        os.close(fd)
        raise


class FixtureAttempt:
    """Exclusive result admission, append-only intent and finite phase budgets."""

    def __init__(self, report, *, work_seconds=900):
        seconds(work_seconds, maximum=900)
        self.report = Path(os.path.abspath(report))
        self.path = self.report.with_name(self.report.name + '.artifacts')
        self.owner = 'freesdn-db-qualification-' + uuid.uuid4().hex
        self.started = time.monotonic()
        self.work_deadline = self.started + work_seconds
        self.total_deadline = self.work_deadline + 60 + 120
        self.active_deadline = self.work_deadline
        self.phase = 'work'
        self._sequence = 0
        self._metadata_bytes = 0
        self._log_bytes = 0
        self._parent_fd = _parent(self.report.parent)
        self._fd = None
        self._events_fd = None
        try:
            try:
                os.stat(self.report.name, dir_fd=self._parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError('Refusing an existing report')
            os.mkdir(self.path.name, mode=0o700, dir_fd=self._parent_fd)
            self._fd = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._parent_fd)
            self._identity = os.fstat(self._fd)
            os.mkdir('events', mode=0o700, dir_fd=self._fd)
            os.mkdir('work', mode=0o700, dir_fd=self._fd)
            os.mkdir('logs', mode=0o700, dir_fd=self._fd)
            self._events_fd = os.open('events', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._fd)
            self.work = self.path/'work'
            self.io_policy = IOPolicy(file_bytes=64*MIB, workspace_bytes=256*MIB, operation_seconds=work_seconds)
            self._json(self._fd, 'intent.json', {
                'format':1, 'owner':self.owner, 'report':str(self.report), 'work':str(self.work),
                'work_seconds':work_seconds, 'evidence_seconds':60, 'cleanup_seconds':120,
                'automatic_retry':False, 'qualification_complete':False,
                'limits':{'events':128,'metadata_bytes':2*MIB,'log_total_bytes':16*MIB,
                          'log_file_bytes':MIB,'work_entries':128,'work_files':64,
                          'work_file_bytes':64*MIB,'work_total_bytes':256*MIB},
            })
            os.fsync(self._fd)
            os.fsync(self._parent_fd)
        except BaseException:
            self.close()
            raise

    def _check(self):
        current = os.stat(self.path.name, dir_fd=self._parent_fd, follow_symlinks=False)
        named = os.stat(self.path, follow_symlinks=False)
        expected = self._identity.st_dev, self._identity.st_ino
        if (not stat.S_ISDIR(current.st_mode) or current.st_mode & 0o077
                or current.st_uid != os.geteuid()
                or (current.st_dev, current.st_ino) != expected
                or (named.st_dev, named.st_ino) != expected):
            raise RuntimeError('Evidence directory identity changed')

    def deadline(self, timeout=120):
        seconds(timeout, maximum=120)
        self._check()
        end = min(self.active_deadline, time.monotonic()+timeout)
        if time.monotonic() >= end:
            raise TimeoutError('Fixture phase deadline exceeded')
        return end

    def begin_evidence(self):
        if self.phase != 'work':
            raise RuntimeError('Invalid evidence phase transition')
        self.phase = 'evidence'
        self.active_deadline = min(time.monotonic()+60, self.total_deadline-120)

    def begin_cleanup(self):
        if self.phase != 'evidence':
            raise RuntimeError('Invalid cleanup phase transition')
        self.phase = 'cleanup'
        self.active_deadline = min(time.monotonic()+120, self.total_deadline)

    def _write(self, directory, name, data):
        if not name or '/' in name or name in {'.', '..'} or type(data) is not bytes:
            raise ValueError('Invalid evidence write')
        self._check()
        free = os.fstatvfs(directory)
        reserve = min(4*1024**3, free.f_blocks*free.f_frsize//4)
        if free.f_bavail*free.f_frsize-len(data) < reserve:
            raise OSError('Evidence filesystem reserve would be crossed')
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            pending = memoryview(data)
            while pending:
                written = os.write(fd, pending)
                if written <= 0:
                    raise OSError('Evidence write made no progress')
                pending = pending[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)

    def _json(self, directory, name, value):
        data = (json.dumps(value, indent=2, allow_nan=False)+'\n').encode()
        if len(data) > 65536 or self._metadata_bytes+len(data) > 2*MIB:
            raise ValueError('Evidence metadata budget exceeded')
        self._metadata_bytes += len(data)
        self._write(directory, name, data)

    def record(self, kind, **fields):
        self.deadline()
        if kind not in {'plan','observed','case','images','container-state','evidence','cleanup'} or self._sequence >= 128:
            raise ValueError('Invalid or excessive evidence event')
        name = f'{self._sequence:03d}-{kind}.json'
        self._sequence += 1
        self._json(self._events_fd, name, {'kind':kind,'elapsed_seconds':time.monotonic()-self.started,**fields})

    def save_log(self, name, data, password):
        self.deadline()
        if type(data) is not bytes or len(data) > MIB or self._log_bytes+len(data) > 16*MIB:
            raise ValueError('Private service log budget exceeded')
        if type(password) is not str or not password or len(password) > 4096:
            raise ValueError('Invalid service log redaction marker')
        marker = password.encode()
        replacement = b'[REDACTED]'
        # Bound the stored representation before allocating the replacement.
        stored_bytes = len(data)+data.count(marker)*(len(replacement)-len(marker))
        charged_bytes = max(len(data), stored_bytes)
        if stored_bytes > MIB or self._log_bytes+charged_bytes > 16*MIB:
            raise ValueError('Private service log budget exceeded')
        self._log_bytes += charged_bytes
        sanitized = data.replace(marker, replacement)
        fd = os.open('logs', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._fd)
        try:
            self._write(fd, name, sanitized)
        finally:
            os.close(fd)
        return {'path':'logs/'+name,'bytes':len(sanitized),'sha256':hashlib.sha256(sanitized).hexdigest()}

    def work_manifest(self):
        """Hash bounded retained regular files via the reviewed I/O worker."""
        self.deadline()
        # Traverse lazily, charging directories as well as files. Never build
        # an unbounded recursive listing before checking the phase deadline.
        pending = [self.work]
        paths = []
        entries = 0
        while pending:
            self.deadline()
            directory = pending.pop()
            if not stat.S_ISDIR(directory.lstat().st_mode):
                raise ValueError('Unexpected retained work directory')
            with os.scandir(directory) as children:
                for child in children:
                    self.deadline()
                    entries += 1
                    if entries > 128:
                        raise ValueError('Retained work entry budget exceeded')
                    path = Path(child.path)
                    info = child.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(path)
                    elif stat.S_ISREG(info.st_mode):
                        paths.append(path)
                    else:
                        raise ValueError('Unexpected retained work entry')
        self.deadline()
        rows = []
        total = 0
        for path in sorted(paths):
            self.deadline()
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or len(rows) >= 64 or info.st_size > 64*MIB:
                raise ValueError('Unexpected or excessive retained work')
            total += info.st_size
            if total > 256*MIB:
                raise ValueError('Retained work budget exceeded')
            with path.open('rb') as stream:
                digest = operate('hash', deadline=self.active_deadline, policy=self.io_policy, stdin=stream).decode('ascii')
            rows.append({'path':str(path.relative_to(self.work)),'bytes':info.st_size,'sha256':digest,'mode':info.st_mode & 0o777})
        return {'files':rows,'bytes':total}

    def finish(self, report):
        """Retain the first outcome; exclusive publication may still fail.

        A retained outcome alone is not a successful final report. Require
        process exit0 and the named final report, with all evidence reviewed.
        """
        report['artifact_directory'] = str(self.path)
        report['elapsed_seconds'] = time.monotonic()-self.started
        self._json(self._fd, 'outcome.json', report)
        os.link('outcome.json', self.report.name, src_dir_fd=self._fd, dst_dir_fd=self._parent_fd, follow_symlinks=False)
        os.fsync(self._parent_fd)

    def close(self):
        for name in ('_events_fd','_fd','_parent_fd'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)
