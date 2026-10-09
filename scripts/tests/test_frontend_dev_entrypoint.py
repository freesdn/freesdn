"""Exercise the development entrypoint with real Node hashing and a fake installer."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class DevelopmentDependenciesTest(unittest.TestCase):
    def setUp(self):
        if not shutil.which("node"):
            self.skipTest("Node is required; CI runs this after setup-node")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.entrypoint = (
            Path(__file__).resolve().parents[2] / "frontend/docker-entrypoint.dev.sh"
        )
        self.bin = self.root / "bin"
        self.bin.mkdir()
        npm = self.bin / "npm"
        npm.write_text(
            "#!/bin/sh\nset -e\n"
            'if [ "$1" = "--version" ]; then echo "${TEST_NPM_VERSION:-12.1.0}"; exit; fi\n'
            'printf "%s\\n" "$*" >> install-calls\n'
            '[ "${TEST_INSTALL_FAIL:-0}" = 0 ] || exit 42\n'
            '[ "$1" = ci ] || exit 43\n'
            "mkdir -p node_modules/.bin\n"
            'printf "{}\\n" > node_modules/.package-lock.json\n'
            'printf "#!/bin/sh\\nexit 0\\n" > node_modules/.bin/vite\n'
            "chmod +x node_modules/.bin/vite\n"
        )
        npm.chmod(0o700)
        (self.root / "package.json").write_text(
            '{"name":"fixture","version":"1.0.0"}\n'
        )
        (self.root / "package-lock.json").write_text(
            '{"name":"fixture","lockfileVersion":3}\n'
        )
        self.env = {
            **os.environ,
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
        }

    def launch(self, **overrides):
        return subprocess.run(
            ["sh", str(self.entrypoint), "sh", "-c", "echo started >> starts"],
            cwd=self.root,
            env={**self.env, **overrides},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def calls(self):
        p = self.root / "install-calls"
        return p.read_text().splitlines() if p.exists() else []

    def test_fresh_install_uses_lock_and_warm_start_reuses_it(self):
        lock = (self.root / "package-lock.json").read_bytes()
        self.assertEqual(self.launch().returncode, 0)
        self.assertEqual(self.launch().returncode, 0)
        self.assertEqual(self.calls(), ["ci --legacy-peer-deps --no-audit --no-fund"])
        self.assertEqual((self.root / "package-lock.json").read_bytes(), lock)
        self.assertEqual(
            (self.root / "starts").read_text().splitlines(), ["started", "started"]
        )

    def test_changed_lock_with_same_timestamp_reinstalls(self):
        self.assertEqual(self.launch().returncode, 0)
        p = self.root / "package-lock.json"
        stamp = p.stat()
        p.write_text(json.dumps({"name": "changed", "lockfileVersion": 3}))
        os.utime(p, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        self.assertEqual(self.launch().returncode, 0)
        self.assertEqual(len(self.calls()), 2)

    def test_changed_package_with_same_timestamp_reinstalls(self):
        self.assertEqual(self.launch().returncode, 0)
        p = self.root / "package.json"
        stamp = p.stat()
        p.write_text('{"name":"fixture","version":"2.0.0"}')
        os.utime(p, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        self.assertEqual(self.launch().returncode, 0)
        self.assertEqual(len(self.calls()), 2)

    def test_npm_configuration_change_reinstalls(self):
        self.assertEqual(self.launch().returncode, 0)
        (self.root / ".npmrc").write_text("legacy-peer-deps=true\n")
        self.assertEqual(self.launch().returncode, 0)
        self.assertEqual(len(self.calls()), 2)

    def test_package_manager_version_change_reinstalls(self):
        self.assertEqual(self.launch().returncode, 0)
        self.assertEqual(self.launch(TEST_NPM_VERSION="12.2.0").returncode, 0)
        self.assertEqual(len(self.calls()), 2)

    def test_native_runtime_fingerprint_change_reinstalls(self):
        self.assertEqual(self.launch().returncode, 0)
        (self.root / "node_modules/.freesdn-dev-dependencies").write_text(
            "old-glibc-runtime\n"
        )
        self.assertEqual(self.launch().returncode, 0)
        self.assertEqual(len(self.calls()), 2)

    def test_missing_vite_reinstalls(self):
        self.assertEqual(self.launch().returncode, 0)
        (self.root / "node_modules/.bin/vite").unlink()
        self.assertEqual(self.launch().returncode, 0)
        self.assertEqual(len(self.calls()), 2)

    def test_missing_installed_lock_reinstalls(self):
        self.assertEqual(self.launch().returncode, 0)
        (self.root / "node_modules/.package-lock.json").unlink()
        self.assertEqual(self.launch().returncode, 0)
        self.assertEqual(len(self.calls()), 2)

    def test_legacy_volume_without_fingerprint_reinstalls(self):
        self.assertEqual(self.launch().returncode, 0)
        (self.root / "node_modules/.freesdn-dev-dependencies").unlink()
        self.assertEqual(self.launch().returncode, 0)
        self.assertEqual(len(self.calls()), 2)

    def test_install_failure_never_starts_or_keeps_success_stamp(self):
        self.assertEqual(self.launch().returncode, 0)
        (self.root / ".npmrc").write_text("legacy-peer-deps=true\n")
        result = self.launch(TEST_INSTALL_FAIL="1")
        self.assertEqual(result.returncode, 42)
        self.assertFalse(
            (self.root / "node_modules/.freesdn-dev-dependencies").exists()
        )
        self.assertEqual((self.root / "starts").read_text().splitlines(), ["started"])

    def test_missing_root_lock_refuses_before_install_and_start(self):
        (self.root / "package-lock.json").unlink()
        self.assertNotEqual(self.launch().returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.root / "starts").exists())


if __name__ == "__main__":
    unittest.main()
