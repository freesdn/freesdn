#!/usr/bin/env python3
"""
FreeSDN Security Audit Scanner
================================
Unified security scanning for the FreeSDN Docker stack.

Scans:
  1. Python dependencies  (pip-audit)   — known CVEs in poetry.lock packages
  2. npm dependencies      (npm audit)   — known CVEs in package-lock.json
  3. Docker images         (Trivy + Grype) — OS/app and explicit source-built media coverage
  4. Dockerfiles           (hadolint)    — Dockerfile best-practice violations
  5. Python static analysis (bandit)     — security anti-patterns in source code

Usage:
  python scripts/security-audit.py                # Run all scans
  python scripts/security-audit.py --python       # Python deps only
  python scripts/security-audit.py --npm          # npm deps only
  python scripts/security-audit.py --docker       # Docker image scan only
  python scripts/security-audit.py --lint         # Dockerfile lint only
  python scripts/security-audit.py --sast         # Python static analysis only
  python scripts/security-audit.py --check-tools  # Verify which tools are installed
"""

from __future__ import annotations

import argparse
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import textwrap
import tempfile
import tomllib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Force UTF-8 output on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ─── Paths ───────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
BACKEND_DIR = PROJECT_DIR / "backend"
FRONTEND_DIR = PROJECT_DIR / "frontend"
RESULTS_FILE = SCRIPT_DIR / ".security-audit-results.json"

# Docker images to scan (built by docker compose)
DOCKER_IMAGES = [
    os.environ.get("BACKEND_IMAGE", "freesdn-backend:local"),
    os.environ.get("EDGE_IMAGE", "freesdn-edge:local"),
    os.environ.get("LOGDB_IMAGE", "freesdn-logdb:local"),
]

# Explicit source-built native consumers. Optional go2rtc is included when selected.
NATIVE_MEDIA_IMAGES = {os.environ.get("BACKEND_IMAGE", "freesdn-backend:local")}
if os.environ.get("GO2RTC_IMAGE"):
    DOCKER_IMAGES.append(os.environ["GO2RTC_IMAGE"])
    NATIVE_MEDIA_IMAGES.add(os.environ["GO2RTC_IMAGE"])

# Dockerfiles to lint
DOCKERFILES = [
    BACKEND_DIR / "Dockerfile",
    FRONTEND_DIR / "Dockerfile",
    FRONTEND_DIR / "Dockerfile.dev",
    PROJECT_DIR / "docker" / "Dockerfile.logdb",
]

# ─── ANSI Colors ─────────────────────────────────────────────────────────────

class C:
    if platform.system() == "Windows":
        os.system("")
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def log(icon: str, msg: str, color: str = C.WHITE) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f" {C.DIM}{ts}{C.RESET}  {icon}  {color}{msg}{C.RESET}")


def log_ok(msg: str) -> None:
    log("✅", msg, C.GREEN)

def log_warn(msg: str) -> None:
    log("⚠️ ", msg, C.YELLOW)

def log_err(msg: str) -> None:
    log("❌", msg, C.RED)

def log_info(msg: str) -> None:
    log("ℹ️ ", msg, C.CYAN)

def log_skip(msg: str) -> None:
    log("⏭️ ", msg, C.DIM)

def banner(title: str) -> None:
    width = 60
    print()
    print(f" {C.BOLD}{C.BLUE}{'═' * width}{C.RESET}")
    print(f" {C.BOLD}{C.BLUE}║{C.RESET}  {C.BOLD}{title.center(width - 4)}{C.RESET}  {C.BOLD}{C.BLUE}║{C.RESET}")
    print(f" {C.BOLD}{C.BLUE}{'═' * width}{C.RESET}")
    print()


# ─── Data ────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Result from a single security scanner."""
    scanner: str
    passed: bool
    skipped: bool = False
    findings: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "passed": self.passed,
            "skipped": self.skipped,
            "finding_count": len(self.findings),
            "findings": self.findings,
            "summary": self.summary,
        }


# ─── Tool Detection ─────────────────────────────────────────────────────────

TOOL_INSTALL_HINTS: dict[str, str] = {
    "pip-audit": "pip install pip-audit",
    "bandit": "pip install bandit",
    "trivy": "https://github.com/aquasecurity/trivy/releases (or: brew install trivy)",
    "grype": "https://github.com/anchore/grype/releases (required for source-built FFmpeg)",
    "hadolint": "https://github.com/hadolint/hadolint/releases (or: brew install hadolint)",
    "npm": "Bundled with Node.js — install from https://nodejs.org",
}


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def check_tools() -> dict[str, bool]:
    """Check which security tools are installed."""
    banner("Security Tool Availability")
    status: dict[str, bool] = {}
    for tool, hint in TOOL_INSTALL_HINTS.items():
        available = tool_available(tool)
        status[tool] = available
        if available:
            log_ok(f"{tool:<12} installed")
        else:
            log_warn(f"{tool:<12} NOT FOUND  →  {hint}")
    print()
    installed = sum(1 for v in status.values() if v)
    total = len(status)
    if installed == total:
        log_ok(f"All {total} security tools available")
    else:
        log_warn(f"{installed}/{total} tools available — install missing tools for full coverage")
    return status


# ─── Scanners ────────────────────────────────────────────────────────────────

def run_cmd(
    cmd: list[str],
    cwd: Optional[Path] = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd, cwd=cwd or PROJECT_DIR,
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", "not found")


def incomplete_scan(scanner: str, reason: str) -> ScanResult:
    """Unavailable evidence cannot establish that a dependency is safe."""
    log_err(f"{scanner}: {reason}")
    return ScanResult(scanner, passed=False, findings=[reason], summary=f"incomplete ({reason})")


def scan_python_deps() -> ScanResult:
    """Audit every exact package in the Poetry lock, never the caller's environment."""
    banner("Python Dependency Scan (pip-audit)")
    if not tool_available("pip-audit"):
        return incomplete_scan("pip-audit", "tool not installed")
    try:
        packages = tomllib.loads((BACKEND_DIR / "poetry.lock").read_text())['package']
        if not isinstance(packages, list) or not packages:
            raise ValueError("empty package inventory")
        pins = set()
        for package in packages:
            name, version = package['name'], package['version']
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or not re.fullmatch(r"[A-Za-z0-9.!+_-]+", version):
                raise ValueError("invalid package pin")
            pins.add((name.lower().replace('_', '-'), version))
        # pip-audit's -r input is requirements syntax, not Poetry's TOML.
        # No resolution/install and no omitted platform markers: audit the entire
        # locked graph, including optional/dev and other-platform packages.
        with tempfile.TemporaryDirectory(prefix="freesdn-pip-audit-") as directory:
            requirements = Path(directory) / "locked.txt"
            requirements.write_text(''.join(f"{name}=={version}\n" for name, version in sorted(pins)))
            result = run_cmd(["pip-audit", "--format", "json", "--desc", "--strict",
                              "--no-deps", "--disable-pip", "--requirement", str(requirements)],
                             cwd=BACKEND_DIR, timeout=300)
        data = json.loads(result.stdout)
        dependencies = data['dependencies']
        if not isinstance(dependencies, list) or not dependencies:
            raise ValueError("empty audit inventory")
        covered = set()
        findings = []
        for dependency in dependencies:
            if dependency.get('skip_reason') or not isinstance(dependency['vulns'], list):
                raise ValueError("dependency was not audited")
            covered.add((dependency['name'].lower().replace('_', '-'), dependency['version']))
            for vulnerability in dependency['vulns']:
                findings.append(f"{dependency['name']}=={dependency['version']}: {vulnerability['id']}")
        if covered != pins:
            raise ValueError("audit coverage does not match the Poetry lock")
        if result.returncode not in (0, 1) or (result.returncode and not findings):
            raise ValueError(f"scanner failed (exit {result.returncode})")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        return incomplete_scan("pip-audit", f"lock or scanner output invalid: {error}")
    return ScanResult("pip-audit", passed=not findings, findings=findings,
                      summary=f"{len(pins)} locked packages audited; {len(findings)} vulnerabilities")


def scan_npm_deps() -> ScanResult:
    """Audit the frontend lock, failing on moderate+ or incomplete evidence."""
    banner("npm Dependency Scan (npm audit)")
    if not tool_available("npm"):
        return incomplete_scan("npm-audit", "tool not installed")
    if not (FRONTEND_DIR / "package-lock.json").is_file():
        return incomplete_scan("npm-audit", "lockfile missing")
    result = run_cmd(["npm", "audit", "--json", "--audit-level=moderate"], cwd=FRONTEND_DIR, timeout=120)
    try:
        data = json.loads(result.stdout)
        counts = data['metadata']['vulnerabilities']
        severities = ('info', 'low', 'moderate', 'high', 'critical')
        if data.get('error') or any(type(counts[k]) is not int or counts[k] < 0 for k in (*severities, 'total')):
            raise ValueError("invalid vulnerability counts or registry error")
        if counts['total'] != sum(counts[k] for k in severities):
            raise ValueError("inconsistent vulnerability counts")
        advisories = data['vulnerabilities']
        if not isinstance(advisories, dict) or len(advisories) != counts['total']:
            raise ValueError("incomplete advisory inventory")
        findings = [f"{name} ({value['severity']})" for name, value in advisories.items()]
        blocked = any(counts[k] for k in ('moderate', 'high', 'critical'))
        if result.returncode not in (0, 1) or (result.returncode and not blocked):
            raise ValueError(f"scanner failed (exit {result.returncode})")
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        return incomplete_scan("npm-audit", f"scanner output invalid: {error}")
    return ScanResult("npm-audit", passed=not blocked, findings=findings,
                      summary=f"{counts['total']} total: {counts['critical']} critical, {counts['high']} high, "
                              f"{counts['moderate']} moderate, {counts['low']} low")


def scan_docker_images() -> ScanResult:
    """Scan Docker images for vulnerabilities using Trivy."""
    banner("Docker Image Scan (Trivy)")

    if not tool_available("trivy"):
        log_skip("trivy not installed — skipping")
        log_info(f"Install: {TOOL_INSTALL_HINTS['trivy']}")
        return ScanResult("trivy", passed=False, summary="incomplete (Trivy is not installed)")

    findings: list[str] = []
    total_critical = 0
    total_high = 0
    scan_errors: list[str] = []
    scanned = 0

    for image in DOCKER_IMAGES:
        log_info(f"Scanning image: {image}...")
        result = run_cmd(
            ["trivy", "image", "--format", "json", "--scanners", "vuln",
             "--severity", "HIGH,CRITICAL", "--ignorefile", os.devnull,
             "--ignore-unfixed=false", "--exit-code", "0", "--quiet", image],
            timeout=300,
        )

        if result.returncode != 0:
            error = f"[{image}] scan failed (exit {result.returncode}); image security is unknown"
            scan_errors.append(error)
            log_err(error)
            continue

        try:
            data = json.loads(result.stdout)
            if not isinstance(data, dict) or not isinstance(data.get("Results"), list) or not data["Results"]:
                raise ValueError("Missing scan result inventory")
            results = data["Results"]
            for entry in results:
                if not isinstance(entry, dict) or not isinstance(entry.get("Vulnerabilities", []), list):
                    raise ValueError("Malformed vulnerability inventory")
                if any(not isinstance(v, dict) or not v.get("VulnerabilityID") or not v.get("Severity")
                       for v in entry.get("Vulnerabilities", [])):
                    raise ValueError("Malformed vulnerability record")
            if image in NATIVE_MEDIA_IMAGES:
                image_id = data.get("Metadata", {}).get("ImageID")
                if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
                    raise ValueError("Native scan cannot bind to the Trivy image identity")
                with tempfile.TemporaryDirectory(prefix="freesdn-native-audit-") as directory:
                    native = run_cmd(
                        [sys.executable, str(SCRIPT_DIR / "check_native_media_security.py"),
                         "--image", image_id, "--work-dir", str(Path(directory) / "evidence")],
                        timeout=2700,
                    )
                native_result = json.loads(native.stdout)
                if (native.returncode != 0 or not isinstance(native_result, dict)
                        or native_result.get("passed") is not True
                        or native_result.get("owned_resources_removed") is not True
                        or native_result.get("image_execution") is not False
                        or native_result.get("explicit_native_inventory") is not True
                        or native_result.get("image_id") != image_id):
                    raise ValueError("Native component scan did not complete for this image")
                native_scans = native_result.get("scans", {})
                if (not isinstance(native_scans, dict)
                        or type(native_scans.get("native", {}).get("matches")) is not int
                        or native_scans.get("native", {}).get("matches") != 0
                        or type(native_scans.get("control", {}).get("matches")) is not int
                        or native_scans["control"]["matches"] <= 0):
                    raise ValueError("Native scanner coverage control is missing")
            scanned += 1
            for r in results:
                for vuln in r.get("Vulnerabilities", []):
                    severity = vuln.get("Severity", "UNKNOWN")
                    vuln_id = vuln.get("VulnerabilityID", "unknown")
                    pkg = vuln.get("PkgName", "unknown")
                    installed = vuln.get("InstalledVersion", "?")
                    fixed = vuln.get("FixedVersion", "none")

                    if severity == "CRITICAL":
                        total_critical += 1
                    elif severity == "HIGH":
                        total_high += 1

                    finding = f"[{image}] {vuln_id}: {pkg}=={installed} ({severity}, fix: {fixed})"
                    findings.append(finding)

            img_vulns = sum(len(r.get("Vulnerabilities", [])) for r in results)
            if img_vulns == 0:
                log_ok(f"  {image}: clean")
            else:
                log_warn(f"  {image}: {img_vulns} HIGH/CRITICAL vulnerabilities")

        except (json.JSONDecodeError, KeyError, ValueError, TypeError, AttributeError):
            error = f"[{image}] invalid scanner output; image security is unknown"
            scan_errors.append(error)
            log_err(error)

    # Print top findings
    for f in findings[:10]:
        severity_color = C.RED if "CRITICAL" in f else C.YELLOW
        print(f"          {severity_color}{f}{C.RESET}")
    if len(findings) > 10:
        print(f"          {C.DIM}... and {len(findings) - 10} more{C.RESET}")

    summary = (f"{scanned}/{len(DOCKER_IMAGES)} images scanned; {len(findings)} findings: "
               f"{total_critical} critical, {total_high} high; {len(scan_errors)} scan errors")
    passed = total_critical == 0 and total_high == 0 and not scan_errors and scanned > 0 and scanned == len(DOCKER_IMAGES)
    if not passed:
        log_warn(f"Docker image scan: {summary}")
    else:
        log_ok("No HIGH/CRITICAL vulnerabilities in Docker images")
    return ScanResult("trivy", passed=passed, findings=findings + scan_errors, summary=summary)


def lint_dockerfiles() -> ScanResult:
    """Require a successful, complete Hadolint result for every listed Dockerfile."""
    banner("Dockerfile Lint (Hadolint)")
    if not tool_available("hadolint"):
        return incomplete_scan("hadolint", "tool not installed")
    findings = []
    config = PROJECT_DIR / ".hadolint.yaml"
    config_args = ["--config", str(config)] if config.exists() else []
    if not DOCKERFILES:
        return incomplete_scan("hadolint", "no Dockerfiles selected")
    for dockerfile in DOCKERFILES:
        if not dockerfile.is_file():
            return incomplete_scan("hadolint", f"Dockerfile missing: {dockerfile.name}")
        result = run_cmd(["hadolint", "--format", "json", *config_args, str(dockerfile)], timeout=30)
        try:
            issues = json.loads(result.stdout)
            if not isinstance(issues, list):
                raise ValueError("invalid issue inventory")
            findings.extend(f"{dockerfile.name}:{issue['line']} {issue['code']}: {issue['message']}" for issue in issues)
            if result.returncode not in (0, 1) or (result.returncode and not issues):
                raise ValueError(f"scanner failed (exit {result.returncode})")
        except (ValueError, KeyError, TypeError) as error:
            return incomplete_scan("hadolint", f"scanner output invalid: {error}")
    return ScanResult("hadolint", passed=not findings, findings=findings, summary=f"{len(findings)} issues")


def scan_python_sast() -> ScanResult:
    """Require complete Bandit coverage and no medium/high confidence findings."""
    banner("Python Static Analysis (Bandit)")
    if not tool_available("bandit"):
        return incomplete_scan("bandit", "tool not installed")
    app_dir = BACKEND_DIR / "app"
    if not app_dir.is_dir():
        return incomplete_scan("bandit", "source directory missing")
    # Quiet disables Bandit's progress bar, which otherwise precedes JSON on stdout.
    result = run_cmd(["bandit", "-q", "-r", str(app_dir), "-f", "json", "--severity-level", "medium",
                      "--confidence-level", "medium", "-x", "tests"], cwd=BACKEND_DIR, timeout=120)
    try:
        data = json.loads(result.stdout)
        issues = data['results']
        if not isinstance(issues, list) or data['errors'] or data['metrics']['_totals']['loc'] <= 0:
            raise ValueError("incomplete source coverage")
        findings = [f"{issue['filename']}:{issue['line_number']} [{issue['test_id']}] {issue['issue_text']}"
                    for issue in issues]
        if result.returncode not in (0, 1) or (result.returncode and not findings):
            raise ValueError(f"scanner failed (exit {result.returncode})")
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        return incomplete_scan("bandit", f"scanner output invalid: {error}")
    return ScanResult("bandit", passed=not findings, findings=findings, summary=f"{len(findings)} medium/high issues")


# ─── Orchestration ───────────────────────────────────────────────────────────


def run_all_scans(
    python: bool = True,
    npm: bool = True,
    docker: bool = True,
    lint: bool = True,
    sast: bool = True,
) -> list[ScanResult]:
    """Run selected scanners and return results."""
    results: list[ScanResult] = []

    if python:
        results.append(scan_python_deps())
    if npm:
        results.append(scan_npm_deps())
    if docker:
        results.append(scan_docker_images())
    if lint:
        results.append(lint_dockerfiles())
    if sast:
        results.append(scan_python_sast())

    return results


def print_summary(results: list[ScanResult]) -> None:
    """Print a summary table of all scan results."""
    banner("Security Audit Summary")

    print(f"  {'Scanner':<16} {'Status':<12} {'Findings':<10} {'Summary'}")
    print(f"  {'─' * 16} {'─' * 12} {'─' * 10} {'─' * 30}")

    for r in results:
        if r.skipped:
            status = f"{C.DIM}SKIPPED{C.RESET}"
            icon = "⏭️ "
        elif r.passed:
            status = f"{C.GREEN}PASS{C.RESET}"
            icon = "✅"
        else:
            status = f"{C.RED}FAIL{C.RESET}"
            icon = "❌"

        count = len(r.findings)
        count_color = C.RED if count > 0 and not r.skipped else C.GREEN
        print(
            f"  {r.scanner:<16} {icon} {status:<20} "
            f"{count_color}{count:<10}{C.RESET} {r.summary}"
        )

    print()

    # Overall verdict
    active = [r for r in results if not r.skipped]
    failed = [r for r in active if not r.passed]
    skipped = [r for r in results if r.skipped]

    if not active:
        log_warn("No scans were run — install security tools first")
    elif failed:
        log_err(f"{len(failed)} scanner(s) reported issues: {', '.join(r.scanner for r in failed)}")
    else:
        log_ok(f"All {len(active)} active scanners passed!")

    if skipped:
        log_info(f"{len(skipped)} scanner(s) skipped (tools not installed)")


def save_results(results: list[ScanResult]) -> None:
    """Write scan results to JSON file."""
    data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "platform": f"{platform.system()} {platform.release()}",
        "scanners": [r.to_dict() for r in results],
        "overall_passed": bool(results) and all(r.passed and not r.skipped for r in results),
    }
    RESULTS_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    log_info(f"Results saved to {RESULTS_FILE.relative_to(PROJECT_DIR)}")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="FreeSDN Security Audit Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              python scripts/security-audit.py                # Run all scans
              python scripts/security-audit.py --python       # Python deps only
              python scripts/security-audit.py --npm          # npm deps only
              python scripts/security-audit.py --docker       # Docker image scan
              python scripts/security-audit.py --lint         # Dockerfile lint
              python scripts/security-audit.py --sast         # Bandit analysis
              python scripts/security-audit.py --check-tools  # Check tool availability
        """),
    )
    parser.add_argument("--check-tools", action="store_true", help="Check which security tools are installed")
    parser.add_argument("--python", action="store_true", help="Scan Python dependencies (pip-audit)")
    parser.add_argument("--npm", action="store_true", help="Scan npm dependencies (npm audit)")
    parser.add_argument("--docker", action="store_true", help="Scan Docker images (Trivy)")
    parser.add_argument("--lint", action="store_true", help="Lint Dockerfiles (Hadolint)")
    parser.add_argument("--sast", action="store_true", help="Python static analysis (Bandit)")

    args = parser.parse_args()

    banner("FreeSDN Security Audit Scanner")
    log_info(f"Platform: {platform.system()} {platform.release()}")
    log_info(f"Project:  {PROJECT_DIR}")

    if args.check_tools:
        check_tools()
        return 0

    # If no specific scanner selected, run all
    run_specific = any([args.python, args.npm, args.docker, args.lint, args.sast])

    results = run_all_scans(
        python=args.python or not run_specific,
        npm=args.npm or not run_specific,
        docker=args.docker or not run_specific,
        lint=args.lint or not run_specific,
        sast=args.sast or not run_specific,
    )

    print_summary(results)
    save_results(results)

    # Exit code = number of scanners that failed (0 = all clean)
    failed_count = sum(1 for r in results if not r.passed or r.skipped) if results else 1
    return failed_count


if __name__ == "__main__":
    sys.exit(main())
