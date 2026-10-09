"""Actual checker subprocess/filesystem contracts with a synthetic engine client."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def fixture(tmp_path):
    report = tmp_path / "report.json"
    observed = tmp_path / "engine-observations.jsonl"
    old_work = tmp_path / "old-temporary-path.json"
    wrapper = tmp_path / "checker_wrapper.py"
    wrapper.write_text("""import json,os,runpy,sys,tempfile
from pathlib import Path
original=tempfile.TemporaryDirectory
class ObservedTemporaryDirectory(original):
 def __init__(self,*args,**kwargs):
  super().__init__(*args,**kwargs)
  if str(kwargs.get('prefix','')).startswith('freesdn-db-qualification-'):
   Path(os.environ['OBSERVED_OLD_WORK']).write_text(json.dumps(self.name))
   Path(self.name,'synthetic-work-marker').write_bytes(b'first-attempt-data')
tempfile.TemporaryDirectory=ObservedTemporaryDirectory
source=sys.argv.pop(1)
runpy.run_path(source,run_name='__main__')
""")
    engine = tmp_path / "synthetic-docker"
    engine.write_text(
        "#!"
        + sys.executable
        + """ -B
import hashlib,json,os,sys
from pathlib import Path
args=sys.argv[1:]
report=Path(os.environ['EXPECTED_REPORT'])
artifacts=report.with_name(report.name+'.artifacts')
plans=[]
events=artifacts/'events'
if events.is_dir():
 for p in events.glob('*-plan.json'):
  plans.append(json.loads(p.read_bytes()))
entry={'argv':args,'intent_present':(artifacts/'intent.json').is_file(),'plans':plans}
with Path(os.environ['OBSERVED_ENGINE']).open('a') as f:f.write(json.dumps(entry)+'\\n')
if args[:2]==['image','inspect']:
 image=args[-1]
 print(json.dumps([{'Id':'sha256:'+hashlib.sha256(image.encode()).hexdigest(),'Os':'linux','Architecture':'amd64'}]))
 sys.exit(0)
if args and args[0]=='info':
 print(json.dumps({'OSType':'linux','Architecture':'x86_64','ServerVersion':'synthetic-boundary'}))
 sys.exit(0)
if args[:2]==['volume','create']:
 work=artifacts/'work'
 if work.is_dir():(work/'synthetic-work-marker').write_bytes(b'first-attempt-data')
 print('synthetic acknowledgement lost',file=sys.stderr)
 sys.exit(42)
print('synthetic engine unavailable',file=sys.stderr)
sys.exit(43)
"""
    )
    engine.chmod(0o700)

    def invoke():
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(wrapper),
                os.environ["FREESDN_CHECKER_SOURCE"],
                "--docker",
                str(engine),
                "--source-postgres",
                "synthetic-source-postgres",
                "--source-logdb",
                "synthetic-source-logdb",
                "--target-postgres",
                "synthetic-target-postgres",
                "--target-logdb",
                "synthetic-target-logdb",
                "--report",
                str(report),
            ],
            env={
                **os.environ,
                "EXPECTED_REPORT": str(report),
                "OBSERVED_ENGINE": str(observed),
                "OBSERVED_OLD_WORK": str(old_work),
            },
            capture_output=True,
            timeout=12,
            check=False,
        )
        assert result.returncode != 0
        calls = (
            [json.loads(line) for line in observed.read_text().splitlines()]
            if observed.exists()
            else []
        )
        return result, calls

    return report, old_work, invoke


def test_existing_report_is_not_replaced_and_engine_is_not_contacted(fixture):
    report, _, invoke = fixture
    report.write_bytes(b"previous-reviewed-result\n")
    _, calls = invoke()
    observed = {"report": report.read_bytes(), "engine_calls": len(calls)}
    assert observed == {"report": b"previous-reviewed-result\n", "engine_calls": 0}


def test_report_symlink_is_not_followed_or_used_for_engine_work(fixture):
    report, _, invoke = fixture
    destination = report.parent / "unrelated-report"
    destination.write_bytes(b"keep-unrelated-data\n")
    report.symlink_to(destination)
    _, calls = invoke()
    observed = {
        "destination": destination.read_bytes(),
        "engine_calls": len(calls),
        "is_symlink": report.is_symlink(),
    }
    assert observed == {
        "destination": b"keep-unrelated-data\n",
        "engine_calls": 0,
        "is_symlink": True,
    }


def test_existing_attempt_is_not_reused_or_changed(fixture):
    report, _, invoke = fixture
    artifacts = report.with_name(report.name + ".artifacts")
    artifacts.mkdir(mode=0o700)
    sentinel = artifacts / "previous-pending-data"
    sentinel.write_bytes(b"preserve-uncertain-attempt")
    _, calls = invoke()
    observed = {
        "sentinel": sentinel.read_bytes(),
        "children": sorted(p.name for p in artifacts.iterdir()),
        "engine_calls": len(calls),
    }
    assert observed == {
        "sentinel": b"preserve-uncertain-attempt",
        "children": ["previous-pending-data"],
        "engine_calls": 0,
    }


def test_first_working_bytes_survive_checker_failure(fixture):
    report, old_work, invoke = fixture
    _, calls = invoke()
    assert any(c["argv"][:2] == ["volume", "create"] for c in calls)
    work = (
        Path(json.loads(old_work.read_bytes()))
        if old_work.exists()
        else report.with_name(report.name + ".artifacts") / "work"
    )
    observed = {
        "work_exists": work.is_dir(),
        "marker_exists": (work / "synthetic-work-marker").is_file(),
    }
    assert observed == {"work_exists": True, "marker_exists": True}
    assert (work / "synthetic-work-marker").read_bytes() == b"first-attempt-data"


def test_durable_owned_intent_precedes_a_lost_creation_acknowledgement(fixture):
    _, _, invoke = fixture
    _, calls = invoke()
    creates = [c for c in calls if c["argv"][:2] == ["volume", "create"]]
    assert len(creates) == 1
    observed = creates[0]
    assert observed["intent_present"] and observed["plans"]
    name = observed["argv"][-1]
    assert any(
        p.get("resource", {}).get("planned_name") == name and p["resource"]["kind"] == "volume"
        for p in observed["plans"]
    )


def test_unavailable_engine_never_produces_a_success_report(fixture):
    report, _, invoke = fixture
    _, calls = invoke()
    state = json.loads(report.read_bytes())
    assert calls and state["passed"] is False and state["qualification_complete"] is False
