"""Run the actual suite and save explicit per-test outcomes plus OS metadata."""
import argparse
import importlib.metadata
import json
import os
import platform
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes.append(dict(test=test.id(), outcome='passed'))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes.append(dict(test=test.id(), outcome='skipped', reason=reason))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes.append(dict(test=test.id(), outcome='failed'))

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes.append(dict(test=test.id(), outcome='error'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='validation/environment-result.json')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    os.chdir(root)
    tests = unittest.defaultTestLoader.discover(str(root / 'tests'))
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(tests)
    report = dict(timestamp=datetime.now(timezone.utc).isoformat(), system=platform.system(),
                  release=platform.release(), os_version=platform.version(), architecture=platform.machine(),
                  python=platform.python_version(), impacket=importlib.metadata.version('impacket'),
                  tests_run=result.testsRun, failed=len(result.failures), errors=len(result.errors),
                  skipped=len(result.skipped), outcomes=result.outcomes,
                  windows_executed=os.name == 'nt',
                  windows_11_tests_passed=(os.name == 'nt' and sys.getwindowsversion().product_type == 1
                                           and sys.getwindowsversion().build >= 22000
                                           and result.wasSuccessful() and not result.skipped),
                  server2022_interoperability='not_run')
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
