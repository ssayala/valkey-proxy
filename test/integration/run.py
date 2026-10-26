"""Runs the integration tests: python3 test/integration/run.py [-k PATTERN]... [--keep]

Starts its own Valkey clusters and proxies (see harness.py); needs the proxy
and the C test runner built first ("make valkey-proxy run-test", which
"make test-integration" does for you).
"""

import argparse
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import harness  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-k", action="append", default=[], metavar="PATTERN",
                    help="only run tests whose name contains PATTERN (repeatable; globs allowed)")
    ap.add_argument("--keep", action="store_true", help="keep the temp dir with all logs even if everything passes")
    ap.add_argument("-x", "--failfast", action="store_true", help="stop at the first failure")
    args = ap.parse_args()

    for b in (harness.PROXY_BIN, harness.RUN_TEST_BIN):
        if not os.access(b, os.X_OK):
            sys.exit("%s not built: run 'make valkey-proxy run-test' (or 'make test-integration')" % b)

    work = harness.init()
    print("valkey-server: %s" % harness.valkey_server())
    print("work dir:      %s\n" % work)

    loader = unittest.TestLoader()
    if args.k:
        loader.testNamePatterns = [k if any(ch in k for ch in "*?[") else "*%s*" % k for k in args.k]
    suite = loader.discover(HERE, pattern="test_*.py", top_level_dir=HERE)

    t0 = time.time()
    result = unittest.TextTestRunner(verbosity=2, stream=sys.stdout, failfast=args.failfast).run(suite)
    ok = result.wasSuccessful()
    harness.cleanup(keep=args.keep or not ok)
    print("integration tests: %s in %.0fs" % ("PASSED" if ok else "FAILED", time.time() - t0))
    if result.skipped:
        print("skipped: %d (see the reasons above)" % len(result.skipped))
    if not ok or args.keep:
        print("server and proxy logs: %s" % work)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
