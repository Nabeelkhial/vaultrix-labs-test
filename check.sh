#!/bin/sh
# Every runnable check in the repo. No framework — see tests/test_scanner.py.
set -e
cd "$(dirname "$0")"
for m in core.findings scanners.secrets scanners.passive scanners.nuclei scanners._tool \
         scanners.gitleaks scanners.trivy scanners.osv scanners.opengrep \
         ownership.github sandbox.generator sandbox.sandbox prove.idor_prober prove.poc_runner fix.patch fix.reverify report.grade tests.test_scanner; do
  python3 -m "$m"
done
echo "all checks passed"
