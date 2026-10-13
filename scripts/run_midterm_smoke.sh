
#!/usr/bin/env bash
set -euo pipefail

echo "================================="
echo " CPSC 491 Midterm Smoke Tests"
echo "================================="

echo ""
echo "[1/3] Checking Python dependencies..."
python -m pip check

echo ""
echo "[2/3] Running automated acceptance tests..."
python -m pytest tests/test_midterm_smoke.py -v

echo ""
echo "[3/3] Running complete regression suite..."
python -m pytest -q

echo ""
echo "================================="
echo " Midterm smoke checks passed!"
echo "================================="
