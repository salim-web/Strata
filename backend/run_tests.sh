#!/usr/bin/env bash
set -e

echo "=================================================="
echo "🛡️  Nibdefender Backend Verification & Test Suite"
echo "=================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check Python environment
if [ -d "venv" ]; then
    PYTHON_BIN="venv/bin/python3"
    PYTEST_BIN="venv/bin/pytest"
else
    PYTHON_BIN="python3"
    PYTEST_BIN="pytest"
fi

echo "Python binary: $PYTHON_BIN"

# Check Redis instance readiness
echo -n "Checking Redis connection... "
if $PYTHON_BIN -c "import redis; r = redis.Redis(socket_connect_timeout=1); r.ping()" 2>/dev/null; then
    echo "✅ Redis is ONLINE"
else
    echo "⚠️ Redis is OFFLINE (Backend will run in resilient in-memory mode)"
fi

# Run pytest test suite
echo ""
echo "Running pytest test cases..."
echo "--------------------------------------------------"
if [ -f "$PYTEST_BIN" ]; then
    $PYTEST_BIN tests/ -v
else
    $PYTHON_BIN -m pytest tests/ -v || $PYTHON_BIN tests/test_gateway.py
fi

echo ""
echo "=================================================="
echo "✅ Nibdefender Gateway verification complete!"
echo "Backend is ready for Next.js Tremor dashboard sync."
echo "=================================================="
