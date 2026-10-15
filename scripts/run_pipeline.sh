
#!/bin/bash

set -euo pipefail

PROJECT_DIR="$HOME/Cybersecurity-Projects/Threat-Intel-Automation"
PYTHON="$PROJECT_DIR/.venv/bin/python"
LOG_DIR="$PROJECT_DIR/logs"

mkdir -p "$LOG_DIR"

cd "$PROJECT_DIR"

echo "========================================"
echo "Threat Intelligence Automation"
echo "Started: $(date)"
echo "========================================"

if [ ! -x "$PYTHON" ]; then
    echo "[ERROR] Python virtual environment not found."
    exit 1
fi

# Ensure the local MISP server is reachable.
# -k is used only for this readiness check;
# the Python pipeline verifies the TLS certificate.
if ! /usr/bin/curl -k -sS --connect-timeout 5 \
    --max-time 15 -o /dev/null \
    --fail "$(
        printf '%s' 'https://localhost:8443/users/login'
    )"; then
    echo "[ERROR] Local MISP server is unavailable."
    exit 1
fi

"$PYTHON" "$PROJECT_DIR/src/main.py"

echo "========================================"
echo "Finished: $(date)"
echo "========================================"
