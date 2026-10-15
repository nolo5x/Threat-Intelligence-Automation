
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from pymisp import PyMISP

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

MISP_URL = os.getenv("MISP_URL")
MISP_IMPORT_API_KEY = os.getenv("MISP_IMPORT_API_KEY")

if not MISP_URL or not MISP_IMPORT_API_KEY:
    print("[ERROR] Missing MISP URL or import API key")
    sys.exit(1)

try:
    print("[INFO] Connecting to MISP using import API key...")

    # Local lab only: certificate verification is disabled
    # temporarily for the self-signed certificate.
    misp = PyMISP(
        url=MISP_URL,
        key=MISP_IMPORT_API_KEY,
        ssl=str(PROJECT_ROOT / 'infrastructure' / 'misp-docker' / 'ssl' / 'cert.pem')
    )

    version = misp.misp_instance_version

    print("[SUCCESS] MISP API connection established!")
    print("[INFO] MISP version:", version["version"])

    # Authenticated read-only request.
    events = misp.search(
        controller="events",
        limit=1
    )

    if isinstance(events, dict) and events.get("errors"):
        raise RuntimeError(str(events["errors"]))

    print("[SUCCESS] Authenticated API read completed!")
    print("[INFO] Import key is usable for API requests.")
    print("[INFO] No events were created or modified.")

except Exception as error:
    print("[ERROR] MISP API test failed.")
    print(f"[DETAILS] {type(error).__name__}: {error}")
    sys.exit(1)
