
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from pymisp import PyMISP

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

MISP_URL = os.getenv("MISP_URL")
MISP_API_KEY = os.getenv("MISP_API_KEY")

CERT_PATH = (
    PROJECT_ROOT
    / "infrastructure"
    / "misp-docker"
    / "ssl"
    / "cert.pem"
)

if not MISP_URL or not MISP_API_KEY:
    print("[ERROR] Missing MISP connection settings")
    sys.exit(1)

if not CERT_PATH.is_file():
    print("[ERROR] SSL certificate not found")
    sys.exit(1)

try:
    print("[INFO] Connecting to MISP with HTTPS verification...")

    misp = PyMISP(
        url=MISP_URL,
        key=MISP_API_KEY,
        ssl=str(CERT_PATH)
    )

    version = misp.misp_instance_version

    print("[SUCCESS] Secure HTTPS connection established!")
    print("[INFO] MISP version:", version["version"])
    print("[INFO] Certificate verification: Enabled")

except Exception as error:
    print("[ERROR] Secure HTTPS connection failed.")
    print(f"[DETAILS] {type(error).__name__}: {error}")
    sys.exit(1)
