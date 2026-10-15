
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from pymisp import PyMISP

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

MISP_URL = os.getenv("MISP_URL")
MISP_API_KEY = os.getenv("MISP_API_KEY")

EVENT_NAME = "Threat Intel Automation - Training Event"


def main():
    if not MISP_URL or not MISP_API_KEY:
        raise ValueError("Missing MISP connection settings")

    print("[INFO] Checking MISP for existing training events...")

    # Temporary local-lab configuration.
    misp = PyMISP(
        url=MISP_URL,
        key=MISP_API_KEY,
        ssl=str(PROJECT_ROOT / 'infrastructure' / 'misp-docker' / 'ssl' / 'cert.pem')
    )

    events = misp.search(
        controller="events",
        eventinfo=EVENT_NAME,
        pythonify=False
    )

    if isinstance(events, dict):
        if events.get("errors"):
            raise RuntimeError(str(events["errors"]))
        raise RuntimeError(f"Unexpected MISP response: {events}")

    if not isinstance(events, list):
        raise RuntimeError("Unexpected event search response")

    matches = []

    for item in events:
        event = item.get("Event", item)
        if event.get("info") == EVENT_NAME:
            matches.append(event)

    if matches:
        print("[FOUND] Training event already exists!")
        for event in matches:
            print("[INFO] Event ID:", event.get("id"))
        print("[INFO] Skip importing another event.")
    else:
        print("[INFO] No matching training event found.")
        print("[INFO] Event could be imported.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("[ERROR] Duplicate check failed.")
        print(f"[DETAILS] {type(error).__name__}: {error}")
        sys.exit(1)
