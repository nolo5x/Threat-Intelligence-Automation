
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from pymisp import PyMISP, MISPEvent

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

MISP_URL = os.getenv("MISP_URL")
MISP_IMPORT_API_KEY = os.getenv("MISP_IMPORT_API_KEY")

EVENT_FILE = PROJECT_ROOT / "data" / "processed" / "misp_event.json"


def event_already_exists(misp, event_name):
    print("[INFO] Checking for duplicate events...")

    results = misp.search(
        controller="events",
        eventinfo=event_name,
        pythonify=False
    )

    if isinstance(results, dict):
        if results.get("errors"):
            raise RuntimeError(
                f"MISP search failed: {results['errors']}"
            )
        raise RuntimeError(
            "Unexpected MISP search response; import stopped."
        )

    if not isinstance(results, list):
        raise RuntimeError(
            "Unexpected MISP search response; import stopped."
        )

    for item in results:
        if not isinstance(item, dict):
            raise RuntimeError("Invalid event search result")

        existing = item.get("Event", item)

        if existing.get("info") == event_name:
            print("[FOUND] Existing event detected!")
            print("[INFO] Event ID:", existing.get("id"))
            return True

    return False


def main():
    if not MISP_URL or not MISP_IMPORT_API_KEY:
        raise ValueError("Missing MISP import configuration")

    with EVENT_FILE.open("r", encoding="utf-8") as file:
        event_data = json.load(file)

    event = MISPEvent()
    event.from_dict(**event_data["Event"])

    # Keep simulated indicators private and unpublished.
    event.distribution = 0
    event.threat_level_id = 4
    event.published = False

    for attribute in event.attributes:
        attribute.to_ids = False

    print("[INFO] Training event:", event.info)
    print("[INFO] Attributes:", len(event.attributes))

    # Local lab only: self-signed HTTPS certificate.
    misp = PyMISP(
        url=MISP_URL,
        key=MISP_IMPORT_API_KEY,
        ssl=str(PROJECT_ROOT / 'infrastructure' / 'misp-docker' / 'ssl' / 'cert.pem')
    )

    if event_already_exists(misp, event.info):
        print("[SUCCESS] Duplicate prevention working!")
        print("[INFO] Import skipped. No new event created.")
        return

    print("[INFO] No duplicate event found.")
    print("[INFO] Distribution: Organization only")
    print("[INFO] Published: False")
    print("[INFO] IDS flags: Disabled")

    confirmation = input(
        "Type IMPORT to create this training event: "
    )

    if confirmation != "IMPORT":
        print("[INFO] Import cancelled.")
        return

    # Recheck immediately before importing.
    if event_already_exists(misp, event.info):
        print("[INFO] Import cancelled: event already exists.")
        return

    print("[INFO] Importing training event...")

    result = misp.add_event(event, pythonify=False)

    if not isinstance(result, dict) or "Event" not in result:
        raise RuntimeError(
            "MISP did not confirm event creation: "
            + str(result)
        )

    created = result["Event"]

    print("[SUCCESS] Training event imported!")
    print("[INFO] MISP Event ID:", created.get("id"))
    print("[INFO] Published:", created.get("published"))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("[ERROR] Import failed.")
        print(f"[DETAILS] {type(error).__name__}: {error}")
        sys.exit(1)
