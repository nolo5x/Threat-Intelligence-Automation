
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from pymisp import PyMISP, MISPEvent

from collect_indicators import collect_indicators
from validate_indicators import validate_indicators
from logger import setup_logger
from report_generator import generate_report


# ==========================================
# PROJECT CONFIGURATION
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(PROJECT_ROOT / ".env")

MISP_URL = os.getenv("MISP_URL")
MISP_IMPORT_API_KEY = os.getenv("MISP_IMPORT_API_KEY")

CERT_PATH = (
    PROJECT_ROOT
    / "infrastructure"
    / "misp-docker"
    / "ssl"
    / "cert.pem"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "misp_event.json"
)

EVENT_NAME = "Threat Intel Automation - Training Event"

logger = setup_logger()


# ==========================================
# EXECUTION COUNTERS
# ==========================================

execution_stats = {
    "collected": 0,
    "validated": 0,
    "event_id": None
}


# ==========================================
# CHECK FOR EXISTING MISP EVENTS
# ==========================================

def check_existing_event(misp, event_name):

    print("[INFO] Checking for existing MISP events...")
    logger.info("Checking for existing MISP events.")

    results = misp.search(
        controller="events",
        eventinfo=event_name,
        pythonify=False
    )

    if not isinstance(results, list):
        raise RuntimeError(
            "MISP event search returned an unexpected response."
        )

    for item in results:

        if not isinstance(item, dict):
            raise RuntimeError(
                "Invalid MISP event search result."
            )

        existing = item.get("Event", item)

        if not isinstance(existing, dict):
            continue

        if existing.get("info") == event_name:

            event_id = existing.get("id")

            print("[FOUND] Existing event ID:", event_id)

            logger.info(
                "Existing event detected. Event ID: %s",
                event_id
            )

            return event_id

    logger.info("No matching MISP event found.")

    return None


# ==========================================
# GENERATE EXECUTION REPORT
# ==========================================

def save_execution_report(
    collected,
    validated,
    event_id=None,
    status="completed",
    action="none"
):

    report_path = generate_report(
        collected=collected,
        validated=validated,
        event_id=event_id,
        status=status,
        action=action
    )

    logger.info(
        "Execution report saved to %s",
        report_path
    )

    return report_path


# ==========================================
# MAIN AUTOMATION PIPELINE
# ==========================================

def main():

    print("\n=== THREAT INTELLIGENCE AUTOMATION ===\n")

    logger.info("Threat intelligence pipeline started.")

    # --------------------------------------
    # CHECK CONFIGURATION
    # --------------------------------------

    if not MISP_URL or not MISP_IMPORT_API_KEY:

        raise ValueError(
            "Missing MISP_URL or MISP_IMPORT_API_KEY"
        )

    if not CERT_PATH.is_file():

        raise FileNotFoundError(
            "MISP SSL certificate not found."
        )

    # --------------------------------------
    # STEP 1: COLLECT INDICATORS
    # --------------------------------------

    print("[STEP 1] Collecting threat intelligence...")

    logger.info("Starting indicator collection.")

    indicators = collect_indicators()

    collected_count = len(indicators)

    execution_stats["collected"] = collected_count

    logger.info(
        "Collected %d indicators.",
        collected_count
    )

    # --------------------------------------
    # STEP 2: VALIDATE INDICATORS
    # --------------------------------------

    print("\n[STEP 2] Validating indicators...")

    logger.info("Starting indicator validation.")

    validated = validate_indicators(indicators)

    validated_count = len(validated)

    execution_stats["validated"] = validated_count

    if not validated:

        raise ValueError(
            "No valid indicators found."
        )

    print(f"[INFO] Valid indicators: {validated_count}")

    logger.info(
        "Validated %d unique indicators.",
        validated_count
    )

    logger.info(
        "Filtered out %d invalid or duplicate indicators.",
        collected_count - validated_count
    )

    # --------------------------------------
    # STEP 3: PREPARE MISP EVENT
    # --------------------------------------

    print("\n[STEP 3] Preparing MISP event...")

    logger.info("Preparing MISP training event.")

    event = MISPEvent()

    event.info = EVENT_NAME
    event.distribution = 0
    event.threat_level_id = 4
    event.analysis = 0
    event.published = False

    for indicator in validated:

        event.add_attribute(
            type=indicator["type"],
            value=indicator["value"],
            category=indicator.get(
                "category",
                "Network activity"
            ),
            to_ids=False,
            comment=indicator.get(
                "comment",
                "TEST ONLY - Simulated indicator"
            )
        )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            {"Event": event.to_dict()},
            file,
            indent=4,
            default=str
        )

    print("[SUCCESS] Event JSON prepared!")
    print("[INFO] Attributes:", len(event.attributes))

    logger.info(
        "MISP event prepared with %d attributes.",
        len(event.attributes)
    )

    logger.info(
        "Event JSON saved to %s",
        OUTPUT_FILE
    )

    # --------------------------------------
    # STEP 4: CONNECT TO MISP
    # --------------------------------------

    print("\n[STEP 4] Connecting to MISP...")

    logger.info("Establishing secure MISP connection.")

    misp = PyMISP(
        url=MISP_URL,
        key=MISP_IMPORT_API_KEY,
        ssl=str(CERT_PATH)
    )

    print("[SUCCESS] Secure MISP connection established!")

    logger.info("Secure MISP connection established.")

    # --------------------------------------
    # STEP 5: CHECK FOR DUPLICATES
    # --------------------------------------

    print("\n[STEP 5] Checking for duplicates...")

    existing_event_id = check_existing_event(
        misp,
        EVENT_NAME
    )

    if existing_event_id is not None:

        execution_stats["event_id"] = existing_event_id

        print("[SUCCESS] Duplicate prevention working!")
        print("[INFO] Import skipped.")

        logger.info(
            "Duplicate import prevented. Event ID: %s",
            existing_event_id
        )

        save_execution_report(
            collected=collected_count,
            validated=validated_count,
            event_id=existing_event_id,
            status="completed",
            action="duplicate_import_skipped"
        )

        logger.info("Pipeline completed successfully.")

        print("\n=== PIPELINE COMPLETE ===")

        return

    # --------------------------------------
    # STEP 6: PREVENT UNATTENDED IMPORTS
    # --------------------------------------

    print("[INFO] No existing event found.")
    print("[INFO] Private, unpublished training event.")
    print("[INFO] IDS flags: Disabled")

    logger.info(
        "No duplicate found. Checking execution mode."
    )

    # launchd and other scheduled processes have no
    # interactive terminal. Never prompt or import
    # automatically in that situation.

    if not sys.stdin.isatty():

        print("[INFO] Non-interactive execution detected.")
        print("[INFO] New event import skipped for safety.")

        logger.info(
            "Import skipped: no interactive terminal available."
        )

        save_execution_report(
            collected=collected_count,
            validated=validated_count,
            status="completed",
            action="non_interactive_import_skipped"
        )

        logger.info(
            "Pipeline completed without importing."
        )

        print("\n=== PIPELINE COMPLETE ===")

        return

    # --------------------------------------
    # STEP 7: MANUAL IMPORT CONFIRMATION
    # --------------------------------------

    confirmation = input(
        "Type IMPORT to create the event, or press Enter to skip: "
    )

    if confirmation != "IMPORT":

        print("[INFO] Import skipped by user.")

        logger.info("Import cancelled by user.")

        save_execution_report(
            collected=collected_count,
            validated=validated_count,
            status="completed",
            action="import_cancelled"
        )

        logger.info(
            "Pipeline completed without importing."
        )

        print("\n=== PIPELINE COMPLETE ===")

        return

    # --------------------------------------
    # STEP 8: FINAL DUPLICATE CHECK
    # --------------------------------------

    existing_event_id = check_existing_event(
        misp,
        EVENT_NAME
    )

    if existing_event_id is not None:

        execution_stats["event_id"] = existing_event_id

        print(
            "[INFO] Import cancelled: event already exists."
        )

        logger.warning(
            "Duplicate detected during final import check."
        )

        save_execution_report(
            collected=collected_count,
            validated=validated_count,
            event_id=existing_event_id,
            status="completed",
            action="duplicate_import_skipped"
        )

        print("\n=== PIPELINE COMPLETE ===")

        return

    # --------------------------------------
    # STEP 9: IMPORT INTO MISP
    # --------------------------------------

    print("[INFO] Importing training event...")

    logger.info("Starting MISP event import.")

    result = misp.add_event(
        event,
        pythonify=False
    )

    if not isinstance(result, dict) or "Event" not in result:

        raise RuntimeError(
            "MISP did not confirm event creation."
        )

    created = result["Event"]

    if not isinstance(created, dict) or not created.get("id"):

        raise RuntimeError(
            "MISP response did not include a valid event ID."
        )

    event_id = created["id"]
    published = created.get("published")

    execution_stats["event_id"] = event_id

    print("[SUCCESS] Event imported!")
    print("[INFO] Event ID:", event_id)
    print("[INFO] Published:", published)

    logger.info(
        "MISP event imported successfully. Event ID: %s",
        event_id
    )

    logger.info(
        "Event published status: %s",
        published
    )

    # --------------------------------------
    # STEP 10: GENERATE SUCCESS REPORT
    # --------------------------------------

    save_execution_report(
        collected=collected_count,
        validated=validated_count,
        event_id=event_id,
        status="completed",
        action="event_imported"
    )

    logger.info("Pipeline completed successfully.")

    print("\n=== PIPELINE COMPLETE ===")


# ==========================================
# PROGRAM ENTRY POINT
# ==========================================

if __name__ == "__main__":

    try:

        main()

    except Exception as error:

        logger.exception(
            "Threat intelligence pipeline failed."
        )

        print("[ERROR] Pipeline failed.")
        print(
            f"[DETAILS] {type(error).__name__}: {error}"
        )

        # Preserve the collected and validated
        # counts if the pipeline fails.

        try:

            save_execution_report(
                collected=execution_stats["collected"],
                validated=execution_stats["validated"],
                event_id=execution_stats["event_id"],
                status="failed",
                action="pipeline_error"
            )

            logger.info(
                "Failure report generated successfully."
            )

        except Exception:

            logger.exception(
                "Unable to generate failure report."
            )

        sys.exit(1)
