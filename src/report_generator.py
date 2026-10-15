
import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = PROJECT_ROOT / "reports"


def generate_report(
    collected,
    validated,
    event_id=None,
    status="completed",
    action="none"
):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)

    report = {
        "project": "Threat Intelligence Automation",
        "timestamp_utc": timestamp.isoformat(),
        "pipeline_status": status,
        "indicators": {
            "collected": collected,
            "validated": validated,
            "filtered": collected - validated
        },
        "misp": {
            "event_id": event_id,
            "action": action
        }
    }

    filename = (
        "report_"
        + timestamp.strftime("%Y%m%d_%H%M%S_%f")
        + ".json"
    )

    report_path = REPORT_DIR / filename

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("[SUCCESS] Execution report generated!")
    print("[INFO] Report saved:", report_path)

    return report_path


if __name__ == "__main__":
    generate_report(
        collected=7,
        validated=3,
        event_id=1,
        status="test",
        action="existing_event_detected"
    )
