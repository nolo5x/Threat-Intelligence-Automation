
import json
from datetime import datetime, timezone
from pathlib import Path

from collect_indicators import collect_indicators
from validate_indicators import validate_indicators

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed"
OUTPUT_FILE = OUTPUT_DIR / "misp_event.json"


def prepare_misp_event():
    print("[INFO] Preparing MISP event...")

    indicators = collect_indicators()
    validated = validate_indicators(indicators)

    if not validated:
        raise ValueError("No valid indicators available")

    event = {
        "Event": {
            "info": "Threat Intel Automation - Training Event",
            "distribution": "0",
            "threat_level_id": "4",
            "analysis": "0",
            "published": False,
            "Attribute": []
        }
    }

    for indicator in validated:
        attribute = {
            "type": indicator["type"],
            "category": indicator.get(
                "category", "Network activity"
            ),
            "value": indicator["value"],
            "to_ids": False,
            "comment": indicator.get(
                "comment", "TEST ONLY - Simulated indicator"
            )
        }

        event["Event"]["Attribute"].append(attribute)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(event, file, indent=4)

    print(f"[INFO] Validated indicators: {len(validated)}")
    print(f"[INFO] Event attributes: {len(event['Event']['Attribute'])}")
    print(f"[INFO] Output file: {OUTPUT_FILE}")
    print("[SUCCESS] MISP event JSON prepared!")

    return event


if __name__ == "__main__":
    try:
        prepare_misp_event()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"[ERROR] {error}")
        raise SystemExit(1)
