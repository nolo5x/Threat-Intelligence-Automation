
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FEED_PATH = PROJECT_ROOT / "data" / "feeds" / "sample_iocs.json"

def collect_indicators():
    if not FEED_PATH.is_file():
        raise FileNotFoundError(f"Feed not found: {FEED_PATH}")

    with FEED_PATH.open("r", encoding="utf-8") as file:
        feed = json.load(file)

    indicators = feed.get("indicators", [])

    if not isinstance(indicators, list):
        raise ValueError("The indicators field must be a list")

    print(f"[INFO] Feed: {feed.get('feed_name', 'Unknown')}")
    print(f"[INFO] Indicators collected: {len(indicators)}")

    for index, indicator in enumerate(indicators, start=1):
        print(
            f"[IOC {index}] "
            f"Type: {indicator.get('type')} | "
            f"Value: {indicator.get('value')}"
        )

    return indicators


if __name__ == "__main__":
    try:
        collect_indicators()
        print("[SUCCESS] Indicator collection completed!")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"[ERROR] {error}")
        raise SystemExit(1)
