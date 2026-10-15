
import ipaddress
from urllib.parse import urlsplit

from collect_indicators import collect_indicators


SUPPORTED_TYPES = {"ip-dst", "domain", "url"}


def is_valid_indicator(indicator):
    if not isinstance(indicator, dict):
        return False

    indicator_type = indicator.get("type")
    value = indicator.get("value")

    if indicator_type not in SUPPORTED_TYPES:
        return False

    if not isinstance(value, str) or not value.strip():
        return False

    value = value.strip()

    if indicator_type == "ip-dst":
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    if indicator_type == "domain":
        if len(value) > 253:
            return False

        labels = value.rstrip(".").split(".")

        return (
            len(labels) >= 2
            and all(
                1 <= len(label) <= 63
                and not label.startswith("-")
                and not label.endswith("-")
                and all(c.isascii() and (c.isalnum() or c == "-") for c in label)
                for label in labels
            )
        )

    if indicator_type == "url":
        try:
            parsed = urlsplit(value)
            return (
                parsed.scheme in {"http", "https"}
                and bool(parsed.hostname)
                and parsed.port != 0
            )
        except ValueError:
            return False

    return False


def validate_indicators(indicators):
    validated = []
    seen = set()

    for indicator in indicators:
        if not is_valid_indicator(indicator):
            print(f"[WARNING] Skipping invalid indicator: {indicator!r}")
            continue

        indicator_type = indicator["type"]
        value = indicator["value"].strip()

        key = (
            indicator_type,
            value.lower() if indicator_type == "domain" else value,
        )

        if key in seen:
            print(f"[INFO] Duplicate skipped: {value}")
            continue

        seen.add(key)
        validated.append({**indicator, "value": value})

    return validated


if __name__ == "__main__":
    indicators = collect_indicators()
    validated = validate_indicators(indicators)

    print(f"[INFO] Valid indicators: {len(validated)}")

    for indicator in validated:
        print(
            f"[VALID] {indicator['type']}: {indicator['value']}"
        )

    print("[SUCCESS] Validation and deduplication completed!")
