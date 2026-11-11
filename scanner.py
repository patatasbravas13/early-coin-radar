
import requests
import time
import json
import os
from datetime import datetime, timezone, timedelta

NETWORKS = [
    "solana", "eth", "base", "bsc",
    "arbitrum", "polygon_pos", "avax", "optimism"
]

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

SEEN_FILE = "state.json"

MIN_LIQUIDITY = 50000
MIN_VOLUME_24H = 25000
MAX_POOL_AGE_HOURS = 48
MAX_ALERTS_PER_SCAN = 3

def load_seen():
    try:
        with open(SEEN_FILE, "r") as f:
            return set(json.load(f))
    except:
        return set()

def save_seen(seen):
    with open(SEEN_FILE, "w") as f:
        json.dump(list(seen), f)

def send_alert(message):
    if not BOT_TOKEN or not CHAT_ID:
        print("Telegram secrets missing.")
        return False

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    try:
        response = requests.post(
            url,
            data={"chat_id": CHAT_ID, "text": message},
            timeout=20
        )
        response.raise_for_status()
        return True
    except Exception as e:
        print("Telegram error:", e)
        return False

def scan_network(network, seen, alerts):
    if alerts >= MAX_ALERTS_PER_SCAN:
        return alerts

    url = (
        f"https://api.geckoterminal.com/api/v2/"
        f"networks/{network}/new_pools"
    )

    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        pools = response.json().get("data", [])

        for pool in pools:
            if alerts >= MAX_ALERTS_PER_SCAN:
                break

            pool_id = pool.get("id", "")
            if not pool_id or pool_id in seen:
                continue

            attrs = pool.get("attributes", {})

            name = attrs.get("name", "Unknown pool")
            address = attrs.get("address", "")
            created = attrs.get("pool_created_at")
            liquidity = attrs.get("reserve_in_usd")
            volume_data = attrs.get("volume_usd", {})
            volume = volume_data.get("h24") if isinstance(volume_data, dict) else None

            # Reject missing or invalid market data
            if not created or liquidity is None or volume is None:
                continue

            try:
                liquidity = float(liquidity)
                volume = float(volume)
                created_at = datetime.fromisoformat(
                    created.replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                continue

            age = datetime.now(timezone.utc) - created_at

            if age < timedelta(0):
                continue

            if age > timedelta(hours=MAX_POOL_AGE_HOURS):
                continue

            if liquidity < MIN_LIQUIDITY:
                continue

            if volume < MIN_VOLUME_24H:
                continue

            message = (
                "🔎 STRICT RADAR ALERT\n\n"
                f"Network: {network}\n"
                f"Pool: {name}\n"
                f"Address: {address}\n"
                f"Liquidity: ${liquidity:,.0f}\n"
                f"24h volume: ${volume:,.0f}\n"
                f"Pool age: {age.total_seconds() / 3600:.1f} hours\n\n"
                "⚠️ Market filters passed only. "
                "Token safety is NOT verified.\n"
                "Research before considering any investment."
            )

            if send_alert(message):
                seen.add(pool_id)
                alerts += 1
                print("Strict alert sent:", name)

    except Exception as e:
        print(f"Error scanning {network}: {e}")

    return alerts

def main():
    seen = load_seen()
    alerts = 0

    print("Strict Radar started:", datetime.now(timezone.utc).isoformat())

    for network in NETWORKS:
        if alerts >= MAX_ALERTS_PER_SCAN:
            break

        alerts = scan_network(network, seen, alerts)

        # Conservative pacing for the public API
        time.sleep(7)

    save_seen(seen)

    print("Strict Radar finished. Alerts sent:", alerts)

if __name__ == "__main__":
    main()
