
import requests
import time
import json
import os
from datetime import datetime, timezone

NETWORKS = [
    "solana",
    "eth",
    "base",
    "bsc",
    "arbitrum",
    "polygon_pos",
    "avax",
    "optimism"
]

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

SEEN_FILE = "state.json"

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
        return

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    try:
        requests.post(
            url,
            data={"chat_id": CHAT_ID, "text": message},
            timeout=20
        )
    except Exception as e:
        print("Telegram error:", e)

def scan_network(network, seen):
    url = f"https://api.geckoterminal.com/api/v2/networks/{network}/new_pools"
    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        pools = response.json().get("data", [])

        for pool in pools:
            pool_id = pool.get("id", "")
            if not pool_id or pool_id in seen:
                continue

            attrs = pool.get("attributes", {})
            name = attrs.get("name", "Unknown pool")
            address = attrs.get("address", "")
            created = attrs.get("pool_created_at", "Unknown")
            liquidity = attrs.get("reserve_in_usd", "0")

            try:
                liquidity_value = float(liquidity or 0)
            except:
                liquidity_value = 0

            if liquidity_value < 5000:
                continue

            message = (
                "🆕 NEW TOKEN POOL DETECTED\n\n"
                f"Network: {network}\n"
                f"Pool: {name}\n"
                f"Pool address: {address}\n"
                f"Liquidity: ${liquidity_value:,.0f}\n"
                f"Created: {created}\n\n"
                "⚠️ Early discovery only. Safety is NOT verified.\n"
                "Research carefully before considering any investment."
            )

            send_alert(message)
            seen.add(pool_id)
            print("Alerted:", name)

    except Exception as e:
        print(f"Error scanning {network}: {e}")

def main():
    seen = load_seen()
    print("Radar started:", datetime.now(timezone.utc).isoformat())

    for network in NETWORKS:
        scan_network(network, seen)
        time.sleep(7)

    save_seen(seen)
    print("Radar finished.")

if __name__ == "__main__":
    main()
