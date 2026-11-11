
import requests
import time
import json
import os
from datetime import datetime, timezone, timedelta

NETWORKS = [
    "solana", "eth", "base", "bsc",
    "arbitrum", "polygon_pos", "avax", "optimism"
]

# GoPlus EVM chain IDs
CHAIN_IDS = {
    "eth": "1",
    "bsc": "56",
    "arbitrum": "42161",
    "polygon_pos": "137",
    "avax": "43114",
    "base": "8453",
    "optimism": "10"
}

# Common quote-token contracts, used to identify the project token.
QUOTE_TOKENS = {
    "bsc": {
        "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
        "0x55d398326f99059ff775485246999027b3197955",
        "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"
    },
    "eth": {
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "0xdac17f958d2ee523a2206206994597c13d831ec7"
    },
    "base": {
        "0x4200000000000000000000000000000000000006",
        "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    },
    "arbitrum": {
        "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
        "0xaf88d065e77c8cc2239327c5edb3a432268e5831"
    },
    "polygon_pos": {
        "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"
    },
    "avax": {
        "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7"
    },
    "optimism": {
        "0x4200000000000000000000000000000000000006"
    }
}

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

SEEN_FILE = "state.json"

MIN_LIQUIDITY = 50000
MIN_VOLUME_24H = 25000
MAX_POOL_AGE_HOURS = 48
MAX_ALERTS_PER_SCAN = 3

# Maximum permitted buy/sell tax: 10%
MAX_TAX = 0.10

session = requests.Session()


def load_seen():
    try:
        with open(SEEN_FILE, "r") as f:
            return set(json.load(f))
    except Exception:
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
        response = session.post(
            url,
            data={"chat_id": CHAT_ID, "text": message},
            timeout=20
        )
        response.raise_for_status()
        return True
    except Exception as e:
        print("Telegram error:", e)
        return False


def get_token_address(network, pool):
    """Extract the project token address from GeckoTerminal relationships."""

    relationships = pool.get("relationships", {})

    base = relationships.get("base_token", {}).get("data", {})
    quote = relationships.get("quote_token", {}).get("data", {})

    def extract(data):
        token_id = data.get("id", "")
        if "_" in token_id:
            return token_id.split("_", 1)[1].lower()
        return ""

    base_address = extract(base)
    quote_address = extract(quote)

    known_quotes = QUOTE_TOKENS.get(network, set())

    if base_address in known_quotes and quote_address:
        return quote_address

    if base_address:
        return base_address

    if quote_address:
        return quote_address

    return None


def check_goplus(network, token_address):
    """Return security results, or None if verification is unavailable."""

    chain_id = CHAIN_IDS.get(network)

    if not chain_id or not token_address:
        return None

    url = (
        f"https://api.gopluslabs.io/api/v1/token_security/"
        f"{chain_id}"
    )

    try:
        response = session.get(
            url,
            params={"contract_addresses": token_address},
            timeout=20
        )
        response.raise_for_status()

        data = response.json()

        if str(data.get("code")) != "1":
            print("GoPlus API did not return success:", data.get("message"))
            return None

        result = data.get("result", {})
        return result.get(token_address.lower())

    except Exception as e:
        print("GoPlus security check error:", e)
        return None


def analyse_security(info):
    """
    Fail closed when important security information is missing.
    Return status, warnings and whether a normal alert is allowed.
    """

    if not info:
        return False, ["Security information unavailable"], "UNVERIFIED"

    required_fields = [
        "is_honeypot",
        "is_open_source",
        "is_mintable",
        "hidden_owner",
        "buy_tax",
        "sell_tax"
    ]

    missing = [
        field for field in required_fields
        if field not in info or info[field] in (None, "")
    ]

    if missing:
        return False, [
            "Missing security data: " + ", ".join(missing)
        ], "UNVERIFIED"

    risks = []

    # Critical trading risks
    if info["is_honeypot"] == "1":
        risks.append("HONEYPOT DETECTED")

    if info.get("cannot_buy") == "1":
        risks.append("Buying may be blocked")

    if info.get("cannot_sell_all") == "1":
        risks.append("Selling may be restricted")

    # Contract and ownership risks
    if info["is_open_source"] == "0":
        risks.append("Contract source code is not verified")

    if info["is_mintable"] == "1":
        risks.append("Owner may be able to mint tokens")

    if info["hidden_owner"] == "1":
        risks.append("Hidden owner detected")

    if info.get("can_take_back_ownership") == "1":
        risks.append("Ownership may be reclaimable")

    if info.get("owner_change_balance") == "1":
        risks.append("Owner may be able to change balances")

    if info.get("is_blacklisted") == "1":
        risks.append("Blacklist function detected")

    if info.get("transfer_pausable") == "1":
        risks.append("Transfers may be paused")

    # Tax checks
    try:
        buy_tax = float(info["buy_tax"])
        sell_tax = float(info["sell_tax"])

        if buy_tax > MAX_TAX:
            risks.append(f"High buy tax: {buy_tax * 100:.1f}%")

        if sell_tax > MAX_TAX:
            risks.append(f"High sell tax: {sell_tax * 100:.1f}%")

    except (ValueError, TypeError):
        return False, ["Tax data could not be interpreted"], "UNVERIFIED"

    # Top-holder concentration (when provided)
    holders = info.get("holders", [])

    if isinstance(holders, list) and holders:
        try:
            largest_holder = max(
                float(holder.get("percent", 0))
                for holder in holders
            )

            if largest_holder > 0.20:
                risks.append(
                    f"Top holder owns {largest_holder * 100:.1f}%"
                )
        except (ValueError, TypeError):
            risks.append("Holder concentration could not be checked")
    else:
        risks.append("Holder concentration data unavailable")

    if risks:
        return False, risks, "HIGH RISK / REVIEW"

    return True, [], "CHECKS PASSED"


def scan_network(network, seen, alerts):
    if alerts >= MAX_ALERTS_PER_SCAN:
        return alerts

    # This first version only performs GoPlus checks on EVM networks.
    if network not in CHAIN_IDS:
        print(f"Security integration not yet available for {network}")
        return alerts

    url = (
        f"https://api.geckoterminal.com/api/v2/"
        f"networks/{network}/new_pools"
    )

    try:
        response = session.get(
            url,
            params={"include": "base_token,quote_token"},
            timeout=20
        )
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
            volume = (
                volume_data.get("h24")
                if isinstance(volume_data, dict)
                else None
            )

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

            # Market filters passed. Now check the actual token.
            token_address = get_token_address(network, pool)

            if not token_address:
                print("Cannot identify token contract:", name)
                continue

            security_info = check_goplus(network, token_address)

            passed, risks, security_status = analyse_security(
                security_info
            )

            print(
                f"Security result for {name}: "
                f"{security_status}"
            )

            # Do not send normal alerts for risky or unverified tokens.
            if not passed:
                print("Normal alert withheld:", name, risks)
                continue

            message = (
                "🛡️ RADAR ALERT - SECURITY CHECKS PASSED\n\n"
                f"Network: {network}\n"
                f"Pool: {name}\n"
                f"Token: {token_address}\n"
                f"Pool address: {address}\n"
                f"Liquidity: ${liquidity:,.0f}\n"
                f"24h volume: ${volume:,.0f}\n"
                f"Pool age: {age.total_seconds() / 3600:.1f} hours\n\n"
                "GoPlus checks passed for the required fields.\n"
                "This is NOT a guarantee of safety.\n"
                "Review the contract and liquidity before investing."
            )

            if send_alert(message):
                seen.add(pool_id)
                alerts += 1
                print("Security-checked alert sent:", name)

            time.sleep(2)

    except Exception as e:
        print(f"Error scanning {network}: {e}")

    return alerts


def main():
    seen = load_seen()
    alerts = 0

    print(
        "Security Radar started:",
        datetime.now(timezone.utc).isoformat()
    )

    for network in NETWORKS:
        if alerts >= MAX_ALERTS_PER_SCAN:
            break

        alerts = scan_network(network, seen, alerts)

        time.sleep(7)

    save_seen(seen)

    print("Radar finished. Alerts sent:", alerts)


if __name__ == "__main__":
    main()
