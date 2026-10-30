
#!/usr/bin/env python3

import argparse
import csv
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATABASE_DIR = BASE_DIR / "database"

ROUTER_VENDORS = [
    "mikrotik",
    "cisco",
    "ubiquiti",
    "tp-link",
    "tplink",
    "asus",
    "fortinet",
    "juniper",
    "netgear",
    "aruba",
    "huawei",
    "zyxel",
    "d-link",
    "dlink",
    "hewlett packard",
    "hewlett-packard",
    "hp inc",
    "palo alto",
    "sophos",
    "watchguard",
]


# ============================================================
# HOST DISCOVERY
# ============================================================

def discover_hosts(interface=None, mode="active", timeout=60):
    """
    Execute Netdiscover and parse its output.

    Interface selection is delegated to Netdiscover when
    no interface is specified.
    """

    if not shutil.which("netdiscover"):
        raise RuntimeError(
            "Netdiscover is not installed or not in PATH."
        )

    command = ["netdiscover", "-P"]

    if interface:
        command.extend(["-i", interface])

    if mode == "passive":
        command.append("-p")

    print(f"\n[*] Starting {mode} discovery...")
    print(f"[*] Command: {' '.join(command)}")
    print(f"[*] Timeout: {timeout} seconds")

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace"
    )

    timed_out = False

    try:
        stdout, stderr = process.communicate(timeout=timeout)

    except subprocess.TimeoutExpired:
        timed_out = True
        process.terminate()

        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()

    output = stdout + "\n" + stderr

    # Match IPv4 address followed by MAC address.
    pattern = re.compile(
        r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
        r"\s+"
        r"(?P<mac>(?:[0-9a-fA-F]{2}[:-]){5}"
        r"[0-9a-fA-F]{2})"
    )

    hosts = {}

    for match in pattern.finditer(output):

        try:
            ip = str(ipaddress.IPv4Address(match.group("ip")))
        except ipaddress.AddressValueError:
            continue

        mac = match.group("mac").upper().replace("-", ":")

        hosts[(ip, mac)] = {
            "ip": ip,
            "mac": mac
        }

    if process.returncode not in (0, None, -15) and not hosts:
        raise RuntimeError(
            f"Netdiscover failed:\n{stderr.strip()}"
        )

    if timed_out:
        print("[!] Scan stopped after reaching the timeout.")

    return sorted(
        hosts.values(),
        key=lambda host: int(ipaddress.IPv4Address(host["ip"]))
    )


# ============================================================
# DATABASE LOADING
# ============================================================

def normalize_prefix(value):
    """Convert a MAC prefix into uppercase hexadecimal."""

    return re.sub(r"[^0-9A-Fa-f]", "", str(value)).upper()


def load_databases(database_dir):
    """
    Load offline IEEE MAC vendor records and virtualization
    MAC prefix records.

    Supports IEEE CSV files:
        oui.csv
        mam.csv
        oui36.csv

    Also supports custom CSV columns:
        prefix,vendor
    """

    database_dir = Path(database_dir)

    oui_database = {}

    database_files = [
        "oui.csv",
        "mam.csv",
        "oui36.csv"
    ]

    for filename in database_files:

        filepath = database_dir / filename

        if not filepath.exists():
            continue

        with filepath.open(
            "r",
            encoding="utf-8-sig",
            newline=""
        ) as file:

            reader = csv.DictReader(file)

            if not reader.fieldnames:
                continue

            columns = {
                column.strip().lower(): column
                for column in reader.fieldnames
            }

            prefix_column = (
                columns.get("assignment")
                or columns.get("prefix")
            )

            vendor_column = (
                columns.get("organization name")
                or columns.get("vendor")
            )

            if not prefix_column or not vendor_column:
                print(f"[!] Unsupported CSV format: {filename}")
                continue

            for row in reader:

                prefix = normalize_prefix(
                    row.get(prefix_column, "")
                )

                vendor = row.get(vendor_column, "").strip()

                if prefix and vendor:
                    oui_database[prefix] = vendor

    if not oui_database:
        raise FileNotFoundError(
            "No valid OUI records found in database directory."
        )

    virtualization_file = (
        database_dir / "virtualization_vendors.json"
    )

    if not virtualization_file.exists():
        raise FileNotFoundError(
            f"Missing database: {virtualization_file}"
        )

    with virtualization_file.open(
        "r",
        encoding="utf-8"
    ) as file:

        virtualization_database = json.load(file)

    virtualization_database = {
        normalize_prefix(prefix): vendor
        for prefix, vendor in virtualization_database.items()
    }

    print(f"\n[*] Loaded {len(oui_database)} OUI records.")
    print(
        f"[*] Loaded {len(virtualization_database)} "
        "virtualization prefixes."
    )

    return oui_database, virtualization_database


# ============================================================
# HOST ANALYSIS
# ============================================================

def analyze_hosts(hosts, oui_database, virtualization_database):
    """
    Identify MAC vendors and classify hosts.

    Virtualization prefixes take precedence over ordinary
    vendor classification.
    """

    # Longest prefixes are checked first.
    oui_prefixes = sorted(
        oui_database.keys(),
        key=len,
        reverse=True
    )

    virtualization_prefixes = sorted(
        virtualization_database.keys(),
        key=len,
        reverse=True
    )

    for host in hosts:

        mac = normalize_prefix(host["mac"])

        vendor = "Unknown"
        virtualization = None

        # Identify MAC vendor.
        for prefix in oui_prefixes:

            if mac.startswith(prefix):
                vendor = oui_database[prefix]
                break

        # Identify virtualization platform.
        for prefix in virtualization_prefixes:

            if mac.startswith(prefix):
                virtualization = virtualization_database[prefix]
                break

        host["vendor"] = vendor
        host["virtualization"] = virtualization

        if virtualization:
            host["classification"] = "Significant"
        else:
            host["classification"] = "Not significant"

    return hosts


# ============================================================
# SUBNET ESTIMATION
# ============================================================

def suggest_subnet(hosts):
    """
    Calculate the smallest single CIDR network containing
    the lowest and highest discovered IPv4 addresses.
    """

    if not hosts:
        return None

    addresses = [
        ipaddress.IPv4Address(host["ip"])
        for host in hosts
    ]

    lowest = min(addresses)
    highest = max(addresses)

    difference = int(lowest) ^ int(highest)

    prefix = 32 - difference.bit_length()

    network = ipaddress.IPv4Network(
        (lowest, prefix),
        strict=False
    )

    return {
        "network": str(network),
        "prefix": prefix,
        "netmask": str(network.netmask),
        "lowest": str(lowest),
        "highest": str(highest)
    }


# ============================================================
# GATEWAY ESTIMATION
# ============================================================

def suggest_gateways(hosts, subnet):
    """
    Rank discovered hosts as potential default gateways.

    Only discovered hosts are considered.
    """

    if not hosts:
        return []

    network = (
        ipaddress.IPv4Network(subnet["network"])
        if subnet else None
    )

    candidates = []

    for host in hosts:

        ip = ipaddress.IPv4Address(host["ip"])

        vendor = host.get("vendor", "").lower()
        virtualization = host.get("virtualization")

        score = 0
        reasons = []

        # Actual network equipment vendors.
        if any(name in vendor for name in ROUTER_VENDORS):
            score += 4
            reasons.append("Network equipment vendor")

        # Virtualization-related MAC addresses.
        if virtualization:
            score += 2
            reasons.append(
                f"Virtualization: {virtualization}"
            )

        # Common gateway IP assignments.
        if ip.packed[-1] in (1, 254):
            score += 2
            reasons.append("Common gateway IP")

        # First usable address in suggested subnet.
        if network and network.num_addresses > 2:

            first_usable = (
                int(network.network_address) + 1
            )

            if int(ip) == first_usable:
                score += 2
                reasons.append("First usable subnet address")

        if score < 2:
            continue

        if score >= 6:
            confidence = "High"
        elif score >= 4:
            confidence = "Medium"
        else:
            confidence = "Low"

        candidates.append({
            "ip": host["ip"],
            "mac": host["mac"],
            "vendor": host.get("vendor", "Unknown"),
            "virtualization": virtualization,
            "score": score,
            "confidence": confidence,
            "reasons": reasons
        })

    return sorted(
        candidates,
        key=lambda candidate: candidate["score"],
        reverse=True
    )


# ============================================================
# RESULTS DISPLAY
# ============================================================

def display_results(hosts, subnet, gateways):

    print("\n" + "=" * 85)
    print("NETWORK DISCOVERY AND ANALYSIS")
    print("=" * 85)

    if not hosts:
        print("\nNo hosts discovered.")
        return

    print("\nDISCOVERED HOSTS")
    print("-" * 85)

    print(
        f"{'IP ADDRESS':<17}"
        f"{'MAC ADDRESS':<20}"
        f"{'VENDOR':<24}"
        f"{'CLASSIFICATION':<20}"
    )

    print("-" * 85)

    significant = 0
    ordinary = 0

    for host in hosts:

        print(
            f"{host['ip']:<17}"
            f"{host['mac']:<20}"
            f"{host['vendor'][:23]:<24}"
            f"{host['classification']:<20}"
        )

        if host["virtualization"]:
            print(
                f"  └─ Virtualization: "
                f"{host['virtualization']}"
            )

        if host["classification"] == "Significant":
            significant += 1
        else:
            ordinary += 1

    print("-" * 85)

    print(f"Total discovered: {len(hosts)}")
    print(f"Significant:      {significant}")
    print(f"Not significant:  {ordinary}")

    # Suggested subnet.
    print("\nSUGGESTED SUBNET")
    print("-" * 85)

    if subnet:

        print(f"Network:          {subnet['network']}")
        print(f"CIDR:             /{subnet['prefix']}")
        print(f"Subnet mask:      {subnet['netmask']}")
        print(f"Lowest IP:        {subnet['lowest']}")
        print(f"Highest IP:       {subnet['highest']}")

    # Suggested gateways.
    print("\nSUGGESTED DEFAULT GATEWAYS")
    print("-" * 85)

    if not gateways:
        print("No gateway candidates identified.")

    else:

        for candidate in gateways:

            print(
                f"\nIP:          {candidate['ip']}"
            )
            print(
                f"MAC:         {candidate['mac']}"
            )
            print(
                f"Vendor:      {candidate['vendor']}"
            )
            print(
                f"Confidence:  {candidate['confidence']}"
            )
            print(
                f"Score:       {candidate['score']}"
            )
            print(
                f"Basis:       {', '.join(candidate['reasons'])}"
            )

    print("\n" + "=" * 85)


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description="Network discovery and host analysis tool."
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Optional network interface for Netdiscover."
    )

    parser.add_argument(
        "--mode",
        choices=["active", "passive"],
        default="active",
        help="Discovery mode (default: active)."
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Discovery timeout in seconds (default: 60)."
    )

    parser.add_argument(
        "--database-dir",
        default=str(DEFAULT_DATABASE_DIR),
        help="Path to offline database directory."
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero.")

    try:

        # 1. Discover hosts.
        hosts = discover_hosts(
            interface=args.interface,
            mode=args.mode,
            timeout=args.timeout
        )

        print(f"\n[*] Discovered {len(hosts)} hosts.")

        # 2. Load offline databases.
        oui_database, virtualization_database = (
            load_databases(args.database_dir)
        )

        # 3. Analyze hosts.
        hosts = analyze_hosts(
            hosts,
            oui_database,
            virtualization_database
        )

        # 4. Suggest subnet.
        subnet = suggest_subnet(hosts)

        # 5. Suggest potential gateways.
        gateways = suggest_gateways(hosts, subnet)

        # 6. Display results.
        display_results(hosts, subnet, gateways)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)

    except (RuntimeError, FileNotFoundError, OSError, ValueError) as error:
        print(f"\n[ERROR] {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
