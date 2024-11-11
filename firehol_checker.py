"""Check if an IP address is listed in a FireHOL blacklist."""
import ipaddress
import os
import sys
import urllib.request
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(levelname)s:%(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


def cache_firehol_blacklists(
    local_file_firehol_level3: str, local_file_firehol_webserver: str
):
    """
    Downloads the FireHOL blacklists from GitHub.

    Parameters
    ----------
    local_file_firehol_level3 : str
        The path to the local file to store the FireHOL Level3 blacklist.
    local_file_firehol_webserver : str
        The path to the local file to store the FireHOL Webserver blacklist.
    """
    # Define the URLs of the Firehol blacklists
    url_firehol_level3 = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset"
    url_firehol_webserver = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webserver.netset"

    # Check if local copies of the blacklists exist
    if not os.path.isfile(local_file_firehol_level3) or (
        datetime.now()
        - datetime.fromtimestamp(os.path.getmtime(local_file_firehol_level3))
    ) > timedelta(hours=12):
        # Download the Firehol Level3 blacklist
        urllib.request.urlretrieve(url_firehol_level3, local_file_firehol_level3)
        logger.info("📥 FireHOL Level3 blacklist downloaded.")

    if not os.path.isfile(local_file_firehol_webserver) or (
        datetime.now()
        - datetime.fromtimestamp(os.path.getmtime(local_file_firehol_webserver))
    ) > timedelta(hours=12):
        # Download the Firehol Webserver blacklist
        urllib.request.urlretrieve(url_firehol_webserver, local_file_firehol_webserver)
        logger.info("📥 FireHOL Webserver blacklist downloaded.")


def read_ip_addresses(input_file: str):
    """
    Reads IP addresses to check against the blacklists from a file.

    Parameters
    ----------
    input_file : str
        The path to the input file. One IP/CIDR per line.
    """
    # Load the IP addresses from the input file
    ips = []
    with open(input_file, "r") as file:
        for line in file.read().splitlines():
            if "/" in line:
                # CIDR notation
                ips.extend([str(ip) for ip in ipaddress.IPv4Network(line)])
            else:
                ips.append(line)
        return ips


def is_ip_in_range(ip: str, range_str: str) -> bool:
    """
    Check if an IP address is in a given range.

    Parameters
    ----------
    ip : str
        The IP address to check.
    range_str : str
        The range to check against.

    Returns
    -------
    bool
        True if the IP address is in the range, False otherwise.
    """
    try:
        ip_range = ipaddress.ip_network(range_str)
        return ipaddress.ip_address(ip) in ip_range
    except ValueError:
        return False


def check_ip_in_blacklist(ip: str, blacklist_file: str) -> bool:
    """
    Check if an IP address is in a blacklist.

    Parameters
    ----------
    ip : str
        The IP address to check.
    blacklist_file : str
        The path to the blacklist file.

    Returns
    -------
    bool
        True if the IP address is in the blacklist, False otherwise.
    """
    with open(blacklist_file, "r") as file:
        for line in file:
            line = line.strip()
            if "/" in line:
                # Handle subnet ranges
                if is_ip_in_range(ip, line):
                    return True
            else:
                # Handle single IP addresses
                if ip == line:
                    return True
        return False


def main():
    """Main function."""
    # Define the local file paths to store the blacklists
    local_file_firehol_level3 = "./firehol_level3.netset"
    local_file_firehol_webserver = "./firehol_webserver.netset"

    cache_firehol_blacklists(local_file_firehol_level3, local_file_firehol_webserver)

    ip_addresses = read_ip_addresses(sys.argv[1])

    # Search for IP addresses in the Firehol blacklists
    suspicious_ips = [
        ip
        for ip in ip_addresses
        if check_ip_in_blacklist(ip, local_file_firehol_level3)
        or check_ip_in_blacklist(ip, local_file_firehol_webserver)
    ]

    # Print the suspicious IP addresses
    if suspicious_ips:
        logger.warning("🚨 Suspicious IP addresses:\n%s", "\n".join(suspicious_ips))
    else:
        logger.info("✅ No suspicious IP addresses found.")


if __name__ == "__main__":
    main()
