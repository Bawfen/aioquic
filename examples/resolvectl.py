#!/usr/bin/env python3
import subprocess
import re
from collections import defaultdict
from typing import List, Dict


def query_resolvectl(domains: List[str]) -> Dict[str, List[str]]:
    """
    Query resolvectl for a list of domains and return a mapping of IPs to domain names.

    Args:
        domains: List of domain names to query

    Returns:
        Dictionary mapping IP addresses to lists of domain names
    """
    ip_to_domains = defaultdict(list)

    for domain in domains:
        try:
            # Run resolvectl query command
            result = subprocess.run(
                ["resolvectl", "query", domain],
                capture_output=True,
                text=True,
                check=True,
            )

            # Parse the output looking for IPv4 and IPv6 addresses
            # Example output line: "example.com: 93.184.216.34                       -- link: eth0"
            for line in result.stdout.split("\n"):
                # Look for IPv4 addresses
                ipv4_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                if ipv4_match:
                    ip = ipv4_match.group(1)
                    ip_to_domains[ip].append(domain)
                    continue

                # Look for IPv6 addresses
                ipv6_match = re.search(r"([0-9a-fA-F:]+:{1,2}[0-9a-fA-F]+)", line)
                if ipv6_match:
                    ip = ipv6_match.group(1)
                    ip_to_domains[ip].append(domain)

        except subprocess.CalledProcessError as e:
            print(f"Error querying {domain}: {e}")
            continue

    return dict(ip_to_domains)
