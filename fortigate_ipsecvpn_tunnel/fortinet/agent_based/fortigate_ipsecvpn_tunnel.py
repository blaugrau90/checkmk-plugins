#!/usr/bin/env python3
##########################################################
#                        _   _                           #
#              ___ _ __ | |_| |__  _   _ ___             #
#             / _ \ '_ \| __| '_ \| | | / __|            #
#            |  __/ | | | |_| | | | |_| \__ \            #
#             \___|_| |_|\__|_| |_|\__,_|___/            #
#                                                        #
##########################################################

# Fortigate IPSEC VPN PH2 Tunnel Check Plugin for Checkmk
# © 2025 enthus GmbH
# Luca-Leon Hausdörfer <luca-leon.hausdoerfer@enthus.de>

from cmk.agent_based.v2 import (
    CheckPlugin,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    SimpleSNMPSection,
    SNMPTree,
    State,
    startswith,
)
from cmk.plugins.lib.fortinet import DETECT_FORTIGATE

fortigate_ipsecvpn_tunnel_ent_status_map = {"1": "down", "2": "up"}

def human_readable_bytes(num_bytes):
    """
    Converts bytes to a human-readable format (KB, MB, GB, etc.).
    """
    for unit in ["bytes", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0

def parse_fortigate_vpn_tunnel(string_table):
    """
    Parse the SNMP table into a structured dictionary.
    """
    parsed = {}
    for ph2_name, ph2_in, ph2_out, ph2_state in string_table:
        parsed[ph2_name] = {
            "in": int(ph2_in),
            "out": int(ph2_out),
            "state": ph2_state,
        }
    return parsed

def discover_fortigate_vpn_tunnel(section):
    """
    Discovery function to find all VPN tunnels.
    """
    for tunnel_name in section.keys():
        yield Service(item=tunnel_name)

def check_fortigate_vpn_tunnel(item, section):
    """
    Check function to evaluate the state of the VPN tunnel.
    """
    data = section.get(item)
    if not data:
        yield Result(state=State.CRIT, summary=f"Tunnel '{item}' is missing")
        return

    state_map = {"up": State.OK, "down": State.CRIT}
    state = state_map.get(fortigate_ipsecvpn_tunnel_ent_status_map[data["state"]], State.UNKNOWN)
    ph2_in = data["in"]
    ph2_out = data["out"]

    yield Result(
        state=state,
        summary=(
            f"Status: {fortigate_ipsecvpn_tunnel_ent_status_map[data['state']]}, "
            f"In: {human_readable_bytes(ph2_in)}, Out: {human_readable_bytes(ph2_out)}"
        ),
    )
    yield Metric("in_octets", ph2_in)
    yield Metric("out_octets", ph2_out)

snmp_section_fortigate_vpn = SimpleSNMPSection(
    name="fortigate_vpn",
    parse_function=parse_fortigate_vpn_tunnel,
    detect=DETECT_FORTIGATE,
    fetch=SNMPTree(
        base=".1.3.6.1.4.1.12356.101.12.2.2.1",
        oids=["3", "18", "19", "20"],  # Name, In, Out, Status
    ),
)

check_plugin_fortigate_vpn = CheckPlugin(
    name="fortigate_ipsecvpn_tunnel",
    sections=["fortigate_vpn"],
    service_name="Fortigate VPN Tunnel %s",
    discovery_function=discover_fortigate_vpn_tunnel,
    check_function=check_fortigate_vpn_tunnel,
)
