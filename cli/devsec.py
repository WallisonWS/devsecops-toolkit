#!/usr/bin/env python3
"""
DevSecOps Toolkit CLI (devsec.py)
Zero-dependency CLI for Developers, Network/Security Engineers, and Data/SOC Analysts.
Author: Wallison Araujo (@WallisonWS)
License: MIT
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import ipaddress
import json
import re
import secrets
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


# ============================================================================
# 1. CIDR & VLSM Calculator
# ============================================================================
def analyze_cidr(cidr_str: str, split: int = 1) -> Dict[str, Any]:
    net = ipaddress.ip_network(cidr_str, strict=False)
    wildcard = ipaddress.IPv4Address(int(net.hostmask))
    usable = max(0, net.num_addresses - 2) if net.prefixlen <= 30 else net.num_addresses
    first_host = str(net.network_address + 1) if net.prefixlen <= 30 else str(net.network_address)
    last_host = str(net.broadcast_address - 1) if net.prefixlen <= 30 else str(net.broadcast_address)

    subnets_info: List[Dict[str, Any]] = []
    if split > 1:
        extra_bits = (split - 1).bit_length()
        new_prefix = min(30, net.prefixlen + extra_bits)
        for idx, sub in enumerate(net.subnets(new_prefix=new_prefix)):
            sub_usable = max(0, sub.num_addresses - 2)
            subnets_info.append(
                {
                    "index": idx + 1,
                    "cidr": str(sub),
                    "gateway": str(sub.network_address + 1),
                    "usable_range": f"{sub.network_address + 1} - {sub.broadcast_address - 1}",
                    "broadcast": str(sub.broadcast_address),
                    "usable_hosts": sub_usable,
                }
            )

    return {
        "network": str(net.network_address),
        "cidr": str(net),
        "netmask": str(net.netmask),
        "wildcard": str(wildcard),
        "broadcast": str(net.broadcast_address),
        "first_host": first_host,
        "last_host": last_host,
        "usable_hosts": usable,
        "is_private": net.is_private,
        "subnets": subnets_info,
    }


# ============================================================================
# 2. Multi-Vendor Firewall Rule Transpiler
# ============================================================================
def transpile_firewall_rule(
    vendor: str,
    name: str,
    action: str,
    src_cidr: str,
    dst_cidr: str,
    proto: str = "ALL",
    port: str = "ALL",
    vlan: int = 99,
    src_intf: str = "vlan99",
    dst_intf: str = "wan1",
) -> str:
    src_net = ipaddress.ip_network(src_cidr, strict=False)
    dst_net = ipaddress.ip_network(dst_cidr, strict=False)
    is_allow = action.lower() in ("accept", "allow", "pass", "permit")
    vendor_key = vendor.lower()

    if vendor_key == "fortigate":
        fg_act = "accept" if is_allow else "deny"
        return (
            f"config firewall address\n"
            f'    edit "ADDR_SRC_{name}"\n'
            f"        set subnet {src_net.network_address} {src_net.netmask}\n"
            f"    next\n"
            f'    edit "ADDR_DST_{name}"\n'
            f"        set subnet {dst_net.network_address} {dst_net.netmask}\n"
            f"    next\n"
            f"end\n"
            f"config firewall policy\n"
            f"    edit 0\n"
            f'        set name "{name}"\n'
            f'        set srcintf "{src_intf}"\n'
            f'        set dstintf "{dst_intf}"\n'
            f"        set action {fg_act}\n"
            f'        set srcaddr "ADDR_SRC_{name}"\n'
            f'        set dstaddr "ADDR_DST_{name}"\n'
            f'        set schedule "always"\n'
            f'        set service "ALL"\n'
            f"        set logtraffic all\n"
            f"    next\n"
            f"end"
        )

    if vendor_key == "pfsense":
        pf_act = "pass" if is_allow else "block drop"
        pf_proto = "any" if proto.upper() == "ALL" else proto.lower()
        port_clause = "" if port.upper() == "ALL" else f" port {{ {port} }}"
        return (
            f'{pf_act} in log quick on ${src_intf} inet proto {pf_proto} '
            f'from {src_net} to {dst_net}{port_clause} label "{name}"'
        )

    if vendor_key in ("aruba", "cisco"):
        acl_act = "permit" if is_allow else "deny"
        acl_proto = "ip" if proto.upper() == "ALL" else proto.lower()
        return (
            f"vlan {vlan}\n"
            f'   name "{name}"\n'
            f"   exit\n"
            f'ip access-list extended "ACL_{name}"\n'
            f"   10 {acl_act} {acl_proto} {src_net.network_address} {src_net.hostmask} "
            f"{dst_net.network_address} {dst_net.hostmask} log\n"
            f"   20 deny ip any any log\n"
            f"   exit"
        )

    if vendor_key == "mikrotik":
        mk_act = "accept" if is_allow else "drop"
        mk_proto = "" if proto.upper() == "ALL" else f" protocol={proto.lower()}"
        mk_port = "" if port.upper() == "ALL" else f" dst-port={port}"
        return (
            f"/interface vlan add interface=bridge name={src_intf} vlan-id={vlan}\n"
            f"/ip firewall filter add chain=forward action={mk_act} "
            f"in-interface={src_intf} out-interface={dst_intf} "
            f"src-address={src_net} dst-address={dst_net}{mk_proto}{mk_port} "
            f'log=yes log-prefix="[{name}] " comment="{name}"'
        )

    if vendor_key == "linux":
        ipt_act = "ACCEPT" if is_allow else "DROP"
        proto_flag = "" if proto.upper() == "ALL" else f"-p {proto.lower()} "
        port_flag = "" if port.upper() == "ALL" else f"--dport {port} "
        return (
            f"iptables -A FORWARD -i {src_intf} -o {dst_intf} "
            f"-s {src_net} -d {dst_net} {proto_flag}{port_flag}-j {ipt_act}"
        )

    raise ValueError(f"Unsupported vendor: {vendor}")


# ============================================================================
# 3. SOC Log, IOC & Secret Scanner
# ============================================================================
def scan_log_text(text: str, defang: bool = False) -> Dict[str, Any]:
    raw_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    public_counts: Counter[str] = Counter()
    private_ips = set()

    for ip_str in raw_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback:
                private_ips.add(ip_str)
            else:
                public_counts[ip_str] += 1
        except ValueError:
            continue

    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)))
    hashes = sorted(set(re.findall(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{32}\b", text)))

    detections: List[str] = []
    patterns = [
        ("SQL Injection (SQLi)", r"(\bUNION\s+SELECT\b|\bOR\s+['\"]?1['\"]?=['\"]?1|sqlmap)"),
        ("Path Traversal (LFI)", r"(\.\./|\.\.\\|/etc/passwd)"),
        ("Cross-Site Scripting (XSS)", r"(<script\b|javascript:|onerror\s*=)"),
        ("AWS Access Key Leak", r"\bAKIA[0-9A-Z]{16}\b"),
        ("Private Key Leak", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ]
    for label, rx in patterns:
        if re.search(rx, text, flags=re.IGNORECASE):
            detections.append(label)

    top_public = [
        {
            "ip": ip.replace(".", "[.]") if defang else ip,
            "events": count,
        }
        for ip, count in public_counts.most_common()
    ]

    return {
        "public_ips_count": len(public_counts),
        "private_ips_count": len(private_ips),
        "top_public_ips": top_public,
        "cves": [c.upper() for c in cves],
        "hashes": hashes,
        "detections": detections,
    }


# ============================================================================
# 4. JWT Security Auditor
# ============================================================================
def _b64url_decode(segment: str) -> bytes:
    padding = "=" * ((4 - (len(segment) % 4)) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def audit_jwt(token: str) -> Dict[str, Any]:
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format: expected at least header.payload")

    header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))

    warnings: List[str] = []
    alg = str(header.get("alg", "")).lower()
    if not alg or alg == "none":
        warnings.append("CRITICAL: JWT uses 'alg: none' (unsigned token)")

    if "exp" not in payload:
        warnings.append("WARNING: Missing 'exp' expiration claim")
    else:
        exp_dt = datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc)
        if exp_dt < datetime.now(tz=timezone.utc):
            warnings.append(f"EXPIRED: Token expired at {exp_dt.isoformat()}")

    sensitive = [k for k in payload.keys() if re.search(r"pass|secret|key|cpf", k, re.I)]
    if sensitive:
        warnings.append(f"CRITICAL: Sensitive keys in JWT payload: {', '.join(sensitive)}")

    return {
        "header": header,
        "payload": payload,
        "signature_present": len(parts) >= 3 and bool(parts[2]),
        "warnings": warnings,
    }


# ============================================================================
# 5. Data Profiler & CSV/JSON -> SQL Generator
# ============================================================================
def profile_and_convert_csv(csv_content: str, table_name: str = "dataset") -> Dict[str, Any]:
    reader = csv.DictReader(io.StringIO(csv_content.strip()))
    rows = list(reader)
    if not rows:
        return {"rows": 0, "columns": {}, "sql": ""}

    columns = list(rows[0].keys())
    col_summary: Dict[str, Any] = {}
    for col in columns:
        vals = [r.get(col, "") for r in rows]
        non_empty = [v for v in vals if v not in (None, "")]
        col_summary[col] = {
            "filled": len(non_empty),
            "nulls": len(rows) - len(non_empty),
            "unique": len(set(non_empty)),
        }

    cols_ddl = ",\n".join(f"  {c} VARCHAR(255)" for c in columns)
    inserts = []
    for r in rows:
        escaped_vals = []
        for c in columns:
            v = r.get(c, "")
            if v in (None, ""):
                escaped_vals.append("NULL")
            else:
                safe_v = str(v).replace("'", "''")
                escaped_vals.append(f"'{safe_v}'")
        inserts.append(
            f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({', '.join(escaped_vals)});"
        )

    sql_script = f"CREATE TABLE {table_name} (\n{cols_ddl}\n);\n\n" + "\n".join(inserts)
    return {"rows": len(rows), "columns": col_summary, "sql": sql_script}


# ============================================================================
# CLI Entrypoint
# ============================================================================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devsec",
        description="DevSecOps Toolkit CLI — Swiss-Army Knife for Devs, SOC & Data Analysts",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # cidr
    p_cidr = sub.add_parser("cidr", help="Analyze IPv4 CIDR block and split into VLAN subnets")
    p_cidr.add_argument("cidr", help="IPv4 CIDR block (e.g. 192.168.10.0/24)")
    p_cidr.add_argument("--split", type=int, default=1, help="Split into N subnets (2, 4, 8)")

    # firewall
    p_fw = sub.add_parser("firewall", help="Transpile Zero-Trust firewall rule across vendors")
    p_fw.add_argument("--vendor", choices=["fortigate", "pfsense", "mikrotik", "aruba", "cisco", "linux"], default="fortigate")
    p_fw.add_argument("--name", default="ZT-ISOLATE-IOT")
    p_fw.add_argument("--action", choices=["accept", "deny"], default="deny")
    p_fw.add_argument("--src", default="10.99.0.0/24")
    p_fw.add_argument("--dst", default="0.0.0.0/0")
    p_fw.add_argument("--proto", default="ALL")
    p_fw.add_argument("--port", default="ALL")
    p_fw.add_argument("--vlan", type=int, default=99)

    # scan-log
    p_log = sub.add_parser("scan-log", help="Scan log file or text for IOCs, attacks and leaked secrets")
    p_log.add_argument("source", help="Path to log file or inline log string")
    p_log.add_argument("--defang", action="store_true", help="Defang extracted IPs (1[.]2[.]3[.]4)")

    # jwt
    p_jwt = sub.add_parser("jwt", help="Decode and audit a JWT token for security issues")
    p_jwt.add_argument("token", help="JWT string (header.payload.signature)")

    # secret
    p_sec = sub.add_parser("secret", help="Generate cryptographic secrets, UUIDs and SHA-256 hashes")
    p_sec.add_argument("--text", default="", help="Optional text to hash with SHA-256")

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "cidr":
        res = analyze_cidr(args.cidr, split=args.split)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0

    if args.command == "firewall":
        script = transpile_firewall_rule(
            vendor=args.vendor,
            name=args.name,
            action=args.action,
            src_cidr=args.src,
            dst_cidr=args.dst,
            proto=args.proto,
            port=args.port,
            vlan=args.vlan,
        )
        print(script)
        return 0

    if args.command == "scan-log":
        path = Path(args.source)
        content = path.read_text(encoding="utf-8", errors="ignore") if path.is_file() else args.source
        res = scan_log_text(content, defang=args.defang)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0

    if args.command == "jwt":
        res = audit_jwt(args.token)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0

    if args.command == "secret":
        payload: Dict[str, Any] = {
            "uuid_v4": str(uuid.uuid4()),
            "api_key": f"dsk_live_{secrets.token_hex(18)}",
            "jwt_secret_256bit": secrets.token_urlsafe(32),
        }
        if args.text:
            payload["sha256"] = hashlib.sha256(args.text.encode("utf-8")).hexdigest()
        print(json.dumps(payload, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
