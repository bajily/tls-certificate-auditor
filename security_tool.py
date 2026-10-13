"""Shared validation, findings, suppressions and reporting for defensive tools."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO 8601 string with a timezone")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamps require a timezone")
    return result.astimezone(timezone.utc)


def object_value(value, label="input"):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def records(data, key, required=()):
    object_value(data)
    rows = data.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"{key} must be an array")
    for index, row in enumerate(rows):
        object_value(row, f"{key}[{index}]")
        if any(field not in row for field in required):
            raise ValueError(f"{key}[{index}] is missing required fields: {', '.join(required)}")
    return rows


def text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def boolean(value, label):
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def number(value, label, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number")
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{label} is outside the permitted range")
    return value


def string_list(value, label):
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label} must be an array of non-empty strings")
    return value


def setting(policy, key, default, minimum=0, maximum=None):
    return number(policy.get(key, default), f"policy.{key}", minimum, maximum)


def finding(rule, severity, resource, title, evidence, remediation, **extra):
    if severity not in SEVERITIES:
        raise ValueError("unknown finding severity")
    resource = str(resource)
    stable = json.dumps([TOOL, rule, resource, extra.get("subject", "")], ensure_ascii=False)
    result = {"rule": rule, "severity": severity, "resource": resource,
              "title": title, "evidence": evidence, "remediation": remediation,
              "fingerprint": hashlib.sha256(stable.encode()).hexdigest()[:24]}
    result.update(extra)
    return result


def unique_rows(rows, key):
    result = {}
    for row in rows:
        identifier = text(row[key], key)
        if identifier in result:
            raise ValueError(f"duplicate {key} in inventory")
        result[identifier] = row
    return result


def decode_json(content):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("JSON contains a duplicate key")
            result[key] = value
        return result
    return json.loads(content, object_pairs_hook=reject_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON number")))


def load_json(path):
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("JSON input exceeds the 10 MiB limit")
    return decode_json(path.read_text(encoding="utf-8-sig"))


def build_report(findings, suppressions=(), now=None):
    now = now or datetime.now(timezone.utc)
    active, suppressed = [], []
    fingerprints = set()
    for suppression in suppressions:
        object_value(suppression, "suppression")
        text(suppression.get("fingerprint"), "suppression fingerprint")
        text(suppression.get("reason"), "suppression reason")
        timestamp(suppression.get("expires"))
        if suppression["fingerprint"] in fingerprints:
            raise ValueError("duplicate suppression fingerprint")
        fingerprints.add(suppression["fingerprint"])
    known = {item["fingerprint"]: item for item in suppressions
             if timestamp(item["expires"]) > now}
    for item in findings:
        if item["fingerprint"] in known:
            suppressed.append({**item, "suppression_reason": known[item["fingerprint"]]["reason"]})
        else:
            active.append(item)
    active.sort(key=lambda item: (-SEVERITIES[item["severity"]], item["resource"], item["rule"], item["fingerprint"]))
    return {"tool": TOOL, "version": VERSION, "generated_at": now.isoformat(),
            "summary": dict(Counter(item["severity"] for item in active)),
            "findings": active, "suppressed": suppressed}


def sarif(report):
    rules = {item["rule"]: item["title"] for item in report["findings"]}
    results = []
    for item in report["findings"]:
        results.append({"ruleId": item["rule"],
                        "level": "error" if SEVERITIES[item["severity"]] >= 3 else "warning" if SEVERITIES[item["severity"]] >= 1 else "note",
                        "message": {"text": item["title"] + ". " + item["remediation"]},
                        "locations": [{"logicalLocations": [{"name": item["resource"]}]}],
                        "partialFingerprints": {"securityToolFingerprint/v1": item["fingerprint"]},
                        "properties": {"severity": item["severity"], "evidence": item["evidence"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": TOOL, "version": VERSION,
                       "rules": [{"id": key, "shortDescription": {"text": title}} for key, title in sorted(rules.items())]}},
                       "results": results}]}


def markdown(report):
    def escape(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    lines = [f"# {TOOL} report", "", f"Version: {VERSION}. Findings: {len(report['findings'])}.", "",
             "| Severity | Resource | Finding | Recommended action |", "|---|---|---|---|"]
    for item in report["findings"]:
        lines.append("| " + " | ".join(escape(item[key]) for key in ("severity", "resource", "title", "remediation")) + " |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("input", nargs="?", type=Path, help="JSON inventory, event export or tool configuration")
    parser.add_argument("--demo", action="store_true", help="run the embedded synthetic example")
    parser.add_argument("--policy", type=Path, help="JSON object overriding documented defaults")
    parser.add_argument("--suppressions", type=Path, help="JSON array: fingerprint, reason, expires")
    parser.add_argument("--format", choices=["json", "sarif", "markdown"], default="json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=list(SEVERITIES), default="high")
    parser.add_argument("--now", help="timezone-aware ISO timestamp for reproducible reviews")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if args.demo == bool(args.input):
        parser.error("provide exactly one of input or --demo")
    try:
        now = timestamp(args.now) if args.now else datetime.now(timezone.utc)
        data = object_value(json.loads(json.dumps(DEMO)) if args.demo else load_json(args.input))
        policy = object_value(load_json(args.policy), "policy") if args.policy else {}
        suppressions = load_json(args.suppressions) if args.suppressions else []
        if not isinstance(suppressions, list):
            raise ValueError("suppressions must be an array")
        report = build_report(audit(data, policy, now), suppressions, now)
        content = markdown(report) if args.format == "markdown" else json.dumps(sarif(report) if args.format == "sarif" else report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            # Exclusive creation keeps earlier evidence from being overwritten.
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(content)
        else:
            print(content, end="")
        return int(any(SEVERITIES[item["severity"]] >= SEVERITIES[args.fail_on] for item in report["findings"]))
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        parser.exit(2, f"error: {type(exc).__name__}: {exc}\n")
import ipaddress
import socket
import ssl

TOOL = "tls-certificate-auditor"
DESCRIPTION = "Audit TLS certificate lifetimes, host coverage and verified endpoint handshakes."
DEMO = {"certificates": [{"hostname": "portal.example", "not_before": "2026-01-01T00:00:00Z",
                         "not_after": "2026-10-10T00:00:00Z", "dns_sans": ["other.example"], "ip_sans": [],
                         "protocol": "TLSv1.1", "cipher_bits": 128, "verified_chain": False}]}


def host_covered(hostname, dns_sans, ip_sans):
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        host = hostname.rstrip(".").encode("idna").decode().lower()
        for candidate in dns_sans:
            candidate = candidate.rstrip(".").encode("idna").decode().lower()
            if candidate == host or (candidate.startswith("*.") and host.count(".") == candidate.count(".") and host.endswith(candidate[1:])):
                return True
        return False
    return any(address == ipaddress.ip_address(value) for value in ip_sans)


def capture_tls(hostname, port=443, timeout=5):
    hostname = text(hostname, "hostname")
    if any(character.isspace() for character in hostname) or "/" in hostname:
        raise ValueError("hostname must not include a URL path or whitespace")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer in 1..65535")
    number(timeout, "timeout", 0.1, 10)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((hostname, port), timeout=timeout) as transport:
        with context.wrap_socket(transport, server_hostname=hostname) as connection:
            certificate = connection.getpeercert()
            cipher = connection.cipher()
            sans = certificate.get("subjectAltName", [])
            return {"hostname": hostname, "not_before": datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notBefore"]), timezone.utc).isoformat(),
                    "not_after": datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), timezone.utc).isoformat(),
                    "dns_sans": [value for kind, value in sans if kind == "DNS"],
                    "ip_sans": [value for kind, value in sans if kind == "IP Address"],
                    "protocol": connection.version(), "cipher_bits": cipher[2], "verified_chain": True}


def audit(data, policy, now):
    object_value(data)
    result = []
    if "targets" in data:
        targets = records(data, "targets", ("hostname",))
        if len(targets) > 100:
            raise ValueError("at most 100 explicitly listed TLS endpoints are permitted")
        certificates = []
        for target in targets:
            try:
                certificates.append(capture_tls(target["hostname"], target.get("port", 443), target.get("timeout", 5)))
            except (OSError, ssl.SSLError) as exc:
                result.append(finding("TLS-HANDSHAKE-FAILED", "high", target["hostname"], "Verified TLS connection failed",
                                      {"error_type": type(exc).__name__}, "Review certificate trust, host coverage, protocol support and endpoint availability."))
    else:
        certificates = records(data, "certificates", ("hostname", "not_before", "not_after", "dns_sans", "ip_sans", "protocol", "cipher_bits", "verified_chain"))
    warn_days = setting(policy, "warning_days", 30, 1)
    urgent_days = setting(policy, "urgent_days", 14, 0)
    if urgent_days > warn_days:
        raise ValueError("urgent_days must not exceed warning_days")
    minimum_bits = setting(policy, "minimum_cipher_bits", 128, 1)
    for row in certificates:
        hostname = text(row["hostname"], "hostname")
        before, after = timestamp(row["not_before"]), timestamp(row["not_after"])
        if after <= before:
            raise ValueError("certificate validity interval is invalid")
        string_list(row["dns_sans"], "dns_sans")
        string_list(row["ip_sans"], "ip_sans")
        boolean(row["verified_chain"], "verified_chain")
        bits = number(row["cipher_bits"], "cipher_bits", 0)
        days = (after - now).total_seconds() / 86400
        if days <= warn_days:
            result.append(finding("TLS-EXPIRY", "critical" if days <= 0 else "high" if days <= urgent_days else "medium", hostname,
                                  "Certificate expired or approaching expiry", {"days_remaining": round(days, 2), "not_after": after.isoformat()},
                                  "Renew the certificate and verify deployment across all endpoint instances."))
        if before > now:
            result.append(finding("TLS-NOT-YET-VALID", "high", hostname, "Certificate validity has not started",
                                  {"not_before": before.isoformat()}, "Review clock synchronization and certificate issuance dates."))
        if not host_covered(hostname, row["dns_sans"], row["ip_sans"]):
            result.append(finding("TLS-HOST-COVERAGE", "high", hostname, "Certificate SANs do not cover the endpoint",
                                  {"dns_san_count": len(row["dns_sans"]), "ip_san_count": len(row["ip_sans"])},
                                  "Deploy a certificate with a valid SAN for the endpoint name."))
        if row["protocol"] not in {"TLSv1.2", "TLSv1.3"} or bits < minimum_bits:
            result.append(finding("TLS-TRANSPORT-STRENGTH", "high", hostname, "Transport parameters fall below the configured baseline",
                                  {"protocol": row["protocol"], "cipher_bits": bits}, "Enable current TLS protocols and a reviewed cipher policy."))
        if not row["verified_chain"]:
            result.append(finding("TLS-CHAIN-UNVERIFIED", "high", hostname, "Certificate trust chain is unverified",
                                  {"verified_chain": False}, "Verify chain trust using the organization's approved trust store."))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
