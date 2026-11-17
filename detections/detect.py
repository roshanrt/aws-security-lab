#!/usr/bin/env python3
"""
CloudTrail detection engine for the AWS security lab.

Reads CloudTrail event history (LookupEvents) from LocalStack, or from a JSON
export, and evaluates detection rules mapped to MITRE ATT&CK. This is the lab's
stand-in for GuardDuty: the same logic works against real AWS event history.

Examples:
  python3 detections/detect.py                       # last 60 minutes from LocalStack
  python3 detections/detect.py --minutes 15 --json
  python3 detections/detect.py --events-file tests/sample_events.json
  python3 detections/detect.py --fail-on-findings    # exit 1 if anything fires (CI)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable

# Which identity may read which secret. Anything else is a finding.
DEFAULT_SECRET_ALLOWLIST = {
    "lab-app": ["lab/app/api-key"],
}

DENIED_BURST_THRESHOLD = 3

LOG_TAMPER_EVENTS = {
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
    "PutInsightSelectors",
}

ADMIN_ATTACH_EVENTS = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    attack: str
    principal: str
    event_name: str
    event_time: str
    detail: str


@dataclass
class Rule:
    rule_id: str
    title: str
    severity: str
    attack: str
    match: Callable[[dict, dict], str | None]  # returns detail text when it fires


# ---------- event helpers ----------

def principal(ev: dict) -> str:
    ui = ev.get("userIdentity") or {}
    arn = str(ui.get("arn") or "")
    return (
        ui.get("userName")
        # LocalStack omits userName on IAM-user events; take it from the ARN.
        or (arn.rsplit("/", 1)[-1] if ":user/" in arn else None)
        or (ui.get("sessionContext") or {}).get("sessionIssuer", {}).get("userName")
        or ui.get("arn")
        or ui.get("principalId")
        or "unknown"
    )


def is_root(ev: dict) -> bool:
    ui = ev.get("userIdentity") or {}
    # Trust the ARN when there is one: LocalStack stamps type "Root" on IAM-user events.
    arn = str(ui.get("arn") or "")
    return arn.endswith(":root") if arn else ui.get("type") == "Root"


def params(ev: dict) -> dict:
    return ev.get("requestParameters") or {}


def succeeded(ev: dict) -> bool:
    return not ev.get("errorCode")


def is_denied(ev: dict) -> bool:
    code = str(ev.get("errorCode") or "")
    return "AccessDenied" in code or "Unauthorized" in code


# ---------- rules ----------

def r_policy_version_default(ev: dict, cfg: dict) -> str | None:
    name = ev.get("eventName")
    if name == "CreatePolicyVersion" and str(params(ev).get("setAsDefault")).lower() == "true":
        return f"New default version on {params(ev).get('policyArn')}"
    if name == "SetDefaultPolicyVersion":
        return f"Default version changed on {params(ev).get('policyArn')} to {params(ev).get('versionId')}"
    return None


def r_admin_attach(ev: dict, cfg: dict) -> str | None:
    if ev.get("eventName") in ADMIN_ATTACH_EVENTS:
        arn = str(params(ev).get("policyArn", ""))
        if arn.endswith("/AdministratorAccess"):
            target = params(ev).get("userName") or params(ev).get("roleName") or params(ev).get("groupName")
            return f"AdministratorAccess attached to {target}"
    return None


def r_log_tamper(ev: dict, cfg: dict) -> str | None:
    if ev.get("eventName") in LOG_TAMPER_EVENTS:
        trail = params(ev).get("name") or params(ev).get("trailName")
        return f"{ev.get('eventName')} on trail {trail}"
    return None


def r_secret_outside_allowlist(ev: dict, cfg: dict) -> str | None:
    if ev.get("eventName") != "GetSecretValue" or is_root(ev):
        return None
    secret = str(params(ev).get("secretId", ""))
    allowed = cfg["allowlist"].get(principal(ev), [])
    if any(a in secret for a in allowed):
        return None
    return f"{principal(ev)} requested {secret}"


def r_secret_enumeration(ev: dict, cfg: dict) -> str | None:
    if ev.get("eventName") == "ListSecrets" and not is_root(ev):
        return f"{principal(ev)} listed all secrets"
    return None


def r_console_no_mfa(ev: dict, cfg: dict) -> str | None:
    if ev.get("eventName") != "ConsoleLogin":
        return None
    extra = ev.get("additionalEventData") or {}
    login = (ev.get("responseElements") or {}).get("ConsoleLogin")
    if login == "Success" and str(extra.get("MFAUsed")).lower() == "no":
        return f"{principal(ev)} signed in to the console without MFA from {ev.get('sourceIPAddress', 'unknown IP')}"
    return None


def r_bucket_exposure(ev: dict, cfg: dict) -> str | None:
    name = ev.get("eventName")
    p = params(ev)
    bucket = p.get("bucketName")
    if name in ("DeletePublicAccessBlock", "DeleteBucketPolicy"):
        return f"{name} on {bucket}"
    if name == "PutBucketPolicy":
        policy = p.get("policy")
        # LocalStack logs an empty policy, so an unreadable policy fails closed.
        if not policy:
            return f"Bucket policy replaced on {bucket} (policy text not in the event)"
        try:
            doc = policy if isinstance(policy, dict) else json.loads(policy)
        except ValueError:
            return f"Bucket policy replaced on {bucket} (policy text unreadable)"
        stmts = doc.get("Statement", [])
        for st in [stmts] if isinstance(stmts, dict) else stmts:
            who = st.get("Principal")
            if st.get("Effect") == "Allow" and (who == "*" or (isinstance(who, dict) and "*" in str(who.get("AWS")))):
                return f"Public bucket policy set on {bucket}"
    if name == "PutBucketAcl" and any(g in json.dumps(p) for g in ("AllUsers", "AuthenticatedUsers", "public-read")):
        return f"Public ACL set on {bucket}"
    return None


RULES = [
    Rule("LAB-001", "IAM policy version set as default", "HIGH",
         "T1098.003 Account Manipulation: Additional Cloud Roles", r_policy_version_default),
    Rule("LAB-002", "AdministratorAccess attached", "HIGH",
         "T1098.003 Account Manipulation: Additional Cloud Roles", r_admin_attach),
    Rule("LAB-003", "CloudTrail logging tampered", "CRITICAL",
         "T1562.008 Impair Defenses: Disable or Modify Cloud Logs", r_log_tamper),
    Rule("LAB-004", "Secret read outside allowlist", "HIGH",
         "T1555.006 Credentials from Password Stores: Cloud Secrets Management Stores", r_secret_outside_allowlist),
    Rule("LAB-005", "Secrets enumeration", "MEDIUM",
         "T1580 Cloud Infrastructure Discovery", r_secret_enumeration),
    Rule("LAB-007", "Console login without MFA", "HIGH",
         "T1078.004 Valid Accounts: Cloud Accounts", r_console_no_mfa),
    Rule("LAB-008", "S3 bucket exposure changed", "HIGH",
         "T1530 Data from Cloud Storage", r_bucket_exposure),
]


def evaluate(events: Iterable[dict], allowlist: dict, include_failed: bool = True) -> list[Finding]:
    cfg = {"allowlist": allowlist}
    findings: list[Finding] = []
    denied: dict[str, list[dict]] = defaultdict(list)

    for ev in events:
        if is_denied(ev) and not is_root(ev):
            denied[principal(ev)].append(ev)

        for rule in RULES:
            detail = rule.match(ev, cfg)
            if not detail:
                continue
            if not succeeded(ev):
                if not include_failed:
                    continue
                detail += f" [attempt failed: {ev.get('errorCode')}]"
            findings.append(Finding(
                rule.rule_id, rule.title, rule.severity, rule.attack,
                principal(ev), ev.get("eventName", ""), ev.get("eventTime", ""), detail,
            ))

    # Correlation rule: a burst of denials from one identity is a blocked attack.
    for who, evs in denied.items():
        if len(evs) >= DENIED_BURST_THRESHOLD:
            names = sorted({e.get("eventName", "") for e in evs})
            findings.append(Finding(
                "LAB-006", "Repeated access denied (probable blocked attack)", "MEDIUM",
                "TA0004 Privilege Escalation / TA0006 Credential Access (attempted)",
                who, ",".join(names), evs[-1].get("eventTime", ""),
                f"{len(evs)} denied calls: {', '.join(names)}",
            ))

    return findings


# ---------- event sources ----------

def load_events_file(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        raw = data.get("Records") or data.get("Events") or []
    else:
        raw = data
    return [normalize(r) for r in raw]


def normalize(record: dict) -> dict:
    """Accept either a raw CloudTrail record or a LookupEvents entry."""
    if "CloudTrailEvent" in record:
        return json.loads(record["CloudTrailEvent"])
    return record


def fetch_lookup_events(endpoint: str | None, region: str, minutes: int) -> list[dict]:
    try:
        import boto3
    except ImportError:
        sys.exit("boto3 is required: pip install boto3")

    kwargs = {"region_name": region}
    if endpoint:
        kwargs.update(endpoint_url=endpoint, aws_access_key_id="test", aws_secret_access_key="test")
    client = boto3.client("cloudtrail", **kwargs)

    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    events: list[dict] = []
    for page in client.get_paginator("lookup_events").paginate(StartTime=start, EndTime=end):
        for entry in page.get("Events", []):
            events.append(normalize(entry))
    events.sort(key=lambda e: e.get("eventTime", ""))
    return events


# ---------- output ----------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def print_human(findings: list[Finding], event_count: int) -> None:
    print(f"Analyzed {event_count} CloudTrail events. Findings: {len(findings)}\n")
    for f in sorted(findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.event_time)):
        print(f"[{f.severity}] {f.rule_id} {f.title}")
        print(f"    principal : {f.principal}")
        print(f"    event     : {f.event_name} at {f.event_time}")
        print(f"    ATT&CK    : {f.attack}")
        print(f"    detail    : {f.detail}\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--endpoint", default=os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566"),
                    help="LocalStack endpoint. Use 'none' for real AWS with your default credentials.")
    ap.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    ap.add_argument("--minutes", type=int, default=60, help="How far back to look.")
    ap.add_argument("--events-file", help="Analyze a JSON export instead of calling LookupEvents.")
    ap.add_argument("--allowlist", help="JSON file mapping principal -> list of secret names.")
    ap.add_argument("--successful-only", action="store_true", help="Ignore failed attempts.")
    ap.add_argument("--json", action="store_true", help="Print findings as JSON.")
    ap.add_argument("--fail-on-findings", action="store_true", help="Exit 1 if any rule fires.")
    args = ap.parse_args()

    allowlist = DEFAULT_SECRET_ALLOWLIST
    if args.allowlist:
        with open(args.allowlist, encoding="utf-8") as fh:
            allowlist = json.load(fh)

    if args.events_file:
        events = load_events_file(args.events_file)
    else:
        endpoint = None if args.endpoint.lower() == "none" else args.endpoint
        events = fetch_lookup_events(endpoint, args.region, args.minutes)

    findings = evaluate(events, allowlist, include_failed=not args.successful_only)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print_human(findings, len(events))

    return 1 if (args.fail_on_findings and findings) else 0


if __name__ == "__main__":
    sys.exit(main())
