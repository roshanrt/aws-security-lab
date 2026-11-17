"""Detection and response for the landing zone (runs in security-tooling).

Two ways in:
  * EventBridge delivers one CloudTrail API event (real AWS: forwarded from every
    account to the security bus).
  * A one-minute schedule (or a direct invoke) polls CloudTrail LookupEvents in every
    account through the read-only lz-security-audit role. This is the path used on
    LocalStack, which cannot deliver events across accounts.

Each event is checked against rules mapped to MITRE ATT&CK. New findings go to
DynamoDB (deduplicated by CloudTrail eventID) and SNS. One containment playbook:
a security group opened to the internet is closed again through lz-security-response.

Stand-in for GuardDuty / Security Hub, which LocalStack does not emulate.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone

OPEN_CIDRS = ("0.0.0.0/0", "::/0")
PUBLIC_INGRESS_TAG = "lz:public-ingress"  # value "allowed-443" marks the one intended public group

TRAIL_TAMPER = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "PutInsightSelectors"}
IAM_CHANGE = {
    "CreatePolicyVersion", "SetDefaultPolicyVersion", "PutRolePolicy", "PutUserPolicy", "PutGroupPolicy",
    "AttachRolePolicy", "AttachUserPolicy", "AttachGroupPolicy", "UpdateAssumeRolePolicy",
    "DeleteRolePermissionsBoundary", "PutRolePermissionsBoundary", "CreateUser", "CreateAccessKey",
    "CreateLoginProfile", "CreateRole",
}
ADMIN_ATTACH = {"AttachRolePolicy", "AttachUserPolicy", "AttachGroupPolicy"}
SG_OPEN = {"AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"}
S3_EXPOSURE = {"PutBucketPolicy", "PutBucketAcl", "DeletePublicAccessBlock", "PutPublicAccessBlock", "DeleteBucketPolicy"}
KMS_DESTROY = {"ScheduleKeyDeletion", "DisableKey", "DisableKeyRotation"}

# Roles the pipeline itself uses; their activity is not an attack.
OWN_ROLES = ("lz-detector", "lz-security-audit", "lz-security-response")


# ---------- event helpers (pure) ----------

def params(ev: dict) -> dict:
    return ev.get("requestParameters") or {}


def flat(ev: dict) -> str:
    """requestParameters as one string. CloudTrail and LocalStack shape them differently,
    so the rules look for values rather than for one exact nesting."""
    return json.dumps(params(ev), default=str)


def find_key(obj, *names):
    """First value stored under any of the given key names, case-insensitive, at any depth."""
    wanted = {n.lower() for n in names}
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k.lower() in wanted and v not in (None, ""):
                    return v
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


def principal_arn(ev: dict) -> str:
    ui = ev.get("userIdentity") or {}
    return str(ui.get("arn") or (ui.get("sessionContext") or {}).get("sessionIssuer", {}).get("arn") or ui.get("principalId") or "unknown")


def principal_name(ev: dict) -> str:
    """Role or user name: arn:...:assumed-role/NAME/session -> NAME, arn:...:user/NAME -> NAME."""
    arn = principal_arn(ev)
    if ":assumed-role/" in arn:
        return arn.split(":assumed-role/", 1)[1].split("/")[0]
    if ":user/" in arn or ":role/" in arn:
        return arn.rsplit("/", 1)[-1]
    return arn


def principal_label(ev: dict) -> str:
    """'lz-ci-deployer (arn:...)' or 'root (arn:...)'. The stored value must not start
    with 'arn:': LocalStack's IAM check reads an attribute value that is another
    account's ARN as the resource owner and denies the detector's PutItem."""
    arn, name = principal_arn(ev), principal_name(ev)
    if name == arn:
        name = arn.rsplit(":", 1)[-1]
    return f"{name} ({arn})"


def outcome(ev: dict) -> str:
    # LocalStack records denied calls without an errorCode, so "no error" is not proof of success.
    return f"failed ({ev['errorCode']})" if ev.get("errorCode") else "succeeded or unknown"


def is_trusted(ev: dict, cfg: dict) -> bool:
    arn = principal_arn(ev)
    if arn in cfg.get("trusted_deployers", []):
        return True
    return principal_name(ev) in OWN_ROLES or str((ev.get("userIdentity") or {}).get("type")) == "AWSService"


def public_policy(policy_text) -> bool:
    """True when a bucket policy has an Allow for everyone with no condition."""
    try:
        doc = json.loads(policy_text) if isinstance(policy_text, str) else policy_text
    except (TypeError, ValueError):
        return False
    statements = doc.get("Statement", []) if isinstance(doc, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    for s in statements:
        p = s.get("Principal")
        everyone = p == "*" or (isinstance(p, dict) and (p.get("AWS") == "*" or p.get("AWS") == ["*"]))
        if s.get("Effect") == "Allow" and everyone and not s.get("Condition"):
            return True
    return False


# ---------- rules: each returns a detail string when it fires ----------

def r_trail_tamper(ev, cfg):
    if ev.get("eventName") in TRAIL_TAMPER:
        return f"{ev['eventName']} on {find_key(params(ev), 'name', 'trailName') or 'a trail'}"


def r_iam_change(ev, cfg):
    if ev.get("eventName") in IAM_CHANGE:
        target = find_key(params(ev), "roleName", "userName", "groupName", "policyArn") or "?"
        return f"{ev['eventName']} on {target}"


def r_admin_attach(ev, cfg):
    if ev.get("eventName") in ADMIN_ATTACH and str(find_key(params(ev), "policyArn") or "").endswith("/AdministratorAccess"):
        return f"AdministratorAccess attached to {find_key(params(ev), 'roleName', 'userName', 'groupName')}"


def r_sg_open(ev, cfg):
    if ev.get("eventName") in SG_OPEN and any(c in flat(ev) for c in OPEN_CIDRS):
        m = re.search(r"sg-[0-9a-f]+", flat(ev))
        return f"Ingress from the internet requested on {m.group(0) if m else 'a security group'}"


def r_s3_exposure(ev, cfg):
    name = ev.get("eventName")
    if name not in S3_EXPOSURE:
        return None
    bucket = find_key(params(ev), "bucketName", "Bucket") or "?"
    if name == "PutBucketPolicy":
        policy = find_key(params(ev), "bucketPolicy", "Policy")
        if policy is None:  # LocalStack records "policy": ""; fail closed rather than miss it
            return f"Bucket policy replaced on {bucket} (policy text not in the event)"
        return f"Public bucket policy on {bucket}" if public_policy(policy) else None
    if name == "PutBucketAcl":
        return f"Public ACL on {bucket}" if re.search(r"public-read|AllUsers|AuthenticatedUsers", flat(ev)) else None
    if name == "PutPublicAccessBlock":
        return f"Block Public Access weakened on {bucket}" if re.search(r"false", flat(ev), re.I) else None
    if name == "DeletePublicAccessBlock":
        return f"Block Public Access removed from {bucket}"
    return None  # DeleteBucketPolicy alone exposes nothing


def r_kms_destroy(ev, cfg):
    if ev.get("eventName") in KMS_DESTROY:
        return f"{ev['eventName']} on key {find_key(params(ev), 'keyId') or '?'}"


def r_secret_read(ev, cfg):
    if ev.get("eventName") != "GetSecretValue":
        return None
    secret = str(find_key(params(ev), "secretId") or "")
    who = principal_name(ev)
    for fragment, allowed in cfg.get("secret_allowlist", {}).items():
        if fragment in secret:
            return None if who in allowed else f"{who} read {secret}; allowed: {', '.join(allowed)}"
    return f"{who} read {secret}, which has no allowlist entry"


def r_break_glass(ev, cfg):
    if ev.get("eventName") == "AssumeRole" and str(find_key(params(ev), "roleArn") or "").endswith(":role/lz-break-glass"):
        return f"Break-glass role assumed: {find_key(params(ev), 'roleArn')}"


RULES = [
    ("ENT-001", "CloudTrail tampering", "CRITICAL", "T1562.008 Impair Defenses: Disable or Modify Cloud Logs", r_trail_tamper),
    ("ENT-002", "IAM policy or identity change", "HIGH", "T1098 Account Manipulation", r_iam_change),
    ("ENT-003", "AdministratorAccess attached", "CRITICAL", "T1098.003 Account Manipulation: Additional Cloud Roles", r_admin_attach),
    ("ENT-004", "Security group opened to the internet", "HIGH", "T1562.007 Impair Defenses: Disable or Modify Cloud Firewall", r_sg_open),
    ("ENT-005", "S3 bucket exposed to the public", "CRITICAL", "T1530 Data from Cloud Storage", r_s3_exposure),
    ("ENT-006", "KMS key disabled or scheduled for deletion", "CRITICAL", "T1485 Data Destruction", r_kms_destroy),
    ("ENT-007", "Secret read outside the allowlist", "HIGH", "T1555.006 Credentials from Password Stores: Cloud Secrets Management Stores", r_secret_read),
    ("ENT-008", "Break-glass role used", "HIGH", "T1078.004 Valid Accounts: Cloud Accounts", r_break_glass),
]


def evaluate(events, cfg) -> list[dict]:
    """Pure rule evaluation. Returns one finding per (event, rule) that fires."""
    findings = []
    for ev in events:
        if is_trusted(ev, cfg):
            continue
        for rule_id, title, severity, attack, match in RULES:
            detail = match(ev, cfg)
            if not detail:
                continue
            findings.append({
                "pk": f"{rule_id}#{ev.get('eventID') or ev.get('requestID')}",
                "rule_id": rule_id,
                "title": title,
                "severity": severity,
                "attack": attack,
                "account": str(ev.get("recipientAccountId") or (ev.get("userIdentity") or {}).get("accountId") or "unknown"),
                "principal": principal_label(ev),
                "event_name": ev.get("eventName", ""),
                "event_time": str(ev.get("eventTime", "")),
                "outcome": outcome(ev),
                "detail": detail,
            })
    return findings


# ---------- AWS access (not used by the unit tests) ----------

def _cfg() -> dict:
    return {
        "accounts": json.loads(os.environ["ACCOUNTS"]),
        "workload_accounts": json.loads(os.environ["WORKLOAD_ACCOUNTS"]),
        "trusted_deployers": json.loads(os.environ.get("TRUSTED_DEPLOYER_ARNS", "[]")),
        "secret_allowlist": json.loads(os.environ.get("SECRET_ALLOWLIST", "{}")),
        "table": os.environ["FINDINGS_TABLE"],
        "topic": os.environ["TOPIC_ARN"],
        "lookback": int(os.environ.get("LOOKBACK_MINUTES", "15")),
    }


def _session(account_id: str, role: str):
    import boto3
    creds = boto3.client("sts").assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}", RoleSessionName="lz-detector")["Credentials"]
    return boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                         aws_session_token=creds["SessionToken"])


def _poll(account_id: str, session, table, lookback: int) -> list[dict]:
    """CloudTrail events since the last poll of this account (with a small overlap; eventIDs dedupe)."""
    key = {"pk": f"checkpoint#{account_id}"}
    now = datetime.now(timezone.utc)
    last = table.get_item(Key=key).get("Item", {}).get("polled_at")
    start = datetime.fromisoformat(last) - timedelta(minutes=2) if last else now - timedelta(minutes=lookback)
    events = []
    for page in session.client("cloudtrail").get_paginator("lookup_events").paginate(StartTime=start, EndTime=now):
        for entry in page.get("Events", []):
            ev = json.loads(entry["CloudTrailEvent"]) if "CloudTrailEvent" in entry else entry
            ev.setdefault("recipientAccountId", account_id)
            events.append(ev)
    table.put_item(Item={**key, "polled_at": now.isoformat()})
    return events


def _trail_state_findings(account_id: str, session) -> list[dict]:
    """State check: a trail that is not logging is a finding even when no event says who stopped it."""
    ct = session.client("cloudtrail")
    out = []
    for trail in ct.describe_trails().get("trailList", []):
        if not ct.get_trail_status(Name=trail["TrailARN"]).get("IsLogging"):
            hour = datetime.now(timezone.utc).strftime("%Y%m%dT%H")
            out.append({
                "pk": f"ENT-001#state#{account_id}#{trail['Name']}#{hour}",
                "rule_id": "ENT-001", "title": "CloudTrail tampering", "severity": "CRITICAL",
                "attack": "T1562.008 Impair Defenses: Disable or Modify Cloud Logs",
                "account": account_id, "principal": "unknown (state check)", "event_name": "TrailNotLogging",
                "event_time": datetime.now(timezone.utc).isoformat(), "outcome": "succeeded",
                "detail": f"Trail {trail['Name']} is not logging",
            })
    return out


def _quarantine(finding: dict, cfg: dict) -> str:
    """Containment for ENT-004: confirm the group really is open, then remove exactly those rules."""
    if finding["account"] not in cfg["workload_accounts"]:
        return "no response role in this account"
    m = re.search(r"sg-[0-9a-f]+", finding["detail"])
    if not m:
        return "security group id not found in event"
    ec2 = _session(finding["account"], "lz-security-response").client("ec2")
    group = ec2.describe_security_groups(GroupIds=[m.group(0)])["SecurityGroups"][0]
    tags = {t["Key"]: t["Value"] for t in group.get("Tags", [])}
    revoke, removed = [], []
    for perm in group.get("IpPermissions", []):
        v4 = [r for r in perm.get("IpRanges", []) if r.get("CidrIp") in OPEN_CIDRS]
        v6 = [r for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") in OPEN_CIDRS]
        if not v4 and not v6:
            continue
        if tags.get(PUBLIC_INGRESS_TAG) == "allowed-443" and perm.get("IpProtocol") == "tcp" and perm.get("FromPort") == 443 and perm.get("ToPort") == 443:
            continue  # the one intended public listener
        entry = {k: perm[k] for k in ("IpProtocol", "FromPort", "ToPort") if k in perm}
        if v4:
            entry["IpRanges"] = [{"CidrIp": r["CidrIp"]} for r in v4]
        if v6:
            entry["Ipv6Ranges"] = [{"CidrIpv6": r["CidrIpv6"]} for r in v6]
        revoke.append(entry)
        removed.append(f"{perm.get('IpProtocol')}/{perm.get('FromPort')}-{perm.get('ToPort')}")
    if not revoke:
        return "group is not open to the internet (already closed, or the call was denied)"
    ec2.revoke_security_group_ingress(GroupId=m.group(0), IpPermissions=revoke)
    ec2.create_tags(Resources=[m.group(0)], Tags=[{"Key": "lz:quarantined", "Value": datetime.now(timezone.utc).isoformat()}])
    return f"revoked internet ingress on {m.group(0)}: {', '.join(removed)}"


def handler(event, context):
    import boto3
    from botocore.exceptions import ClientError

    cfg = _cfg()
    table = boto3.resource("dynamodb").Table(cfg["table"])
    sns = boto3.client("sns")
    events, state_findings, errors = [], [], []

    if isinstance(event, dict) and event.get("detail-type") == "AWS API Call via CloudTrail":
        ev = dict(event["detail"])
        ev.setdefault("recipientAccountId", event.get("account"))
        events.append(ev)
    else:
        for account_id in cfg["accounts"]:
            try:
                session = _session(account_id, "lz-security-audit")
                events.extend(_poll(account_id, session, table, cfg["lookback"]))
                state_findings.extend(_trail_state_findings(account_id, session))
            except ClientError as exc:
                errors.append(f"{account_id}: {exc.response['Error']['Code']}")

    new = []
    for finding in evaluate(events, cfg) + state_findings:
        try:
            table.put_item(Item=finding, ConditionExpression="attribute_not_exists(pk)")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                continue  # already reported
            raise
        if finding["rule_id"] == "ENT-004":
            try:
                finding["containment"] = _quarantine(finding, cfg)
            except ClientError as exc:
                finding["containment"] = f"containment failed: {exc.response['Error']['Code']}"
            table.update_item(Key={"pk": finding["pk"]}, UpdateExpression="SET containment = :c",
                              ExpressionAttributeValues={":c": finding["containment"]})
        sns.publish(TopicArn=cfg["topic"], Subject=f"[{finding['severity']}] {finding['rule_id']} {finding['title']}"[:100],
                    Message=json.dumps(finding))
        new.append(finding)

    return {"events": len(events), "new_findings": len(new), "errors": errors,
            "findings": [{k: f.get(k) for k in ("rule_id", "account", "principal", "event_name", "detail", "containment")} for f in new]}
