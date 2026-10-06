#!/usr/bin/env python3
"""
CloudGuard - DevSecOps shield for hardcoded secrets and IAM misconfigurations.

Usage:
    python cloudguard.py scan <path>            # scan files/folders for secrets and risky IAM policies
    python cloudguard.py fix <policy.json>      # print a least-privilege suggestion for an IAM policy
    python cloudguard.py precommit              # scan staged git files (used by the git hook)
"""
import json
import math
import os
import re
import subprocess
import sys

# ---------- colours ----------
R, Y, G, B, X = "\033[91m", "\033[93m", "\033[92m", "\033[1m", "\033[0m"


# ---------- secret patterns ----------
SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "AWS Secret Access Key": re.compile(
        r"(?i)aws.{0,20}(secret|private).{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"
    ),
    "GitHub Token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Slack Token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "Private Key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Generic API Key": re.compile(
        r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"]([A-Za-z0-9_\-/+]{16,})['\"]"
    ),
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".pyc", ".pptx"}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def mask(value: str) -> str:
    return value[:4] + "*" * max(len(value) - 8, 4) + value[-4:] if len(value) > 8 else "****"


def scan_text_for_secrets(path, text):
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for name, pat in SECRET_PATTERNS.items():
            m = pat.search(line)
            if not m:
                continue
            if name == "Generic API Key":
                value = m.group(2)
                # skip obvious placeholders / low-entropy values to reduce false positives
                if shannon_entropy(value) < 3.0 or value.lower().startswith(("your", "example", "changeme")):
                    continue
            elif name == "AWS Secret Access Key":
                value = re.search(r"[0-9a-zA-Z/+]{40}", m.group(0)).group(0)
            else:
                value = m.group(0)
            findings.append(
                {
                    "type": "SECRET",
                    "severity": "CRITICAL",
                    "file": path,
                    "line": lineno,
                    "title": f"Hardcoded {name}",
                    "evidence": mask(value),
                    "fix": "Remove it from code, rotate the key, and load it from an environment "
                    "variable or a secrets manager (AWS Secrets Manager / Vault).",
                }
            )
    return findings


# ---------- IAM analysis ----------
def as_list(x):
    return x if isinstance(x, list) else [x]


def analyze_policy(path, policy):
    findings = []
    statements = as_list(policy.get("Statement", []))
    for i, st in enumerate(statements):
        if st.get("Effect") != "Allow":
            continue
        actions = as_list(st.get("Action", []))
        resources = as_list(st.get("Resource", []))
        principal = st.get("Principal")
        has_condition = bool(st.get("Condition"))

        full_wild = "*" in actions
        service_wild = [a for a in actions if isinstance(a, str) and a.endswith(":*") and a != "*"]
        res_wild = "*" in resources

        if full_wild and res_wild:
            sev, title = "CRITICAL", 'Full admin access ("Action": "*" on "Resource": "*")'
        elif full_wild:
            sev, title = "CRITICAL", 'Wildcard action ("Action": "*")'
        elif service_wild and res_wild:
            sev, title = "HIGH", f"Service-wide wildcard {service_wild} on all resources"
        elif res_wild and not has_condition:
            sev, title = "MEDIUM", 'Applies to all resources ("Resource": "*")'
        else:
            sev, title = None, None

        if sev:
            findings.append(
                {
                    "type": "IAM",
                    "severity": sev,
                    "file": path,
                    "line": f"Statement[{i}]",
                    "title": title,
                    "evidence": json.dumps({"Action": actions, "Resource": resources}),
                    "fix": "Grant only the specific actions and resource ARNs needed (least privilege).",
                }
            )

        if principal in ("*", {"AWS": "*"}) and not has_condition:
            findings.append(
                {
                    "type": "IAM",
                    "severity": "CRITICAL",
                    "file": path,
                    "line": f"Statement[{i}]",
                    "title": 'Public access (Principal "*") with no condition',
                    "evidence": json.dumps({"Principal": principal}),
                    "fix": "Restrict Principal to specific accounts/roles or add an aws:SourceArn / aws:PrincipalOrgID condition.",
                }
            )
    return findings


def suggest_least_privilege(policy):
    """Rewrite wildcard statements into a safer starting template."""
    safe = json.loads(json.dumps(policy))
    for st in as_list(safe.get("Statement", [])):
        if st.get("Effect") != "Allow":
            continue
        actions = as_list(st.get("Action", []))
        if "*" in actions or any(a.endswith(":*") for a in actions if isinstance(a, str)):
            new_actions = []
            for a in actions:
                if a == "*":
                    new_actions += ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
                elif a == "s3:*":
                    new_actions += ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
                elif a == "ec2:*":
                    new_actions += ["ec2:DescribeInstances", "ec2:StartInstances", "ec2:StopInstances"]
                elif a == "iam:*":
                    new_actions += ["iam:GetUser", "iam:ListRoles"]
                else:
                    new_actions.append(a)
            st["Action"] = sorted(set(new_actions))
        if "*" in as_list(st.get("Resource", [])):
            st["Resource"] = [
                "arn:aws:s3:::YOUR-BUCKET-NAME",
                "arn:aws:s3:::YOUR-BUCKET-NAME/*",
            ]
            st["Condition"] = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    # merge duplicate statements produced by the rewrite
    unique = []
    for st in as_list(safe.get("Statement", [])):
        if st not in unique:
            unique.append(st)
    safe["Statement"] = unique
    return safe


# ---------- Terraform / IaC (simple text checks) ----------
def scan_iac(path, text):
    findings = []
    checks = [
        (r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', "HIGH", "Security group open to the whole internet (0.0.0.0/0)"),
        (r'acl\s*=\s*"public-read(-write)?"', "HIGH", "S3 bucket is publicly readable"),
        (r'actions\s*=\s*\[\s*"\*"\s*\]', "CRITICAL", 'IAM policy with wildcard actions ["*"]'),
    ]
    for lineno, line in enumerate(text.splitlines(), 1):
        for pat, sev, title in checks:
            if re.search(pat, line):
                findings.append(
                    {
                        "type": "IaC",
                        "severity": sev,
                        "file": path,
                        "line": lineno,
                        "title": title,
                        "evidence": line.strip(),
                        "fix": "Restrict to specific IP ranges / make bucket private / use least-privilege actions.",
                    }
                )
    return findings


# ---------- file walking ----------
def iter_files(target):
    if os.path.isfile(target):
        yield target
        return
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if os.path.splitext(f)[1].lower() not in SKIP_EXT:
                yield os.path.join(root, f)


def scan_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return []
    findings = scan_text_for_secrets(path, text)
    if path.endswith(".json"):
        try:
            data = json.loads(text)
            if isinstance(data, dict) and "Statement" in data:
                findings += analyze_policy(path, data)
        except json.JSONDecodeError:
            pass
    if path.endswith(".tf"):
        findings += scan_iac(path, text)
    return findings


# ---------- reporting ----------
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEV_COLOR = {"CRITICAL": R, "HIGH": R, "MEDIUM": Y, "LOW": G}
SEV_POINTS = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2}


def risk_score(findings):
    return min(100, sum(SEV_POINTS[f["severity"]] for f in findings))


def print_report(findings):
    if not findings:
        print(f"{G}{B}CloudGuard: no issues found. Safe to commit.{X}")
        return
    findings.sort(key=lambda f: SEV_ORDER[f["severity"]])
    print(f"\n{B}=== CloudGuard Security Report ==={X}")
    for f in findings:
        c = SEV_COLOR[f["severity"]]
        print(f"\n{c}{B}[{f['severity']}]{X} {f['title']}")
        print(f"  Where   : {f['file']}:{f['line']}")
        print(f"  Evidence: {f['evidence']}")
        print(f"  Fix     : {f['fix']}")
    score = risk_score(findings)
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print(f"\n{B}Summary:{X} " + ", ".join(f"{v} {k}" for k, v in counts.items()))
    print(f"{B}Overall risk score:{X} {score}/100")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 0
    cmd = sys.argv[1]

    if cmd == "scan":
        target = sys.argv[2] if len(sys.argv) > 2 else "."
        findings = []
        for p in iter_files(target):
            findings += scan_file(p)
        print_report(findings)
        return 1 if any(f["severity"] in ("CRITICAL", "HIGH") for f in findings) else 0

    if cmd == "fix":
        with open(sys.argv[2]) as fh:
            policy = json.load(fh)
        print(f"{B}Suggested least-privilege policy (edit the placeholders):{X}")
        print(json.dumps(suggest_least_privilege(policy), indent=2))
        return 0

    if cmd == "precommit":
        out = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True,
        ).stdout.split()
        findings = []
        for p in out:
            if os.path.isfile(p):
                findings += scan_file(p)
        if any(f["severity"] in ("CRITICAL", "HIGH") for f in findings):
            print_report(findings)
            print(f"\n{R}{B}COMMIT BLOCKED by CloudGuard. Fix the issues above and commit again.{X}")
            return 1
        print(f"{G}CloudGuard: staged files look clean.{X}")
        return 0

    print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
