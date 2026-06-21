"""
DevOps Sentinel - V1
Pipeline: Changed Files -> Filter -> Rule-based Detectors -> (if findings) AI Explanation -> Formatted Comment

Design principles (V1 scope):
- Severity is DETERMINISTIC (decided by rules, never by the AI)
- AI is only used to explain a finding and suggest a fix
- Only the relevant snippet for a finding is sent to the AI, never the whole diff/PR
- If no findings are detected, exit silently (no comment posted) - avoids notification noise
- Single provider for V1: OpenRouter only
"""

import os
import re
import json
import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
PR_NUMBER = os.environ.get("PR_NUMBER")
REPO = os.environ.get("REPO")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free"

# Only these file types are ever analysed. Anything else (lockfiles, assets,
# markdown, etc.) is ignored before any detector or AI call runs.
ALLOWED_EXTENSIONS = (".py", ".yml", ".yaml")
ALLOWED_FILENAMES = ("Dockerfile",)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "SUGGESTION": 3}
SEVERITY_BADGE = {
    "CRITICAL": "\U0001F534 Critical",
    "HIGH": "\U0001F7E0 High",
    "MEDIUM": "\U0001F7E1 Medium",
    "SUGGESTION": "\U0001F7E2 Suggestion",
}


# ---------------------------------------------------------------------------
# Step 1 - Fetch changed files from the PR
# ---------------------------------------------------------------------------

def get_pr_files():
    """Returns list of {filename, patch} for files changed in the PR."""
    url = f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}/files"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }
    res = requests.get(url, headers=headers)
    res.raise_for_status()
    files = res.json()

    result = []
    for f in files:
        filename = f["filename"]
        patch = f.get("patch", "")  # patch is absent for binary/huge files
        if not patch:
            continue
        result.append({"filename": filename, "patch": patch})
    return result


# ---------------------------------------------------------------------------
# Step 2 - Filter to only relevant file types
# ---------------------------------------------------------------------------

def is_relevant_file(filename):
    basename = filename.split("/")[-1]
    if basename in ALLOWED_FILENAMES:
        return True
    return filename.endswith(ALLOWED_EXTENSIONS)


def filter_files(files):
    return [f for f in files if is_relevant_file(f["filename"])]


# ---------------------------------------------------------------------------
# Step 3 - Rule-based detectors (deterministic severity)
# ---------------------------------------------------------------------------
# Each detector function takes (filename, patch_text) and returns a list of
# findings. A finding is a dict: {file, severity, title, snippet}
# Severity here is FINAL - the AI never changes it, only explains it.

def added_lines(patch):
    """Extract only the lines that were ADDED in this diff (lines starting with +,
    excluding the +++ file header line)."""
    lines = []
    for line in patch.split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
    return lines


SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|secret|token|password|passwd)\s*=\s*['\"][A-Za-z0-9_\-\.]{8,}['\"]", "Hardcoded credential-like value"),
    (r"sk-[A-Za-z0-9]{16,}", "OpenAI/OpenRouter-style API key pattern"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key pattern"),
    (r"(?i)mongodb(\+srv)?://[^\s'\"]+:[^\s'\"]+@", "Database connection string with embedded credentials"),
]


def detect_secrets(filename, patch):
    findings = []
    for line in added_lines(patch):
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "file": filename,
                    "severity": "CRITICAL",
                    "title": f"Possible secret exposure: {label}",
                    "snippet": line.strip()[:200],
                })
    return findings


def detect_dockerfile_issues(filename, patch):
    findings = []
    basename = filename.split("/")[-1]
    if basename != "Dockerfile":
        return findings

    for line in added_lines(patch):
        stripped = line.strip()

        if re.match(r"(?i)^USER\s+root\b", stripped):
            findings.append({
                "file": filename, "severity": "HIGH",
                "title": "Container explicitly runs as root user",
                "snippet": stripped,
            })

        if re.search(r"(?i)FROM\s+[^\s]+:latest\b", stripped):
            findings.append({
                "file": filename, "severity": "MEDIUM",
                "title": "Base image uses 'latest' tag instead of a pinned version",
                "snippet": stripped,
            })

        if re.search(r"curl[^\n]*\|\s*(sh|bash)", stripped) or re.search(r"wget[^\n]*\|\s*(sh|bash)", stripped):
            findings.append({
                "file": filename, "severity": "HIGH",
                "title": "Piping a remote script directly into a shell (curl|bash pattern)",
                "snippet": stripped,
            })

    has_user_instruction = any(re.match(r"(?i)^USER\s+", l.strip()) for l in added_lines(patch))
    has_healthcheck = any(re.match(r"(?i)^HEALTHCHECK\b", l.strip()) for l in added_lines(patch))
    has_from = any(re.match(r"(?i)^FROM\b", l.strip()) for l in added_lines(patch))

    if has_from and not has_healthcheck:
        findings.append({
            "file": filename, "severity": "MEDIUM",
            "title": "No HEALTHCHECK instruction found in Dockerfile",
            "snippet": "(missing HEALTHCHECK directive)",
        })

    if has_from and not has_user_instruction:
        findings.append({
            "file": filename, "severity": "SUGGESTION",
            "title": "No explicit non-root USER instruction found",
            "snippet": "(missing USER directive - container will default to root)",
        })

    return findings


def detect_github_actions_issues(filename, patch):
    findings = []
    if not (filename.endswith(".yml") or filename.endswith(".yaml")):
        return findings
    if ".github/workflows" not in filename:
        return findings

    for line in added_lines(patch):
        stripped = line.strip()

        if re.search(r"(?i)permissions\s*:\s*write-all", stripped):
            findings.append({
                "file": filename, "severity": "HIGH",
                "title": "Workflow grants 'write-all' permissions",
                "snippet": stripped,
            })

        action_match = re.search(r"uses:\s*([\w\-]+/[\w\-]+)@(v?\d+(\.\d+)*|main|master)\b", stripped)
        if action_match:
            findings.append({
                "file": filename, "severity": "SUGGESTION",
                "title": f"Action '{action_match.group(1)}' is pinned to a tag/branch, not a commit SHA",
                "snippet": stripped,
            })

    return findings


DETECTORS = [detect_secrets, detect_dockerfile_issues, detect_github_actions_issues]


def run_detectors(files):
    all_findings = []
    for f in files:
        for detector in DETECTORS:
            all_findings.extend(detector(f["filename"], f["patch"]))
    return all_findings


# ---------------------------------------------------------------------------
# Step 4 - AI explanation (only called if findings exist, only relevant snippet sent)
# ---------------------------------------------------------------------------

def explain_finding_with_ai(finding):
    prompt = f"""You are a DevOps and security expert. A static analysis tool found the
following issue in a pull request. Explain the risk in 1-2 sentences and give a concrete fix.
Be concise. Do not repeat the title verbatim. Output plain text only, no markdown headers.

Issue: {finding['title']}
File: {finding['file']}
Code snippet:
{finding['snippet']}

Respond in this format exactly:
Impact: <1 sentence on why this matters>
Fix: <concrete fix, code if relevant>"""

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com",
        "X-Title": "DevOps-Sentinel",
    }
    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        res = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=30)
        result = res.json()
        if "choices" not in result:
            return "Impact: (AI explanation unavailable)\nFix: Review the snippet manually."
        return result["choices"][0]["message"]["content"]
    except Exception:
        return "Impact: (AI explanation unavailable)\nFix: Review the snippet manually."


# ---------------------------------------------------------------------------
# Step 5 - Format the GitHub comment
# ---------------------------------------------------------------------------

def format_comment(findings_with_explanations):
    findings_with_explanations.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])

    lines = ["## DevOps Sentinel — Review", ""]
    lines.append(f"Findings: {len(findings_with_explanations)}")
    lines.append("")
    lines.append("---")
    lines.append("")

    for f in findings_with_explanations:
        badge = SEVERITY_BADGE[f["severity"]]
        lines.append(f"### {badge} — {f['title']}")
        lines.append(f"`{f['file']}`")
        lines.append("```")
        lines.append(f["snippet"])
        lines.append("```")
        lines.append(f["explanation"])
        lines.append("")

    lines.append("---")
    lines.append("*Generated by DevOps Sentinel — findings are rule-based, explanations are AI-assisted.*")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Step 6 - Post comment to GitHub
# ---------------------------------------------------------------------------

def post_comment(body):
    url = f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }
    requests.post(url, headers=headers, json={"body": body})


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main():
    print("Fetching changed files...")
    all_files = get_pr_files()
    print(f"  {len(all_files)} files changed in total")

    print("Filtering to relevant file types (.py, .yml, .yaml, Dockerfile)...")
    relevant_files = filter_files(all_files)
    print(f"  {len(relevant_files)} relevant files after filtering")

    if not relevant_files:
        print("No relevant files to analyse. Exiting silently.")
        return

    print("Running rule-based detectors...")
    findings = run_detectors(relevant_files)
    print(f"  {len(findings)} findings detected")

    if not findings:
        print("No findings detected. Exiting silently (no comment posted).")
        return

    print("Sending findings to AI for explanation (snippet-only, not full diff)...")
    for finding in findings:
        finding["explanation"] = explain_finding_with_ai(finding)

    print("Formatting comment...")
    comment_body = format_comment(findings)

    print("Posting comment to PR...")
    post_comment(comment_body)
    print("Done.")


if __name__ == "__main__":
    main()
