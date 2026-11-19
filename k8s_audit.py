#!/usr/bin/env python3
"""
K8s Zero-Trust & CIS Pod Security Auditor (k8s_audit.py)
Audits Kubernetes Deployment/Pod YAML manifests against CIS Kubernetes Benchmark
& Pod Security Standards (Restricted profile) with zero external dependencies.
Author: Wallison Araujo (@WallisonWS) | License: MIT
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List


def audit_k8s_yaml(yaml_text: str) -> Dict[str, Any]:
    checks = [
        ("Privileged Container Enabled", "CRITICAL", 30, bool(re.search(r"privileged:\s*true", yaml_text, re.I))),
        ("HostNetwork / HostPID Exposed", "CRITICAL", 25, bool(re.search(r"host(?:Network|PID|IPC):\s*true", yaml_text, re.I))),
        ("Mutable :latest Image Tag", "MEDIUM", 10, bool(re.search(r"image:\s*[^\s]+:latest\b", yaml_text, re.I))),
        ("Missing runAsNonRoot: true", "HIGH", 15, not bool(re.search(r"runAsNonRoot:\s*true", yaml_text, re.I))),
        ("Missing readOnlyRootFilesystem: true", "MEDIUM", 10, not bool(re.search(r"readOnlyRootFilesystem:\s*true", yaml_text, re.I))),
        ("Missing allowPrivilegeEscalation: false", "HIGH", 15, not bool(re.search(r"allowPrivilegeEscalation:\s*false", yaml_text, re.I))),
        ("Missing Capabilities drop ALL", "MEDIUM", 10, not bool(re.search(r"drop:\s*(?:\[\s*['\"]?ALL['\"]?\s*\]|\n\s*-\s*ALL)", yaml_text, re.I))),
        ("Missing Resource Limits (CPU/Memory)", "LOW", 5, not bool(re.search(r"limits:", yaml_text, re.I))),
    ]
    findings: List[Dict[str, Any]] = []
    penalty = 0
    for title, sev, weight, violated in checks:
        if violated:
            penalty += weight
            findings.append({"rule": title, "severity": sev, "penalty": weight})
    score = max(0, 100 - penalty)
    return {"cis_hardening_score": score, "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "F", "findings": findings}


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="k8s-audit", description="Kubernetes CIS Pod Security Standards Auditor")
    parser.add_argument("manifest", help="Path to Kubernetes YAML file")
    args = parser.parse_args(argv)
    res = audit_k8s_yaml(Path(args.manifest).read_text(encoding="utf-8", errors="ignore"))
    print(json.dumps(res, indent=2))
    return 2 if res["cis_hardening_score"] < 70 else 0


if __name__ == "__main__":
    sys.exit(main())
