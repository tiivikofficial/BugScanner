"""
Data modelləri — Vulnerability, ScanResult, SeverityRating
"""

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import Optional

from core.asset_inventory import Asset


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score_range(self) -> tuple:
        return {"critical": (9.0, 10.0), "high": (7.0, 8.9), "medium": (4.0, 6.9), "low": (1.0, 3.9), "info": (0.0, 0.9)}[self.value]

    @property
    def color(self) -> str:
        return {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue", "info": "dim"}[self.value]

    @property
    def emoji(self) -> str:
        return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}[self.value]


def calculate_severity(cvss_score: float) -> Severity:
    if cvss_score >= 9.0: return Severity.CRITICAL
    if cvss_score >= 7.0: return Severity.HIGH
    if cvss_score >= 4.0: return Severity.MEDIUM
    if cvss_score >= 1.0: return Severity.LOW
    return Severity.INFO


@dataclass
class Vulnerability:
    vuln_type: str
    url: str
    severity: Severity
    cvss_score: float = 0.0
    title: str = ""
    description: str = ""
    evidence: str = ""
    exploitation: str = ""
    remediation: str = ""
    parameter: Optional[str] = None
    method: Optional[str] = "GET"
    payload_used: Optional[str] = None
    curl_poc: Optional[str] = None
    cwe_id: Optional[str] = None
    references: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    evidence_quality: float = 0.0
    independent_confirmations: int = 0
    confidence: float = 0.0
    verification_status: str = "unverified"
    exploitability: str = "not-assessed"
    impact_status: str = "unconfirmed"
    poc_available: bool = False
    poc_status: str = "not-generated"
    safe_verification: str = ""
    verification_observed: bool = False
    risk_priority: str = "P3"
    source_modules: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"vuln_type": self.vuln_type, "url": self.url, "severity": self.severity.value, "cvss_score": self.cvss_score, "title": self.title, "description": self.description, "evidence": self.evidence, "exploitation": self.exploitation, "remediation": self.remediation, "parameter": self.parameter, "method": self.method, "payload_used": self.payload_used, "curl_poc": self.curl_poc, "cwe_id": self.cwe_id, "references": self.references, "timestamp": self.timestamp.isoformat(), "evidence_quality": self.evidence_quality, "independent_confirmations": self.independent_confirmations, "confidence": self.confidence, "verification_status": self.verification_status, "exploitability": self.exploitability, "impact_status": self.impact_status, "poc_available": self.poc_available, "poc_status": self.poc_status, "safe_verification": self.safe_verification, "verification_observed": self.verification_observed, "risk_priority": self.risk_priority, "source_modules": self.source_modules}


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    version: Optional[str] = None
    banner: Optional[str] = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


@dataclass
class SubdomainInfo:
    subdomain: str
    ip: Optional[str] = None
    status: Optional[int] = None
    technologies: list[str] = field(default_factory=list)
    open_ports: list[PortInfo] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    assets: list[Asset] = field(default_factory=list)
    subdomains: list[SubdomainInfo] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    open_ports: list[PortInfo] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    duplicates_filtered: int = 0
    false_positives_filtered: int = 0
    manifest: dict = field(default_factory=dict)

    @property
    def vuln_count_by_severity(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for v in self.vulnerabilities: counts[v.severity.value] += 1
        return counts

    @property
    def risk_score(self) -> float:
        if not self.vulnerabilities: return 0.0
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        total = sum(v.cvss_score * weights[v.severity.value] for v in self.vulnerabilities)
        max_possible = len(self.vulnerabilities) * 10 * 4
        return round((total / max_possible) * 10, 2) if max_possible > 0 else 0.0

    def to_dict(self) -> dict:
        return {"target": self.target, "start_time": self.start_time.isoformat(), "end_time": self.end_time.isoformat() if self.end_time else None, "summary": {"assets_found": len(self.assets), "subdomains_found": len(self.subdomains), "open_ports": len(self.open_ports), "endpoints_found": len(self.endpoints), "total_vulnerabilities": len(self.vulnerabilities), "duplicates_filtered": self.duplicates_filtered, "false_positives_filtered": self.false_positives_filtered, "by_severity": self.vuln_count_by_severity, "risk_score": self.risk_score}, "manifest": self.manifest, "assets": [{"type": a.asset_type.value, "value": a.value, "sources": a.sources, "metadata": a.metadata} for a in self.assets], "subdomains": [{"subdomain": s.subdomain, "ip": s.ip, "status": s.status, "technologies": s.technologies, "open_ports": [p.__dict__ for p in s.open_ports], "vulnerabilities": [v.to_dict() for v in s.vulnerabilities]} for s in self.subdomains], "technologies": self.technologies, "open_ports": [p.__dict__ for p in self.open_ports], "endpoints": self.endpoints, "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]}
