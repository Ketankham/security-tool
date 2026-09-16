"""AI narrative + deterministic data -> dashboard, PDF, SARIF, attestation letters.

M2 slice 2 (this milestone): ScanReport, a structured JSON summary of what a
scan found (recon assets, crawled surface, authorization findings). PDF,
SARIF, the AI-written narrative, and the attestation letter are M3/Verified-
tier work — not implemented yet.
"""

from .models import ReportAsset, ReportEndpoint, ReportFinding, ScanReport

__all__ = ["ScanReport", "ReportAsset", "ReportEndpoint", "ReportFinding"]

__version__ = "0.1.0"
