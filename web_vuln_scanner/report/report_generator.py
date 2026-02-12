"""
Professional Report Generator
==============================

Generates pentester-quality reports with:
- Executive summary
- Vulnerability details
- Evidence
- Fix recommendations
- OWASP mapping

"""

from datetime import datetime
from utils.vuln_definitions import get_vuln_info, get_owasp_info


class ReportGenerator:
    """
    Creates professional security reports.
    
    Like writing a medical report after examining a patient.
    """
    
    def __init__(self, target_url):
        """Initialize the report."""
        self.target_url = target_url
        self.scan_time = datetime.now()
        self.findings = []
        self.stats = {}
    
    def add_finding(self, vuln_type, url, param, confidence, evidence, payload=""):
        """
        Add a vulnerability finding to the report.
        
        Args:
            vuln_type: Type of vulnerability (sqli, xss, etc.)
            url: Where it was found
            param: Which parameter is vulnerable
            confidence: HIGH/MEDIUM/LOW
            evidence: Proof it's vulnerable
            payload: The payload that worked
        """
        vuln_info = get_vuln_info(vuln_type)
        
        finding = {
            "vuln_type": vuln_type,
            "name": vuln_info.get("name", "Unknown"),
            "url": url,
            "param": param,
            "confidence": confidence,
            "evidence": evidence,
            "payload": payload,
            "severity": vuln_info.get("severity", "Unknown"),
            "owasp": vuln_info.get("owasp", "N/A"),
            "cwe": vuln_info.get("cwe", "N/A"),
            "remediation": vuln_info.get("remediation", "No fix available"),
            "description": vuln_info.get("description", ""),
            "impact": vuln_info.get("impact", "")
        }
        
        self.findings.append(finding)
    
    def set_stats(self, stats):
        """Set scanning statistics."""
        self.stats = stats
    
    def generate_console_report(self):
        """
        Generate a detailed console report.
        
        This is the fancy report shown in the terminal.
        """
        lines = []
        
        # Header
        lines.append("")
        lines.append("=" * 80)
        lines.append("                    VULNERABILITY ASSESSMENT REPORT")
        lines.append("=" * 80)
        lines.append(f"Target: {self.target_url}")
        lines.append(f"Scan Date: {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 80)
        
        # Executive Summary
        lines.append("")
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 80)
        
        total = len(self.findings)
        high = len([f for f in self.findings if f["confidence"] == "HIGH"])
        medium = len([f for f in self.findings if f["confidence"] == "MEDIUM"])
        low = len([f for f in self.findings if f["confidence"] == "LOW"])
        
        critical = len([f for f in self.findings if f["severity"] == "Critical"])
        high_sev = len([f for f in self.findings if f["severity"] == "High"])
        medium_sev = len([f for f in self.findings if f["severity"] == "Medium"])
        lines.append(f"Total Vulnerabilities Found: {total}")
        lines.append(f"  - Critical Severity: {critical}")
        lines.append(f"  - High Severity: {high_sev}")
        lines.append("")
        lines.append(f"Confidence Levels:")
        lines.append(f"  - High Confidence: {high}")
        lines.append(f"  - Medium Confidence: {medium}")
        lines.append(f"  - Low Confidence: {low}")
        
        if total > 0:
            lines.append("")
            lines.append("RISK ASSESSMENT: HIGH RISK")
            lines.append("Immediate action required to address critical vulnerabilities.")
        else:
            lines.append("")
            lines.append("RISK ASSESSMENT: LOW RISK")
            lines.append("No vulnerabilities detected during this scan.")
        
        # OWASP Breakdown
        lines.append("")
        lines.append("=" * 80)
        lines.append("OWASP TOP 10 MAPPING")
        lines.append("-" * 80)
        
        owasp_groups = {}
        for finding in self.findings:
            owasp = finding["owasp"]
            if owasp not in owasp_groups:
                owasp_groups[owasp] = []
            owasp_groups[owasp].append(finding)
        
        for owasp_id in sorted(owasp_groups.keys()):
            owasp_info = get_owasp_info(owasp_id)
            lines.append(f"\n{owasp_id}: {owasp_info.get('name', 'Unknown')}")
            for finding in owasp_groups[owasp_id]:
                lines.append(f"  - {finding['name']} (Severity: {finding['severity']}, Confidence: {finding['confidence']})")
        
        # Detailed Findings
        lines.append("")
        lines.append("=" * 80)
        lines.append("DETAILED FINDINGS")
        lines.append("=" * 80)
        
        for i, finding in enumerate(self.findings, 1):
            lines.append("")
            lines.append(f"[{i}] {finding['name']}")
            lines.append("-" * 80)
            lines.append(f"Severity: {finding['severity']}")
            lines.append(f"Confidence: {finding['confidence']}")
            lines.append(f"OWASP: {finding['owasp']} - {get_owasp_info(finding['owasp']).get('name', '')}")
            lines.append(f"CWE: {finding['cwe']}")
            lines.append("")
            lines.append(f"Location:")
            lines.append(f"  URL: {finding['url']}")
            lines.append(f"  Parameter: {finding['param']}")
            lines.append("")
            lines.append(f"Description:")
            lines.append(f"  {finding['description']}")
            lines.append("")
            lines.append(f"Evidence:")
            lines.append(f"  {finding['evidence']}")
            if finding.get('payload'):
                lines.append(f"  Payload: {finding['payload']}")
            lines.append("")
            lines.append(f"Impact:")
            lines.append(f"  {finding['impact']}")
            lines.append("")
            lines.append(f"Remediation:")
            lines.append(f"  {finding['remediation']}")
        
        # Scan Statistics
        if self.stats:
            lines.append("")
            lines.append("=" * 80)
            lines.append("SCAN STATISTICS")
            lines.append("-" * 80)
            lines.append(f"Total Requests: {self.stats.get('total_requests', 0)}")
            lines.append(f"URLs Scanned: {self.stats.get('urls_visited', 0)}")
            lines.append(f"Scan Duration: {self.stats.get('duration', 'N/A')}")
        
        # Footer
        lines.append("")
        lines.append("=" * 80)
        lines.append("                         END OF REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        return "\n".join(lines)
    
    def save_to_file(self, filename):
        """
        Save the report to a text file.
        
        Args:
            filename: Name of file to save to
        """
        report = self.generate_console_report()
        
        with open(filename, "w") as f:
            f.write(report)
        
        return filename
    
    def generate_summary(self):
        """
        Generate a quick summary for display during scanning.
        
        Returns:
            String with summary
        """
        total = len(self.findings)
        high = len([f for f in self.findings if f["confidence"] == "HIGH"])
        
        if total == 0:
            return "No vulnerabilities found"
        
        return f"{total} vulnerabilities found ({high} high confidence)"

