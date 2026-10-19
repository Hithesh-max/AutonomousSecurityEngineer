import subprocess
import json
import logging
import uuid
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class TrivyScanner:
    """Wrapper for Trivy Container & Dependency Scanning."""
    
    def scan(self, target_path: str) -> Dict[str, Any]:
        """
        Executes Trivy. Raises FileNotFoundError if missing.
        """
        try:
            cmd = ["trivy", "fs", "--format", "json", target_path]
            logger.info(f"Executing: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return json.loads(result.stdout)
            
        except FileNotFoundError:
            logger.error("Trivy executable not found.")
            raise FileNotFoundError("Trivy executable not found. Cannot proceed with scan.")
        except json.JSONDecodeError:
            logger.error("Failed to parse Trivy JSON output.")
            raise RuntimeError("Failed to parse Trivy JSON output.")

    def normalize(self, raw_data: Dict[str, Any], project_id: uuid.UUID) -> List[Dict[str, Any]]:
        """Converts raw Trivy JSON into our Canonical Finding Schema."""
        normalized = []
        results = raw_data.get("Results", [])
        
        for result in results:
            target_file = result.get("Target", "Unknown")
            vulnerabilities = result.get("Vulnerabilities", [])
            
            for vuln in vulnerabilities:
                finding = {
                    "project_id": project_id,
                    "title": f"[{vuln.get('VulnerabilityID')}] {vuln.get('PkgName')} - {vuln.get('Title', 'Dependency Vulnerability')}",
                    "category": "Vulnerable Dependency",
                    "severity": vuln.get("Severity", "MEDIUM").upper(),
                    "confidence": "HIGH",
                    "status": "OPEN",
                    "source_tools": ["trivy"],
                    "source_location": {
                        "file": target_file,
                    },
                    "evidence": {
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "description": vuln.get("Description")
                    },
                    "cwe": vuln.get("CweIDs", [""])[0] if vuln.get("CweIDs") else None,
                    "remediation_plan": f"Upgrade {vuln.get('PkgName')} to version {vuln.get('FixedVersion')}" if vuln.get("FixedVersion") else "No patch currently available."
                }
                normalized.append(finding)
                
        return normalized
