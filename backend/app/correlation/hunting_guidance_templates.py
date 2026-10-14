"""
Hunting guidance templates for MITRE ATT&CK techniques
Template-derived approach - no AI calls, reliable and specific
"""

HUNTING_GUIDANCE_TEMPLATES = {
    # Exploitation techniques (common in CVE assessments)
    "T1190": "Monitor web server logs for anomalous requests to public-facing endpoints; review WAF rules for this vector; scan for unpatched public-facing services",
    "T1210": "Monitor remote service logs for authentication failures; review VPN/RDP access patterns for anomalies; check for unauthorized remote service usage",
    "T1499.004": "Monitor application logs for crash events or unexpected behavior; review system logs for exploitation attempts; check for unauthorized code execution",
    "T1687": "Monitor security software logs for tampering attempts; review antivirus/EDR agent status; check for disabled security controls",
    
    # Supply chain techniques (common in incident assessments)
    "T1195": "Monitor third-party software updates for unauthorized modifications; review supply chain access logs for anomalous activity; verify software signatures",
    "T1195.002": "Monitor application update processes for unauthorized changes; review software repository access logs; verify package integrity",
    "T1195.003": "Monitor hardware component deliveries for tampering; review supply chain logs for unauthorized modifications; verify hardware integrity",
    
    # Ransomware/impact techniques
    "T1486": "Monitor file system for rapid encryption activity; review backup system access logs; check for unusual file modification patterns",
    "T1553.003": "Monitor SIP and trust provider components for tampering; review certificate authority logs; check for unauthorized code signing",
    
    # Malware/upload techniques
    "T1588.001": "Monitor endpoint processes for suspicious execution; review download logs for unknown binaries; check for malware indicators",
    "T1608.001": "Monitor network traffic for upload to unknown destinations; review cloud storage access patterns; check for data exfiltration",
    
    # Virtualization techniques (from CVE assessments)
    "T1505.006": "Monitor vSphere installation bundles for unauthorized changes; review ESXi hypervisor logs; check for malicious VIBs",
    "T1564.006": "Monitor virtual machine creation and deletion; review hypervisor logs for suspicious activity; check for unauthorized virtual instances",
    
    # Common privilege escalation techniques
    "T1068": "Monitor privilege escalation events; review user account creation and modification logs; check for unauthorized admin access",
    "T1059": "Monitor command-line interpreter usage; review script execution logs; check for suspicious PowerShell/bash activity",
    "T1055": "Monitor process injection attempts; review memory access patterns; check for DLL injection indicators",
    
    # Common initial access techniques
    "T1566": "Monitor email for phishing attempts; review user-reported phishing; check for malicious attachments/links",
    "T1078": "Monitor valid account usage for anomalies; review authentication logs; check for credential sharing or reuse",
}


def get_hunting_guidance(technique_id, technique_name):
    """
    Get hunting guidance for a given MITRE technique.
    Returns curated guidance if available, otherwise generic fallback.
    """
    curated = HUNTING_GUIDANCE_TEMPLATES.get(technique_id)
    if curated:
        return curated
    
    # Generic fallback using existing technique data
    return f"Monitor for activity consistent with {technique_name} (MITRE {technique_id})"


def build_hunting_guidance_json(matched_techniques):
    """
    Build hunting_guidance JSONB from matched techniques.
    
    Args:
        matched_techniques: List of dicts with technique_id, technique_name, etc.
    
    Returns:
        JSON string with techniques and their hunting guidance
    """
    import json
    
    techniques_guidance = []
    
    for technique in matched_techniques:
        technique_id = technique.get("technique_id")
        technique_name = technique.get("technique_name")
        
        if technique_id and technique_name:
            guidance = get_hunting_guidance(technique_id, technique_name)
            techniques_guidance.append({
                "technique_id": technique_id,
                "technique_name": technique_name,
                "hunting_guidance": guidance
            })
    
    return json.dumps({"techniques": techniques_guidance})
