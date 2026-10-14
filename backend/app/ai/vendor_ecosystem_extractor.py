"""
Vendor Ecosystem Extractor

Extracts third-party vendors, technologies, and relationships from customer documents.
Distinguishes vendors from technologies and classifies third-party roles.
"""
import json
import logging
import re
from typing import Dict, Any, List, Optional

from app.ai.ollama_client import ask_mistral_with_fallback, OLLAMA_MODEL

logger = logging.getLogger(__name__)

# Controlled vocabulary for third-party relationship types
RELATIONSHIP_TYPES = [
    "CLOUD_PROVIDER",
    "IDENTITY_PROVIDER",
    "CDN_PROVIDER",
    "DNS_PROVIDER",
    "CODE_REPOSITORY",
    "SECURITY_PROVIDER",
    "EDR_PROVIDER",
    "SIEM_PROVIDER",
    "EMAIL_PROVIDER",
    "COLLABORATION_PROVIDER",
    "DATABASE_PROVIDER",
    "HOSTING_PROVIDER",
    "SAAS_PROVIDER",
    "PAYMENT_PROVIDER",
    "CRM_PROVIDER",
    "ERP_PROVIDER",
    "NETWORK_PROVIDER",
    "TELECOMMUNICATION_PROVIDER",
    "BACKUP_PROVIDER",
    "STORAGE_PROVIDER",
    "IT_SERVICE_PROVIDER",
    "MSP",
    "MSSP",
    "SOFTWARE_VENDOR",
    "HARDWARE_VENDOR",
    "DATA_PROVIDER",
    "ANALYTICS_PROVIDER",
    "DEVELOPER_PLATFORM",
    "OTHER",
]

# Known third-party vendors (for classification)
KNOWN_THIRD_PARTY_VENDORS = {
    "aws": "CLOUD_PROVIDER",
    "amazon web services": "CLOUD_PROVIDER",
    "microsoft": "SOFTWARE_VENDOR",
    "microsoft corporation": "SOFTWARE_VENDOR",
    "microsoft azure": "CLOUD_PROVIDER",
    "microsoft 365": "COLLABORATION_PROVIDER",
    "office 365": "COLLABORATION_PROVIDER",
    "azure ad": "IDENTITY_PROVIDER",
    "google cloud": "CLOUD_PROVIDER",
    "google workspace": "COLLABORATION_PROVIDER",
    "g suite": "COLLABORATION_PROVIDER",
    "cloudflare": "CDN_PROVIDER",
    "github": "CODE_REPOSITORY",
    "gitlab": "CODE_REPOSITORY",
    "okta": "IDENTITY_PROVIDER",
    "crowdstrike": "EDR_PROVIDER",
    "crowdstrike falcon": "EDR_PROVIDER",
    "salesforce": "CRM_PROVIDER",
    "servicenow": "IT_SERVICE_PROVIDER",
    "workday": "HR_PROVIDER",
    "slack": "COLLABORATION_PROVIDER",
    "zoom": "COLLABORATION_PROVIDER",
    "dropbox": "STORAGE_PROVIDER",
    "box": "STORAGE_PROVIDER",
    "atlassian": "COLLABORATION_PROVIDER",
    "jira": "COLLABORATION_PROVIDER",
    "confluence": "COLLABORATION_PROVIDER",
    "snowflake": "DATABASE_PROVIDER",
    "databricks": "ANALYTICS_PROVIDER",
    "tableau": "ANALYTICS_PROVIDER",
    "splunk": "SIEM_PROVIDER",
    "elastic": "ANALYTICS_PROVIDER",
    "elasticsearch": "ANALYTICS_PROVIDER",
    "datadog": "MONITORING_PROVIDER",
    "new relic": "MONITORING_PROVIDER",
    "pagerduty": "IT_SERVICE_PROVIDER",
    "twilio": "TELECOMMUNICATION_PROVIDER",
    "sendgrid": "EMAIL_PROVIDER",
    "mailchimp": "EMAIL_PROVIDER",
    "stripe": "PAYMENT_PROVIDER",
    "paypal": "PAYMENT_PROVIDER",
    "adobe": "SOFTWARE_VENDOR",
    "adobe creative cloud": "SOFTWARE_VENDOR",
    "oracle": "DATABASE_PROVIDER",
    "oracle cloud": "CLOUD_PROVIDER",
    "sap": "ERP_PROVIDER",
    "ibm": "IT_SERVICE_PROVIDER",
    "ibm cloud": "CLOUD_PROVIDER",
    "cisco": "NETWORK_PROVIDER",
    "cisco systems": "NETWORK_PROVIDER",
    "juniper": "NETWORK_PROVIDER",
    "palo alto networks": "SECURITY_PROVIDER",
    "checkpoint": "SECURITY_PROVIDER",
    "fortinet": "SECURITY_PROVIDER",
    "vmware": "SOFTWARE_VENDOR",
    "citrix": "SOFTWARE_VENDOR",
    "netapp": "STORAGE_PROVIDER",
    "dell": "HARDWARE_VENDOR",
    "hp": "HARDWARE_VENDOR",
    "hpe": "HARDWARE_VENDOR",
    "lenovo": "HARDWARE_VENDOR",
    "akamai": "CDN_PROVIDER",
    "fastly": "CDN_PROVIDER",
    "heroku": "CLOUD_PROVIDER",
    "digitalocean": "CLOUD_PROVIDER",
    "linode": "HOSTING_PROVIDER",
    "rackspace": "HOSTING_PROVIDER",
    "godaddy": "HOSTING_PROVIDER",
    "namecheap": "DNS_PROVIDER",
    "cloudns": "DNS_PROVIDER",
    "auth0": "IDENTITY_PROVIDER",
    "ping identity": "IDENTITY_PROVIDER",
    "onelogin": "IDENTITY_PROVIDER",
    "sailpoint": "IDENTITY_PROVIDER",
    "cyberark": "SECURITY_PROVIDER",
    "beyondtrust": "SECURITY_PROVIDER",
    "thycotic": "SECURITY_PROVIDER",
    "qualys": "SECURITY_PROVIDER",
    "rapid7": "SECURITY_PROVIDER",
    "tenable": "SECURITY_PROVIDER",
    "trend micro": "SECURITY_PROVIDER",
    "mcafee": "SECURITY_PROVIDER",
    "symantec": "SECURITY_PROVIDER",
    "kaspersky": "SECURITY_PROVIDER",
    "sophos": "SECURITY_PROVIDER",
    "sentinelone": "EDR_PROVIDER",
    "cylance": "EDR_PROVIDER",
    "carbon black": "EDR_PROVIDER",
    "fireeye": "SECURITY_PROVIDER",
    "mandiant": "SECURITY_PROVIDER",
    "recorded future": "ANALYTICS_PROVIDER",
    "threatconnect": "ANALYTICS_PROVIDER",
    "anomali": "ANALYTICS_PROVIDER",
    "mis": "MSSP",
    "secureworks": "MSSP",
    "optic": "MSSP",
}

# Known technologies that are NOT third-party vendors
NON_VENDOR_TECHNOLOGIES = {
    "linux", "ubuntu", "debian", "red hat", "centos", "fedora",
    "windows", "windows server", "windows 10", "windows 11",
    "nginx", "apache", "apache http server", "apache tomcat",
    "postgresql", "mysql", "mariadb", "mongodb", "redis", "elasticsearch",
    "docker", "kubernetes", "jenkins", "git", "terraform", "ansible",
    "python", "java", "javascript", "node.js", "go", "rust", "php",
    "react", "angular", "vue.js", "django", "flask", "spring",
    "openssl", "openssh", "ssh", "tls", "ssl",
    "json", "xml", "yaml", "csv",
    "html", "css", "http", "https", "ftp", "sftp",
    "tcp", "udp", "ip", "dns", "dhcp",
    "wifi", "bluetooth", "vpn",
}


class VendorEcosystemExtractor:
    """Extract third-party vendors and technologies from customer documents."""
    
    def __init__(self):
        self.extraction_prompt = """
You are a cybersecurity and IT infrastructure analyst. Your task is to analyze a customer's technical document and identify:

1. THIRD-PARTY VENDORS - External companies/services the customer uses
2. THIRD-PARTY TECHNOLOGIES - Technologies provided by the vendor
3. CUSTOMER TECHNOLOGIES - Internal/self-hosted technologies not belonging to a specific external third-party vendor
4. RELATIONSHIP TYPES - How the third party is used
5. RISK FACTORS - Evidence for risk assessment
6. EVIDENCE - Document text supporting each detection

CRITICAL: Return ONLY a valid JSON object. No explanations. No markdown. No extra text.

Required JSON format:
{
  "vendors": [
    {
      "name": "AWS",
      "type": "vendor",
      "relationship_type": "CLOUD_PROVIDER",
      "criticality": "CRITICAL",
      "data_sensitivity": "HIGH",
      "confidence": 95,
      "evidence": "AWS provides the organization's production cloud infrastructure.",
      "risk_factors": {
        "criticality": "CRITICAL",
        "data_sensitivity": "HIGH",
        "privileged_access": true,
        "business_dependency": "HIGH",
        "internet_exposed": true,
        "regulatory_relevance": ["GDPR"],
        "evidence": [
          "Provides identity authentication",
          "Processes customer data"
        ]
      },
      "technologies": ["EC2", "S3", "EKS", "RDS"]
    }
  ],
  "customer_technologies": [
    {
      "name": "PostgreSQL",
      "category": "database",
      "confidence": 90,
      "evidence": "We run our own PostgreSQL database cluster internally."
    }
  ]
}

RELATIONSHIP TYPES (use ONLY these exact values):
CLOUD_PROVIDER, IDENTITY_PROVIDER, CDN_PROVIDER, DNS_PROVIDER, CODE_REPOSITORY,
SECURITY_PROVIDER, EDR_PROVIDER, SIEM_PROVIDER, EMAIL_PROVIDER, COLLABORATION_PROVIDER,
DATABASE_PROVIDER, HOSTING_PROVIDER, SAAS_PROVIDER, PAYMENT_PROVIDER, CRM_PROVIDER,
ERP_PROVIDER, NETWORK_PROVIDER, TELECOMMUNICATION_PROVIDER, BACKUP_PROVIDER,
STORAGE_PROVIDER, IT_SERVICE_PROVIDER, MSP, MSSP, SOFTWARE_VENDOR, HARDWARE_VENDOR,
DATA_PROVIDER, ANALYTICS_PROVIDER, DEVELOPER_PLATFORM, OTHER

CRITICALITY: CRITICAL, HIGH, MEDIUM, LOW
DATA_SENSITIVITY: HIGH, MEDIUM, LOW

VENDOR vs TECHNOLOGY DISTINCTION:
- VENDOR: External company/service provider (AWS, Microsoft, Cloudflare, GitHub, Okta, CrowdStrike)
- TECHNOLOGY: Software/platform/tool (Linux, PostgreSQL, Nginx, Docker, Kubernetes, OpenSSL)

If unsure whether something is a vendor or technology:
- Set type to "potential_vendor" with lower confidence (40-60)
- Include reason in evidence
- Example: "PostgreSQL" could be a technology OR a database service provider

CONFIDENCE SCORING:
- 90-100: Explicit vendor name with clear relationship evidence
- 70-89: Vendor mentioned with some context
- 50-69: Vendor mentioned but relationship unclear
- 40-49: Potential vendor (could be technology)
- Below 40: Too uncertain, exclude

RISK FACTORS MUST BE EXPLAINABLE:
- Do NOT just output "risk_score": 85
- Extract actual evidence: privileged_access, business_dependency, internet_exposed, regulatory_relevance
- Include document quotes supporting each factor

EVIDENCE REQUIREMENTS:
- Must include actual text from the document
- Should be specific quotes or paraphrases
- Include context about how the entity is used

TECHNOLOGIES LIST:
- Include specific products/services mentioned for each vendor
- Example: AWS -> ["EC2", "S3", "EKS", "RDS", "CloudFront"]

Document text:
"""
    
    def extract_from_text(self, text: str, filename: str = "") -> Dict[str, Any]:
        """Extract vendor ecosystem from document text using AI.
        
        Returns:
            dict: On success: {"entities": [...], "model": str, "duration": float}
                  On failure: {"status": "failed", "reason": str, "model": str}
        """
        import time
        logger.info(f"[VENDOR ECOSYSTEM EXTRACTION] Starting extraction from {filename}")
        start_time = time.time()
        model_used = OLLAMA_MODEL
        
        try:
            prompt = self.extraction_prompt + text
            logger.info(f"[VENDOR ECOSYSTEM EXTRACTION] Calling AI model...")
            
            ai_result = ask_mistral_with_fallback(prompt)
            response = ai_result["response"]
            model_used = ai_result["model"]
            
            logger.info(f"[VENDOR ECOSYSTEM EXTRACTION] Raw response received, length={len(response)} chars")
            
            # Parse JSON response
            result = self._parse_json_response(response)
            
            if result is None:
                return {
                    "status": "failed",
                    "reason": "Could not extract valid JSON from AI response",
                    "model": model_used,
                }
            
            vendors = result.get("vendors", [])
            customer_technologies = result.get("customer_technologies", [])
            
            # Compatibility fallback if the AI used "entities" instead of the new format
            if not vendors and "entities" in result:
                vendors = [e for e in result["entities"] if e.get("type", "vendor").lower() == "vendor"]
                # For technologies incorrectly classified as entities
                for e in result["entities"]:
                    if e.get("type", "").lower() == "technology":
                        customer_technologies.append({
                            "name": e.get("name", ""),
                            "evidence": e.get("evidence", ""),
                            "confidence": e.get("confidence", 70),
                            "category": "other"
                        })
            
            # Post-process vendors
            processed_vendors = self._post_process_entities(vendors)
            
            # Post-process customer technologies
            processed_technologies = []
            for tech in customer_technologies:
                if isinstance(tech, dict) and tech.get("name"):
                    processed_technologies.append({
                        "name": tech.get("name", "").strip(),
                        "category": tech.get("category", "other").lower(),
                        "confidence": int(tech.get("confidence", 70)),
                        "evidence": tech.get("evidence", "")
                    })
            
            total_time = time.time() - start_time
            logger.info(f"[VENDOR ECOSYSTEM EXTRACTION] Extracted {len(processed_vendors)} vendors and {len(processed_technologies)} customer technologies in {total_time:.2f}s")
            
            return {
                "vendors": processed_vendors,
                "customer_technologies": processed_technologies,
                "model": model_used,
                "duration": round(total_time, 2),
            }
            
        except Exception as e:
            logger.error(f"[VENDOR ECOSYSTEM EXTRACTION] Failed: {e}")
            import traceback
            logger.error(f"[VENDOR ECOSYSTEM EXTRACTION] Traceback: {traceback.format_exc()}")
            return {
                "status": "failed",
                "reason": f"Unexpected extraction error: {str(e)}",
                "model": OLLAMA_MODEL,
            }
    
    def _parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse JSON from AI response with multiple strategies."""
        result = None
        
        # Strategy 1: direct JSON
        try:
            result = json.loads(response)
            logger.info(f"[JSON PARSING] ✓ Direct JSON parsing successful")
        except json.JSONDecodeError:
            logger.info(f"[JSON PARSING] ✗ Direct JSON parsing failed, trying regex extraction")
        
        # Strategy 2: regex JSON object
        if result is None:
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                try:
                    result = json.loads(json_match.group(0))
                    logger.info(f"[JSON PARSING] ✓ JSON extracted using regex")
                except json.JSONDecodeError:
                    logger.info(f"[JSON PARSING] ✗ Regex JSON object extraction failed")
        
        # Strategy 3: markdown code block
        if result is None:
            markdown_match = re.search(r'```json\s*([\s\S]*?)\s*```', response)
            if markdown_match:
                try:
                    result = json.loads(markdown_match.group(1))
                    logger.info(f"[JSON PARSING] ✓ JSON extracted from markdown code block")
                except json.JSONDecodeError:
                    logger.info(f"[JSON PARSING] ✗ Markdown extraction failed")
        
        return result
    
    def _post_process_entities(self, entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Post-process extracted entities to normalize and validate."""
        processed = []
        
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            
            name = entity.get("name", "").strip()
            if not name:
                continue
            
            # Normalize entity type
            entity_type = entity.get("type", "vendor").lower()
            if entity_type not in ["vendor", "technology", "potential_vendor"]:
                entity_type = "vendor"
            
            # Normalize relationship type
            relationship_type = entity.get("relationship_type", "OTHER").upper()
            if relationship_type not in RELATIONSHIP_TYPES:
                relationship_type = "OTHER"
            
            # Normalize criticality
            criticality = entity.get("criticality", "MEDIUM").upper()
            if criticality not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                criticality = "MEDIUM"
            
            # Normalize data sensitivity
            data_sensitivity = entity.get("data_sensitivity", "MEDIUM").upper()
            if data_sensitivity not in ["HIGH", "MEDIUM", "LOW"]:
                data_sensitivity = "MEDIUM"
            
            # Validate confidence
            try:
                confidence = int(entity.get("confidence", 70))
                confidence = max(0, min(100, confidence))
            except (ValueError, TypeError):
                confidence = 70
            
            # Build risk factors
            risk_factors = entity.get("risk_factors", {})
            if not isinstance(risk_factors, dict):
                risk_factors = {}
            
            # Ensure risk factors have required structure
            risk_factors.setdefault("criticality", criticality)
            risk_factors.setdefault("data_sensitivity", data_sensitivity)
            risk_factors.setdefault("privileged_access", False)
            risk_factors.setdefault("business_dependency", "MEDIUM")
            risk_factors.setdefault("internet_exposed", False)
            risk_factors.setdefault("regulatory_relevance", [])
            risk_factors.setdefault("evidence", [])
            
            # Build technologies list
            technologies = entity.get("technologies", [])
            if not isinstance(technologies, list):
                technologies = []
            
            processed_entity = {
                "name": name,
                "type": entity_type,
                "relationship_type": relationship_type,
                "criticality": criticality,
                "data_sensitivity": data_sensitivity,
                "confidence": confidence,
                "evidence": entity.get("evidence", ""),
                "risk_factors": risk_factors,
                "technologies": technologies,
            }
            
            processed.append(processed_entity)
        
        logger.info(f"[POST-PROCESS] Processed {len(processed)} entities")
        return processed
    
    def classify_known_vendor(self, name: str) -> Optional[str]:
        """Classify known vendor to relationship type."""
        name_lower = name.lower().strip()
        return KNOWN_THIRD_PARTY_VENDORS.get(name_lower)
    
    def is_known_technology(self, name: str) -> bool:
        """Check if name is a known non-vendor technology."""
        name_lower = name.lower().strip()
        return name_lower in NON_VENDOR_TECHNOLOGIES
