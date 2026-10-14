import type {
  ChatConversation,
  Customer,
  KpiMetric,
  ReportOption,
  RiskyVendor,
  SettingsSection,
  SeverityDistribution,
  ThirdPartyVendor,
  ThreatAlert,
  ThreatFeedItem,
  ThreatTrendPoint,
} from "@/types";

export const kpiMetrics: KpiMetric[] = [
  {
    id: "total-alerts",
    label: "Total Alerts",
    value: 847,
    description: "Active across all customers",
    trend: 12.4,
    trendLabel: "vs last 30 days",
    icon: "AlertTriangle",
  },
  {
    id: "critical-threats",
    label: "Critical Threats",
    value: 23,
    description: "Require immediate action",
    trend: -8.2,
    trendLabel: "vs last 30 days",
    icon: "ShieldAlert",
  },
  {
    id: "monitored-vendors",
    label: "Monitored Vendors",
    value: 156,
    description: "Third-party integrations",
    trend: 4,
    trendFormat: "number",
    trendLabel: "new this quarter",
    icon: "Building2",
  },
  {
    id: "customers",
    label: "Customers",
    value: 42,
    description: "Under active monitoring",
    trend: 2,
    trendFormat: "number",
    trendLabel: "new this month",
    icon: "Users",
  },
];

export const threatTrendData: ThreatTrendPoint[] = [
  { date: "Jan 1", critical: 4, high: 12, medium: 28, low: 45 },
  { date: "Jan 8", critical: 6, high: 15, medium: 32, low: 41 },
  { date: "Jan 15", critical: 3, high: 18, medium: 35, low: 38 },
  { date: "Jan 22", critical: 8, high: 14, medium: 30, low: 42 },
  { date: "Jan 29", critical: 5, high: 20, medium: 38, low: 36 },
  { date: "Feb 5", critical: 9, high: 16, medium: 33, low: 40 },
  { date: "Feb 12", critical: 7, high: 22, medium: 29, low: 44 },
  { date: "Feb 19", critical: 11, high: 19, medium: 36, low: 37 },
  { date: "Feb 26", critical: 6, high: 17, medium: 31, low: 43 },
  { date: "Mar 5", critical: 10, high: 21, medium: 34, low: 39 },
  { date: "Mar 12", critical: 8, high: 18, medium: 37, low: 35 },
  { date: "Mar 19", critical: 12, high: 23, medium: 32, low: 41 },
];

export const severityDistribution: SeverityDistribution[] = [
  { name: "Critical", value: 23, color: "#EF4444" },
  { name: "High", value: 87, color: "#F97316" },
  { name: "Medium", value: 214, color: "#F59E0B" },
  { name: "Low", value: 523, color: "#2563EB" },
];

export const riskyVendors: RiskyVendor[] = [
  {
    id: "microsoft",
    name: "Microsoft",
    riskScore: 91,
    criticalCves: 5,
    logo: "MS",
    color: "#0078D4",
  },
  {
    id: "cisco",
    name: "Cisco",
    riskScore: 82,
    criticalCves: 3,
    logo: "CS",
    color: "#049FD9",
  },
  {
    id: "cloudflare",
    name: "Cloudflare",
    riskScore: 44,
    criticalCves: 1,
    logo: "CF",
    color: "#F38020",
  },
  {
    id: "aws",
    name: "AWS",
    riskScore: 27,
    criticalCves: 0,
    logo: "AW",
    color: "#FF9900",
  },
];

export const threatAlerts: ThreatAlert[] = [
  {
    id: "alert-001",
    severity: "Critical",
    vendor: "Microsoft",
    customer: "Acme Financial Corp",
    threat: "Exchange Server RCE Vulnerability",
    cve: "CVE-2026-1234",
    cvss: 9.8,
    date: "2026-03-18T14:32:00Z",
    status: "Open",
    description:
      "A critical remote code execution vulnerability in Microsoft Exchange Server allows unauthenticated attackers to execute arbitrary code via crafted HTTP requests. Exploitation has been observed in the wild targeting financial sector organizations.",
    mitreTactic: "Initial Access",
    mitreTechnique: "T1190 - Exploit Public-Facing Application",
    aiRecommendation:
      "Immediately apply Microsoft security update KB5034765. Enable enhanced monitoring on all Exchange endpoints. Consider temporary network segmentation for affected mail servers until patching is complete. Review authentication logs for anomalous access patterns from the past 72 hours.",
    timeline: [
      {
        id: "t1",
        timestamp: "2026-03-18T14:32:00Z",
        title: "Alert Detected",
        description: "Automated threat intelligence feed identified active exploitation.",
      },
      {
        id: "t2",
        timestamp: "2026-03-18T14:45:00Z",
        title: "Customer Notified",
        description: "Acme Financial Corp SOC team notified via automated workflow.",
      },
      {
        id: "t3",
        timestamp: "2026-03-18T15:10:00Z",
        title: "Risk Assessment",
        description: "AI agent assessed 3 production Exchange servers at risk.",
      },
    ],
  },
  {
    id: "alert-002",
    severity: "Critical",
    vendor: "Cisco",
    customer: "GlobalTech Industries",
    threat: "IOS XE Web UI Privilege Escalation",
    cve: "CVE-2026-0891",
    cvss: 9.1,
    date: "2026-03-17T09:15:00Z",
    status: "Investigating",
    description:
      "Critical vulnerability in Cisco IOS XE Software Web UI allows authenticated local attackers to elevate privileges to root level. Affects multiple router and switch models deployed in enterprise environments.",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "T1068 - Exploitation for Privilege Escalation",
    aiRecommendation:
      "Disable HTTP/HTTPS server on all affected Cisco devices immediately. Apply Cisco advisory patch cisco-sa-iosxe-webui. Conduct forensic review of admin account activity on affected devices.",
    timeline: [
      {
        id: "t1",
        timestamp: "2026-03-17T09:15:00Z",
        title: "Alert Detected",
        description: "Vendor advisory correlated with customer asset inventory.",
      },
      {
        id: "t2",
        timestamp: "2026-03-17T10:00:00Z",
        title: "Assigned to Analyst",
        description: "Case assigned to Tier 2 SOC analyst for investigation.",
      },
    ],
  },
  {
    id: "alert-003",
    severity: "High",
    vendor: "Cloudflare",
    customer: "RetailMax Group",
    threat: "CDN Configuration Exposure",
    cve: "CVE-2026-0456",
    cvss: 7.5,
    date: "2026-03-16T16:48:00Z",
    status: "Open",
    description:
      "Misconfiguration in Cloudflare CDN settings may expose origin server IP addresses and bypass WAF protections. Could enable direct attacks against backend infrastructure.",
    mitreTactic: "Discovery",
    mitreTechnique: "T1046 - Network Service Discovery",
    aiRecommendation:
      "Audit Cloudflare DNS and proxy settings. Enable Authenticated Origin Pulls. Verify WAF rules are active on all production zones.",
    timeline: [
      {
        id: "t1",
        timestamp: "2026-03-16T16:48:00Z",
        title: "Alert Detected",
        description: "Configuration drift detected during scheduled compliance scan.",
      },
    ],
  },
  {
    id: "alert-004",
    severity: "High",
    vendor: "AWS",
    customer: "HealthFirst Medical",
    threat: "S3 Bucket Public Access Misconfiguration",
    cve: "N/A",
    cvss: 7.2,
    date: "2026-03-15T11:22:00Z",
    status: "Investigating",
    description:
      "An AWS S3 bucket associated with a third-party healthcare analytics vendor was found with public read access enabled, potentially exposing PHI data.",
    mitreTactic: "Collection",
    mitreTechnique: "T1530 - Data from Cloud Storage",
    aiRecommendation:
      "Immediately revoke public access on affected S3 buckets. Enable S3 Block Public Access at account level. Conduct data exposure assessment and initiate breach notification procedures if PHI was accessed.",
    timeline: [
      {
        id: "t1",
        timestamp: "2026-03-15T11:22:00Z",
        title: "Alert Detected",
        description: "Cloud security posture scan identified public bucket.",
      },
      {
        id: "t2",
        timestamp: "2026-03-15T12:00:00Z",
        title: "Vendor Contacted",
        description: "Third-party vendor notified to remediate within 4 hours.",
      },
    ],
  },
  {
    id: "alert-005",
    severity: "Medium",
    vendor: "Microsoft",
    customer: "EduLearn Systems",
    threat: "Azure AD Conditional Access Bypass",
    cve: "CVE-2026-0789",
    cvss: 6.8,
    date: "2026-03-14T08:55:00Z",
    status: "Resolved",
    description:
      "A logic flaw in Azure AD conditional access policies allows bypass of MFA requirements under specific federation configurations.",
    mitreTactic: "Defense Evasion",
    mitreTechnique: "T1556 - Modify Authentication Process",
    aiRecommendation:
      "Review and update conditional access policies. Enable security defaults. Monitor sign-in logs for MFA bypass attempts.",
    timeline: [
      {
        id: "t1",
        timestamp: "2026-03-14T08:55:00Z",
        title: "Alert Detected",
        description: "Policy compliance scan flagged configuration gap.",
      },
      {
        id: "t2",
        timestamp: "2026-03-14T14:30:00Z",
        title: "Remediation Complete",
        description: "Conditional access policies updated and verified.",
      },
    ],
  },
  {
    id: "alert-006",
    severity: "Medium",
    vendor: "Cisco",
    customer: "LogiTrans Shipping",
    threat: "AnyConnect VPN Information Disclosure",
    cve: "CVE-2026-0334",
    cvss: 5.9,
    date: "2026-03-13T19:40:00Z",
    status: "Closed",
    description:
      "Cisco AnyConnect Secure Mobility Client may disclose sensitive session information through verbose error logging when connecting to compromised VPN gateways.",
    mitreTactic: "Credential Access",
    mitreTechnique: "T1552 - Unsecured Credentials",
    aiRecommendation:
      "Update AnyConnect client to version 5.1.6 or later. Disable verbose logging in production environments.",
    timeline: [
      {
        id: "t1",
        timestamp: "2026-03-13T19:40:00Z",
        title: "Alert Detected",
        description: "Vendor security bulletin matched customer deployment.",
      },
      {
        id: "t2",
        timestamp: "2026-03-14T10:00:00Z",
        title: "Patch Deployed",
        description: "Client update pushed via MDM to all endpoints.",
      },
    ],
  },
  {
    id: "alert-007",
    severity: "Low",
    vendor: "Cloudflare",
    customer: "MediaStream Inc",
    threat: "TLS Certificate Expiration Warning",
    cve: "N/A",
    cvss: 3.1,
    date: "2026-03-12T07:30:00Z",
    status: "Open",
    description:
      "SSL/TLS certificate for a Cloudflare-managed domain is scheduled to expire within 14 days. Automated renewal may fail due to DNS validation issues.",
    mitreTactic: "Impact",
    mitreTechnique: "T1498 - Network Denial of Service",
    aiRecommendation:
      "Verify DNS validation records are correctly configured. Manually trigger certificate renewal through Cloudflare dashboard.",
    timeline: [
      {
        id: "t1",
        timestamp: "2026-03-12T07:30:00Z",
        title: "Alert Detected",
        description: "Certificate monitoring detected upcoming expiration.",
      },
    ],
  },
  {
    id: "alert-008",
    severity: "High",
    vendor: "AWS",
    customer: "FinSecure Banking",
    threat: "IAM Role Over-Privilege Detected",
    cve: "N/A",
    cvss: 8.1,
    date: "2026-03-11T13:18:00Z",
    status: "Investigating",
    description:
      "Third-party SaaS integration has been granted excessive IAM permissions including iam:* and s3:* on production accounts, violating least-privilege policy.",
    mitreTactic: "Persistence",
    mitreTechnique: "T1098 - Account Manipulation",
    aiRecommendation:
      "Immediately scope down IAM role permissions to minimum required. Implement permission boundaries. Enable AWS CloudTrail alerting for privilege escalation events.",
    timeline: [
      {
        id: "t1",
        timestamp: "2026-03-11T13:18:00Z",
        title: "Alert Detected",
        description: "IAM policy analyzer flagged over-privileged role.",
      },
      {
        id: "t2",
        timestamp: "2026-03-11T14:00:00Z",
        title: "Under Review",
        description: "Cloud security team reviewing required permissions.",
      },
    ],
  },
];

export const thirdPartyVendors: ThirdPartyVendor[] = [
  {
    id: "v1",
    name: "Microsoft",
    logo: "MS",
    color: "#0078D4",
    riskScore: 91,
    activeCriticalCves: 5,
    lastIncident: "2026-03-18",
    complianceScore: 78,
    industry: "Cloud & Productivity",
    monitoredCustomers: 38,
  },
  {
    id: "v2",
    name: "Cisco",
    logo: "CS",
    color: "#049FD9",
    riskScore: 82,
    activeCriticalCves: 3,
    lastIncident: "2026-03-17",
    complianceScore: 82,
    industry: "Networking",
    monitoredCustomers: 29,
  },
  {
    id: "v3",
    name: "Cloudflare",
    logo: "CF",
    color: "#F38020",
    riskScore: 44,
    activeCriticalCves: 1,
    lastIncident: "2026-03-16",
    complianceScore: 91,
    industry: "CDN & Security",
    monitoredCustomers: 22,
  },
  {
    id: "v4",
    name: "AWS",
    logo: "AW",
    color: "#FF9900",
    riskScore: 27,
    activeCriticalCves: 0,
    lastIncident: "2026-03-11",
    complianceScore: 95,
    industry: "Cloud Infrastructure",
    monitoredCustomers: 35,
  },
  {
    id: "v5",
    name: "Salesforce",
    logo: "SF",
    color: "#00A1E0",
    riskScore: 38,
    activeCriticalCves: 1,
    lastIncident: "2026-03-08",
    complianceScore: 93,
    industry: "CRM",
    monitoredCustomers: 18,
  },
  {
    id: "v6",
    name: "ServiceNow",
    logo: "SN",
    color: "#81B5A1",
    riskScore: 52,
    activeCriticalCves: 2,
    lastIncident: "2026-03-05",
    complianceScore: 88,
    industry: "ITSM",
    monitoredCustomers: 15,
  },
  {
    id: "v7",
    name: "Okta",
    logo: "OK",
    color: "#007DC1",
    riskScore: 61,
    activeCriticalCves: 2,
    lastIncident: "2026-02-28",
    complianceScore: 86,
    industry: "Identity",
    monitoredCustomers: 31,
  },
  {
    id: "v8",
    name: "Palo Alto Networks",
    logo: "PA",
    color: "#FA582D",
    riskScore: 35,
    activeCriticalCves: 0,
    lastIncident: "2026-02-20",
    complianceScore: 96,
    industry: "Security",
    monitoredCustomers: 12,
  },
];

export const customers: Customer[] = [
  {
    id: "c1",
    name: "Acme Financial Corp",
    industry: "Financial Services",
    country: "United States",
    monitoredVendors: 24,
    riskScore: 87,
    openAlerts: 12,
    status: "At Risk",
  },
  {
    id: "c2",
    name: "GlobalTech Industries",
    industry: "Technology",
    country: "United Kingdom",
    monitoredVendors: 31,
    riskScore: 72,
    openAlerts: 8,
    status: "At Risk",
  },
  {
    id: "c3",
    name: "HealthFirst Medical",
    industry: "Healthcare",
    country: "Canada",
    monitoredVendors: 18,
    riskScore: 65,
    openAlerts: 5,
    status: "Monitoring",
  },
  {
    id: "c4",
    name: "RetailMax Group",
    industry: "Retail",
    country: "Germany",
    monitoredVendors: 15,
    riskScore: 54,
    openAlerts: 3,
    status: "Monitoring",
  },
  {
    id: "c5",
    name: "FinSecure Banking",
    industry: "Financial Services",
    country: "Singapore",
    monitoredVendors: 28,
    riskScore: 78,
    openAlerts: 7,
    status: "At Risk",
  },
  {
    id: "c6",
    name: "EduLearn Systems",
    industry: "Education",
    country: "Australia",
    monitoredVendors: 12,
    riskScore: 41,
    openAlerts: 2,
    status: "Healthy",
  },
  {
    id: "c7",
    name: "LogiTrans Shipping",
    industry: "Logistics",
    country: "Netherlands",
    monitoredVendors: 14,
    riskScore: 38,
    openAlerts: 1,
    status: "Healthy",
  },
  {
    id: "c8",
    name: "MediaStream Inc",
    industry: "Media",
    country: "United States",
    monitoredVendors: 9,
    riskScore: 33,
    openAlerts: 2,
    status: "Healthy",
  },
];

export const threatFeedItems: ThreatFeedItem[] = [
  {
    id: "tf1",
    title: "Active Exploitation of Microsoft Exchange Zero-Day",
    vendor: "Microsoft",
    severity: "Critical",
    published: "2026-03-18T12:00:00Z",
    summary:
      "Threat actors are actively exploiting CVE-2026-1234 in Microsoft Exchange Server. CISA has added this vulnerability to its Known Exploited Vulnerabilities catalog. Organizations using on-premises Exchange should prioritize patching.",
    fullContent:
      "Multiple threat intelligence sources confirm active exploitation of CVE-2026-1234 affecting Microsoft Exchange Server 2016, 2019, and Subscription Edition. The vulnerability allows unauthenticated remote code execution via the Exchange Web Services (EWS) endpoint. Observed attack patterns include deployment of web shells and lateral movement using stolen credentials.",
  },
  {
    id: "tf2",
    title: "Cisco IOS XE Zero-Day Under Active Investigation",
    vendor: "Cisco",
    severity: "Critical",
    published: "2026-03-17T08:30:00Z",
    summary:
      "Cisco has released an emergency advisory for a critical privilege escalation vulnerability in IOS XE Software. Proof-of-concept exploit code has been published, increasing urgency for patching.",
    fullContent:
      "Cisco PSIRT advisory cisco-sa-iosxe-webui-pesc addresses a critical vulnerability in the web UI of IOS XE Software. The flaw allows authenticated attackers with low privileges to escalate to root. Over 40,000 devices globally may be affected based on internet-wide scanning data.",
  },
  {
    id: "tf3",
    title: "Cloudflare WAF Bypass Technique Disclosed",
    vendor: "Cloudflare",
    severity: "High",
    published: "2026-03-16T15:45:00Z",
    summary:
      "Security researchers have disclosed a technique to bypass Cloudflare WAF rules using HTTP request smuggling. Cloudflare has deployed mitigations across its network.",
    fullContent:
      "A novel HTTP request smuggling variant has been demonstrated against Cloudflare-protected applications. While Cloudflare has implemented network-level mitigations, customers are advised to review custom WAF rule configurations and enable Bot Management where applicable.",
  },
  {
    id: "tf4",
    title: "AWS Lambda Runtime Security Update",
    vendor: "AWS",
    severity: "Medium",
    published: "2026-03-15T10:00:00Z",
    summary:
      "AWS has updated Lambda runtime environments to address multiple open-source dependency vulnerabilities. No customer action required for managed runtimes.",
    fullContent:
      "AWS automatically updated Node.js 20.x, Python 3.12, and Java 21 Lambda runtimes to include patched versions of affected dependencies. Custom runtime users should review the AWS Security Bulletin and update their deployment packages accordingly.",
  },
  {
    id: "tf5",
    title: "Okta Session Token Replay Attack Advisory",
    vendor: "Okta",
    severity: "High",
    published: "2026-03-14T09:20:00Z",
    summary:
      "Okta has identified a session token replay vulnerability affecting Okta Verify push notifications. Patch available for Okta Identity Engine.",
    fullContent:
      "Under specific conditions, an attacker with network access could replay Okta Verify push notification session tokens. Okta recommends enabling Number Challenge for all users and updating to the latest Okta Verify mobile app version.",
  },
  {
    id: "tf6",
    title: "Salesforce API Rate Limiting Changes",
    vendor: "Salesforce",
    severity: "Low",
    published: "2026-03-13T14:00:00Z",
    summary:
      "Salesforce will implement stricter API rate limiting on Connected App integrations starting April 2026. Third-party integrations may need configuration updates.",
    fullContent:
      "Starting April 15, 2026, Salesforce will reduce default API rate limits for Connected Apps from 100,000 to 50,000 daily calls. Organizations with third-party integrations should audit API usage and request limit increases where necessary.",
  },
];

export const chatConversations: ChatConversation[] = [
  {
    id: "conv-1",
    title: "Microsoft vulnerability analysis",
    updatedAt: "2026-03-18T15:00:00Z",
    messages: [
      {
        id: "m1",
        role: "user",
        content: "Does Microsoft have critical vulnerabilities?",
        timestamp: "2026-03-18T14:50:00Z",
      },
      {
        id: "m2",
        role: "assistant",
        content:
          "Yes, Microsoft currently has 5 active critical CVEs affecting your monitored customer base. The most severe is CVE-2026-1234 (CVSS 9.8) — an Exchange Server RCE vulnerability actively exploited in the wild. This affects 38 of your monitored customers, with Acme Financial Corp at highest risk. I recommend prioritizing patch deployment for Exchange Server 2019 instances.",
        timestamp: "2026-03-18T14:50:05Z",
      },
    ],
  },
  {
    id: "conv-2",
    title: "CVE-2026-1234 summary",
    updatedAt: "2026-03-17T11:30:00Z",
    messages: [
      {
        id: "m3",
        role: "user",
        content: "Summarize CVE-2026-1234",
        timestamp: "2026-03-17T11:25:00Z",
      },
      {
        id: "m4",
        role: "assistant",
        content:
          "CVE-2026-1234 is a critical remote code execution vulnerability in Microsoft Exchange Server with a CVSS score of 9.8. It allows unauthenticated attackers to execute arbitrary code via crafted HTTP requests to the EWS endpoint. MITRE ATT&CK mapping: Initial Access (T1190). Published: March 18, 2026. Status: Actively exploited. Affected versions: Exchange Server 2016, 2019, SE.",
        timestamp: "2026-03-17T11:25:08Z",
      },
    ],
  },
  {
    id: "conv-3",
    title: "Cisco threat overview",
    updatedAt: "2026-03-16T09:00:00Z",
    messages: [
      {
        id: "m5",
        role: "user",
        content: "Show latest Cisco threats",
        timestamp: "2026-03-16T08:55:00Z",
      },
      {
        id: "m6",
        role: "assistant",
        content:
          "Latest Cisco threats in your environment:\n\n1. CVE-2026-0891 — IOS XE Web UI Privilege Escalation (Critical, CVSS 9.1) — Active investigation for GlobalTech Industries\n2. CVE-2026-0334 — AnyConnect VPN Information Disclosure (Medium, CVSS 5.9) — Closed for LogiTrans Shipping\n\nCisco's overall risk score across your portfolio is 82/100 with 3 active critical CVEs.",
        timestamp: "2026-03-16T08:55:06Z",
      },
    ],
  },
];

export const aiPlaceholderResponses: Record<string, string> = {
  "Does Microsoft have critical vulnerabilities?":
    "Yes, Microsoft currently has 5 active critical CVEs in your monitored environment. The highest priority is CVE-2026-1234 (Exchange Server RCE, CVSS 9.8) which is being actively exploited. 38 customers are potentially affected. Immediate patching is recommended.",
  "Summarize CVE-2026-1234":
    "CVE-2026-1234 is a critical RCE in Microsoft Exchange Server (CVSS 9.8). Unauthenticated attackers can execute code via crafted HTTP requests. MITRE: Initial Access (T1190). Affects Exchange 2016, 2019, and SE. Patch: KB5034765.",
  "Generate mitigation steps":
    "Recommended mitigation steps:\n\n1. Apply vendor security patches within 24 hours for critical CVEs\n2. Enable enhanced logging on affected endpoints\n3. Implement network segmentation for unpatched systems\n4. Review authentication logs for the past 72 hours\n5. Notify affected customer SOC teams\n6. Document remediation in compliance tracking system",
  "Show latest Cisco threats":
    "Latest Cisco threats:\n\n• CVE-2026-0891 — IOS XE Privilege Escalation (Critical, 9.1) — Investigating\n• CVE-2026-0334 — AnyConnect Info Disclosure (Medium, 5.9) — Closed\n\nRisk score: 82/100 | Active critical CVEs: 3 | Last incident: March 17, 2026",
};

export const reportOptions: ReportOption[] = [
  {
    id: "r1",
    title: "Generate Executive Report",
    description:
      "Comprehensive executive summary with risk trends, top threats, and remediation status across all customers.",
    icon: "FileText",
    format: "PDF",
  },
  {
    id: "r2",
    title: "Generate PDF",
    description:
      "Detailed technical report including CVE details, affected assets, and MITRE ATT&CK mappings.",
    icon: "FileDown",
    format: "PDF",
  },
  {
    id: "r3",
    title: "Generate Excel",
    description:
      "Exportable spreadsheet with all alerts, vendor scores, and customer risk metrics for further analysis.",
    icon: "Sheet",
    format: "XLSX",
  },
  {
    id: "r4",
    title: "Weekly Summary",
    description:
      "Automated weekly digest of new threats, resolved alerts, and vendor posture changes.",
    icon: "Calendar",
    format: "PDF",
  },
  {
    id: "r5",
    title: "Monthly Summary",
    description:
      "Monthly compliance and risk posture report for stakeholder review and audit purposes.",
    icon: "BarChart3",
    format: "PDF",
  },
];

export const settingsSections: SettingsSection[] = [
  {
    id: "general",
    title: "General",
    description: "Organization name, timezone, and default dashboard preferences.",
    icon: "Settings",
  },
  {
    id: "notifications",
    title: "Notifications",
    description: "Alert thresholds, email notifications, and escalation rules.",
    icon: "Bell",
  },
  {
    id: "ai-model",
    title: "AI Model",
    description: "Configure AI assistant model, response style, and data sources.",
    icon: "Bot",
  },
  {
    id: "theme",
    title: "Theme",
    description: "Appearance settings, color scheme, and display density.",
    icon: "Palette",
  },
  {
    id: "integrations",
    title: "Integrations",
    description: "Connect SIEM, ticketing, and threat intelligence platforms.",
    icon: "Plug",
  },
  {
    id: "api-keys",
    title: "API Keys",
    description: "Manage API keys for external integrations and automation.",
    icon: "Key",
  },
];

export const suggestedPrompts = [
  "Does Microsoft have critical vulnerabilities?",
  "Summarize CVE-2026-1234",
  "Generate mitigation steps",
  "Show latest Cisco threats",
];
