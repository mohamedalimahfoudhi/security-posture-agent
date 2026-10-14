"""
Comprehensive technology pattern database for regex-based extraction.

This module provides a structured knowledge base of technology detection
patterns used as the primary extraction method in the hybrid pipeline.
Regex extraction is fast, deterministic, and can detect 100+ technologies
from a document, unlike relying solely on a small AI model.

Every entry follows the same schema so the extractor can iterate uniformly:

    {
        "name":       canonical technology name (used as the asset technology)
        "vendor":     company/organization that develops it
        "category":   one of the KNOWN_CATEGORIES below
        "patterns":   list of case-insensitive regex patterns to match
        "version_re": optional regex with a single capture group for version
        "aliases":    list of alias strings for normalization/dedup
    }

CATEGORIES (controlled vocabulary aligned with the assets table columns):
    operating_system, web_server, database, cloud_provider, security_tools,
    container, devops, monitoring, network_devices, framework,
    programming_language
"""

from typing import Dict, List

# ---------------------------------------------------------------------------
# Controlled vocabulary
# ---------------------------------------------------------------------------

KNOWN_CATEGORIES = [
    "operating_system",
    "web_server",
    "database",
    "cloud_provider",
    "security_tools",
    "container",
    "devops",
    "monitoring",
    "network_devices",
    "framework",
    "programming_language",
]

# ---------------------------------------------------------------------------
# Technology pattern definitions
# ---------------------------------------------------------------------------

TECHNOLOGY_PATTERNS: List[Dict] = [
    # ============================ OPERATING SYSTEMS ============================
    {
        "name": "Windows Server",
        "vendor": "Microsoft Corporation",
        "category": "operating_system",
        "patterns": [
            r"windows\s*server\s*\d{4}",
            r"windows\s*server",
        ],
        "version_re": r"windows\s*server\s*(\d{4})",
        "aliases": ["windows server", "win server", "microsoft windows server", "windows server r2"],
    },
    {
        "name": "Windows Desktop",
        "vendor": "Microsoft Corporation",
        "category": "operating_system",
        "patterns": [
            r"windows\s*\d{1,2}",
            r"windows\s*(?:10|11|8|7|xp|vista)",
        ],
        "version_re": r"windows\s*(\d{1,2})",
        "aliases": ["windows", "microsoft windows"],
    },
    {
        "name": "Ubuntu",
        "vendor": "Canonical",
        "category": "operating_system",
        "patterns": [
            r"ubuntu(?:\s+server)?\s+\d{2}\.\d{2}(?:\s*\.\d+)?",
            r"ubuntu\s+[0-9]{2}\.[0-9]{2}",
            r"\bubuntu\s*lts\b",
        ],
        "version_re": r"ubuntu[^\d]*(\d{2}\.\d{2}(?:\.\d+)?)",
        "aliases": ["ubuntu", "ubuntu server", "canonical ubuntu", "ubuntu lts"],
    },
    {
        "name": "Debian",
        "vendor": "Debian Project",
        "category": "operating_system",
        "patterns": [
            r"debian\s+\d+(?:\.\d+)?",
            r"debian\b",
        ],
        "version_re": r"debian\s+(\d+(?:\.\d+)?)",
        "aliases": ["debian", "debian linux"],
    },
    {
        "name": "Red Hat Enterprise Linux",
        "vendor": "Red Hat",
        "category": "operating_system",
        "patterns": [
            r"(?:red\s*hat\s*enterprise\s*linux|rhel)\s*\d+(?:\.\d+)?",
            r"red\s*hat\s*enterprise\s*linux",
            r"rhel\b",
        ],
        "version_re": r"(?:red\s*hat\s*enterprise\s*linux|rhel)\s*(\d+(?:\.\d+)?)",
        "aliases": ["rhel", "red hat enterprise linux", "red hat linux"],
    },
    {
        "name": "CentOS",
        "vendor": "Red Hat",
        "category": "operating_system",
        "patterns": [
            r"centos\s*\d+(?:\s*stream)?",
            r"centos\b",
        ],
        "version_re": r"centos\s*(\d+(?:\.\d+)?)",
        "aliases": ["centos", "centos stream"],
    },
    {
        "name": "Rocky Linux",
        "vendor": "Rocky Enterprise Software Foundation",
        "category": "operating_system",
        "patterns": [
            r"rocky\s*linux\s*\d+(?:\.\d+)?",
            r"rocky\s*linux",
        ],
        "version_re": r"rocky\s*linux\s*(\d+(?:\.\d+)?)",
        "aliases": ["rocky linux", "rocky"],
    },
    {
        "name": "AlmaLinux",
        "vendor": "AlmaLinux OS Foundation",
        "category": "operating_system",
        "patterns": [
            r"alma\s*linux\s*\d+(?:\.\d+)?",
            r"alma\s*linux",
        ],
        "version_re": r"alma\s*linux\s*(\d+(?:\.\d+)?)",
        "aliases": ["almalinux", "alma linux"],
    },
    {
        "name": "SUSE Linux",
        "vendor": "SUSE",
        "category": "operating_system",
        "patterns": [
            r"suse\s*linux\s*enterprise\s*server",
            r"sles\b",
            r"opensuse\b",
            r"suse\b",
        ],
        "version_re": r"suse[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["suse", "sles", "suse linux enterprise", "opensuse"],
    },
    {
        "name": "Oracle Linux",
        "vendor": "Oracle Corporation",
        "category": "operating_system",
        "patterns": [
            r"oracle\s*linux\s*\d+(?:\.\d+)?",
            r"oracle\s*linux",
        ],
        "version_re": r"oracle\s*linux\s*(\d+(?:\.\d+)?)",
        "aliases": ["oracle linux", "oel"],
    },
    {
        "name": "Fedora",
        "vendor": "Red Hat",
        "category": "operating_system",
        "patterns": [
            r"fedora\s*\d+(?:\.\d+)?",
            r"fedora\b",
        ],
        "version_re": r"fedora\s*(\d+(?:\.\d+)?)",
        "aliases": ["fedora", "fedora linux"],
    },
    {
        "name": "FreeBSD",
        "vendor": "FreeBSD Foundation",
        "category": "operating_system",
        "patterns": [
            r"freebsd\s*\d+(?:\.\d+)?",
            r"freebsd\b",
        ],
        "version_re": r"freebsd\s*(\d+(?:\.\d+)?)",
        "aliases": ["freebsd"],
    },
    {
        "name": "Solaris",
        "vendor": "Oracle Corporation",
        "category": "operating_system",
        "patterns": [
            r"solaris\s*\d+(?:\.\d+)?",
            r"solaris\b",
        ],
        "version_re": r"solaris\s*(\d+(?:\.\d+)?)",
        "aliases": ["solaris", "oracle solaris", "sun solaris"],
    },
    {
        "name": "AIX",
        "vendor": "IBM",
        "category": "operating_system",
        "patterns": [
            r"\baix\s*\d+(?:\.\d+)?",
            r"\baix\b",
        ],
        "version_re": r"\baix\s*(\d+(?:\.\d+)?)",
        "aliases": ["aix", "ibm aix"],
    },
    {
        "name": "macOS",
        "vendor": "Apple Inc.",
        "category": "operating_system",
        "patterns": [
            r"mac\s*os\s*x?\s*\d+",
            r"macos\s*\d+",
            r"mac\s*os",
            r"macos",
        ],
        "version_re": r"(?:mac\s*os\s*x?|macos)\s*(\d+(?:\.\d+)*)",
        "aliases": ["macos", "mac os", "mac os x", "os x"],
    },
    {
        "name": "Android",
        "vendor": "Google LLC",
        "category": "operating_system",
        "patterns": [
            r"android\s*\d+(?:\.\d+)?",
            r"android\b",
        ],
        "version_re": r"android\s*(\d+(?:\.\d+)?)",
        "aliases": ["android", "android os"],
    },
    {
        "name": "iOS",
        "vendor": "Apple Inc.",
        "category": "operating_system",
        "patterns": [
            r"\bios\s*(?:version\s*)?\d+(?:\.\d+)*\b",
            r"apple\s*ios",
            r"\bios\s+device\b",
        ],
        "version_re": r"\bios[^\d]*(\d+(?:\.\d+)*)\b",
        "aliases": ["ios", "apple ios"],
    },
    {
        "name": "Linux",
        "vendor": "Various (see specific distro)",
        "category": "operating_system",
        "patterns": [
            r"\blinux\s*(?:kernel)?\s*\d+\.\d+",
            r"\blinux\b",
        ],
        "version_re": r"linux[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["linux", "linux os", "linux kernel"],
    },

    # ============================ WEB SERVERS ============================
    {
        "name": "Apache HTTP Server",
        "vendor": "Apache Software Foundation",
        "category": "web_server",
        "patterns": [
            r"apache\s*http\s*server\s*\d+\.\d+\.\d+",
            r"apache\s*http\s*server",
            r"apache\s*/\s*\d+\.\d+\.\d+",
            r"httpd\s*\d+\.\d+\.\d+",
            r"\bapache\s*httpd\b",
        ],
        "version_re": r"apache[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["apache", "apache http server", "apache httpd", "httpd"],
    },
    {
        "name": "Nginx",
        "vendor": "F5 Networks (formerly NGINX Inc)",
        "category": "web_server",
        "patterns": [
            r"nginx\s*\d+\.\d+\.\d+",
            r"nginx\s*\d+\.\d+",
            r"\bnginx\b",
        ],
        "version_re": r"nginx[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["nginx", "nginx web server", "nginx reverse proxy"],
    },
    {
        "name": "Microsoft IIS",
        "vendor": "Microsoft Corporation",
        "category": "web_server",
        "patterns": [
            r"iis\s*\d+(?:\.\d+)?",
            r"internet\s*information\s*services",
            r"\biis\b",
        ],
        "version_re": r"iis\s*(\d+(?:\.\d+)?)",
        "aliases": ["iis", "internet information services", "microsoft iis"],
    },
    {
        "name": "Apache Tomcat",
        "vendor": "Apache Software Foundation",
        "category": "framework",
        "patterns": [
            r"apache\s*tomcat\s*\d+\.\d+\.\d+",
            r"apache\s*tomcat",
            r"\btomcat\s*\d+\.\d+",
            r"\btomcat\b",
        ],
        "version_re": r"tomcat[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["tomcat", "apache tomcat", "catalina"],
    },
    {
        "name": "Caddy",
        "vendor": "Caddy (Spencer & The Caddy Team)",
        "category": "web_server",
        "patterns": [
            r"caddy\s*server\s*\d+(?:\.\d+)*",
            r"\bcaddy\b",
        ],
        "version_re": r"\bcaddy\s*(\d+(?:\.\d+)*)",
        "aliases": ["caddy", "caddy server"],
    },
    {
        "name": "LiteSpeed",
        "vendor": "LiteSpeed Technologies",
        "category": "web_server",
        "patterns": [
            r"litespeed\s*(?:web\s*server)?\s*\d+(?:\.\d+)*",
            r"litespeed\b",
        ],
        "version_re": r"litespeed[^\d]*(\d+(?:\.\d+)*)",
        "aliases": ["litespeed", "litespeed web server", "ls ws"],
    },
    {
        "name": "HAProxy",
        "vendor": "HAProxy Technologies",
        "category": "web_server",
        "patterns": [
            r"haproxy\s*\d+\.\d+\.\d+",
            r"haproxy\s*\d+\.\d+",
            r"\bhaproxy\b",
        ],
        "version_re": r"haproxy[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["haproxy", "haproxy load balancer"],
    },
    {
        "name": "Node.js",
        "vendor": "OpenJS Foundation",
        "category": "framework",
        "patterns": [
            r"node\.?js\s*(?:runtime)?\s*\d+(?:\.\d+)*",
            r"\bnode\.?js\b",
        ],
        "version_re": r"node\.?js[^\d]*(\d+(?:\.\d+)*)",
        "aliases": ["node.js", "nodejs", "node js", "node.js runtime"],
    },

    # ============================ DATABASES ============================
    {
        "name": "MySQL",
        "vendor": "Oracle Corporation",
        "category": "database",
        "patterns": [
            r"mysql\s*\d+\.\d+\.\d+",
            r"mysql\s*\d+\.\d+",
            r"\bmysql\b",
        ],
        "version_re": r"mysql[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["mysql", "mysql server"],
    },
    {
        "name": "PostgreSQL",
        "vendor": "PostgreSQL Global Development Group",
        "category": "database",
        "patterns": [
            r"postgres(?:ql)?\s*\d+\.\d+(?:\.\d+)?",
            r"postgres(?:ql)?\b",
        ],
        "version_re": r"postgres(?:ql)?[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["postgresql", "postgres", "pg"],
    },
    {
        "name": "MariaDB",
        "vendor": "MariaDB Foundation",
        "category": "database",
        "patterns": [
            r"mariadb\s*\d+\.\d+\.\d+",
            r"mariadb\s*\d+\.\d+",
            r"\bmariadb\b",
        ],
        "version_re": r"mariadb[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["mariadb", "mariadb server"],
    },
    {
        "name": "MongoDB",
        "vendor": "MongoDB Inc",
        "category": "database",
        "patterns": [
            r"mongo(?:db)?\s*\d+\.\d+(?:\.\d+)?",
            r"\bmongodb\b",
        ],
        "version_re": r"mongodb[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["mongodb", "mongo"],
    },
    {
        "name": "Microsoft SQL Server",
        "vendor": "Microsoft Corporation",
        "category": "database",
        "patterns": [
            r"microsoft\s*sql\s*server\s*\d{4}",
            r"sql\s*server\s*\d{4}",
            r"mssql\s*\d+(?:\.\d+)?",
            r"\bmssql\b",
        ],
        "version_re": r"(?:microsoft\s*)?sql\s*server\s*(\d{4})",
        "aliases": ["mssql", "sql server", "microsoft sql server"],
    },
    {
        "name": "Oracle Database",
        "vendor": "Oracle Corporation",
        "category": "database",
        "patterns": [
            r"oracle\s*(?:database)?\s*\d+(?:[cg]|\.\d+)*",
            r"oracle\s*db",
            r"oracle\s*database",
        ],
        "version_re": r"oracle[^\d]*(\d+(?:[cg]|\.\d+)*)",
        "aliases": ["oracle", "oracle database", "oracle db", "rdbms"],
    },
    {
        "name": "Redis",
        "vendor": "Redis Ltd",
        "category": "database",
        "patterns": [
            r"redis\s*\d+\.\d+\.\d+",
            r"redis\s*\d+\.\d+",
            r"\bredis\b",
        ],
        "version_re": r"redis[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["redis", "redis cache"],
    },
    {
        "name": "Elasticsearch",
        "vendor": "Elastic",
        "category": "database",
        "patterns": [
            r"elasticsearch\s*\d+\.\d+\.\d+",
            r"elasticsearch\s*\d+\.\d+",
            r"\belasticsearch\b",
        ],
        "version_re": r"elasticsearch[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["elasticsearch", "es", "elastic search"],
    },
    {
        "name": "Cassandra",
        "vendor": "Apache Software Foundation",
        "category": "database",
        "patterns": [
            r"cassandra\s*\d+\.\d+",
            r"\bcassandra\b",
        ],
        "version_re": r"cassandra[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["cassandra", "apache cassandra"],
    },
    {
        "name": "Couchbase",
        "vendor": "Couchbase Inc",
        "category": "database",
        "patterns": [
            r"couchbase\s*\d+\.\d+",
            r"\bcouchbase\b",
        ],
        "version_re": r"couchbase[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["couchbase", "couchbase server"],
    },
    {
        "name": "SQLite",
        "vendor": "SQLite Consortium (public domain)",
        "category": "database",
        "patterns": [
            r"sqlite\s*\d+\.\d+",
            r"\bsqlite\b",
        ],
        "version_re": r"sqlite[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["sqlite", "sqlite database"],
    },
    {
        "name": "Neo4j",
        "vendor": "Neo4j Inc",
        "category": "database",
        "patterns": [
            r"neo4j\s*\d+\.\d+",
            r"\bneo4j\b",
        ],
        "version_re": r"neo4j[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["neo4j", "neo4j graph database"],
    },
    {
        "name": "InfluxDB",
        "vendor": "InfluxData",
        "category": "database",
        "patterns": [
            r"influx(?:db)?\s*\d+\.\d+",
            r"\binfluxdb\b",
        ],
        "version_re": r"influxdb[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["influxdb", "influx"],
    },
    {
        "name": "ClickHouse",
        "vendor": "ClickHouse Inc",
        "category": "database",
        "patterns": [
            r"clickhouse\s*\d+\.\d+",
            r"\bclickhouse\b",
        ],
        "version_re": r"clickhouse[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["clickhouse", "click house"],
    },
    {
        "name": "Amazon DynamoDB",
        "vendor": "Amazon Web Services",
        "category": "database",
        "patterns": [
            r"amazon\s*dynamo\s*db",
            r"dynamo\s*db",
            r"\bdynamodb\b",
        ],
        "version_re": None,
        "aliases": ["dynamodb", "dynamo db", "amazon dynamodb"],
    },

    # ============================ CLOUD PROVIDERS ============================
    {
        "name": "Amazon Web Services",
        "vendor": "Amazon Web Services",
        "category": "cloud_provider",
        "patterns": [
            r"amazon\s*web\s*services",
            r"\baws\b",
            r"amazon\s*ec2",
            r"amazon\s*s3",
            r"s3\s*bucket",
        ],
        "version_re": None,
        "aliases": ["aws", "amazon web services", "amazon", "ec2", "s3", "amazon ec2", "amazon s3"],
    },
    {
        "name": "Microsoft Azure",
        "vendor": "Microsoft Corporation",
        "category": "cloud_provider",
        "patterns": [
            r"microsoft\s*azure",
            r"\bazure\b",
            r"azure\s*(?:ad|app\s*service|functions|vms)",
        ],
        "version_re": None,
        "aliases": ["azure", "microsoft azure", "azure cloud"],
    },
    {
        "name": "Google Cloud Platform",
        "vendor": "Google LLC",
        "category": "cloud_provider",
        "patterns": [
            r"google\s*cloud\s*platform",
            r"google\s*cloud",
            r"\bgcp\b",
            r"google\s*compute\s*engine",
        ],
        "version_re": None,
        "aliases": ["gcp", "google cloud", "google cloud platform", "gce"],
    },
    {
        "name": "IBM Cloud",
        "vendor": "IBM",
        "category": "cloud_provider",
        "patterns": [
            r"ibm\s*cloud",
            r"ibm\s*cloud\s*foundry",
        ],
        "version_re": None,
        "aliases": ["ibm cloud", "ibm bluemix"],
    },
    {
        "name": "Oracle Cloud Infrastructure",
        "vendor": "Oracle Corporation",
        "category": "cloud_provider",
        "patterns": [
            r"oracle\s*cloud\s*infrastructure",
            r"\boci\b",
        ],
        "version_re": None,
        "aliases": ["oci", "oracle cloud infrastructure"],
    },
    {
        "name": "Alibaba Cloud",
        "vendor": "Alibaba Group",
        "category": "cloud_provider",
        "patterns": [
            r"alibaba\s*cloud",
            r"aliyun\b",
        ],
        "version_re": None,
        "aliases": ["alibaba cloud", "aliyun", "alicloud"],
    },
    {
        "name": "VMware Cloud",
        "vendor": "VMware Inc",
        "category": "cloud_provider",
        "patterns": [
            r"vmware\s*cloud",
            r"vmware\s*on\s*aws",
        ],
        "version_re": None,
        "aliases": ["vmware cloud", "vmware on aws"],
    },
    {
        "name": "Salesforce",
        "vendor": "Salesforce Inc",
        "category": "cloud_provider",
        "patterns": [
            r"salesforce\s*(?:cloud)?\s*\d+",
            r"\bsalesforce\b",
        ],
        "version_re": r"salesforce\s*(\d+)",
        "aliases": ["salesforce", "salesforce cloud", "sfdc"],
    },
    {
        "name": "Heroku",
        "vendor": "Salesforce Inc",
        "category": "cloud_provider",
        "patterns": [
            r"\bheroku\b",
        ],
        "version_re": None,
        "aliases": ["heroku", "heroku cloud"],
    },
    {
        "name": "DigitalOcean",
        "vendor": "DigitalOcean Inc",
        "category": "cloud_provider",
        "patterns": [
            r"digital\s*ocean",
            r"\bdigitalocean\b",
        ],
        "version_re": None,
        "aliases": ["digitalocean", "digital ocean"],
    },

    # ============================ CONTAINERS ============================
    {
        "name": "Docker",
        "vendor": "Docker Inc",
        "category": "container",
        "patterns": [
            r"docker\s*(?:engine)?\s*\d+(?:\.\d+)*",
            r"\bdocker\b",
            r"docker\s*compose",
        ],
        "version_re": r"docker[^\d]*(\d+(?:\.\d+)*)",
        "aliases": ["docker", "docker engine", "docker container"],
    },
    {
        "name": "Kubernetes",
        "vendor": "Cloud Native Computing Foundation",
        "category": "container",
        "patterns": [
            r"kubernetes\s*v?\d+\.\d+\.\d+",
            r"kubernetes\s*v?\d+\.\d+",
            r"\bk8s\b",
            r"\bkubernetes\b",
        ],
        "version_re": r"kubernetes\s*v?(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["kubernetes", "k8s", "kube"],
    },
    {
        "name": "OpenShift",
        "vendor": "Red Hat",
        "category": "container",
        "patterns": [
            r"openshift\s*\d+\.\d+",
            r"\bopenshift\b",
        ],
        "version_re": r"openshift[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["openshift", "red hat openshift", "ocp"],
    },
    {
        "name": "Rancher",
        "vendor": "Rancher (SUSE)",
        "category": "container",
        "patterns": [
            r"rancher\s*(?:kubernetes)?\s*\d+\.\d+",
            r"\brancher\b",
        ],
        "version_re": r"rancher[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["rancher", "rancher kubernetes"],
    },
    {
        "name": "Podman",
        "vendor": "Red Hat (Containers)",
        "category": "container",
        "patterns": [
            r"podman\s*\d+\.\d+",
            r"\bpodman\b",
        ],
        "version_re": r"podman[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["podman", "podman container"],
    },
    {
        "name": "containerd",
        "vendor": "Cloud Native Computing Foundation",
        "category": "container",
        "patterns": [
            r"containerd\s*v?\d+\.\d+",
            r"\bcontainerd\b",
        ],
        "version_re": r"containerd\s*v?(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["containerd", "container runtime"],
    },
    {
        "name": "Helm",
        "vendor": "Cloud Native Computing Foundation",
        "category": "container",
        "patterns": [
            r"helm\s*v?\d+\.\d+",
            r"\bhelm\b",
        ],
        "version_re": r"helm\s*v?(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["helm", "helm charts"],
    },
    {
        "name": "Docker Swarm",
        "vendor": "Docker Inc",
        "category": "container",
        "patterns": [
            r"docker\s*swarm",
        ],
        "version_re": None,
        "aliases": ["docker swarm", "swarm mode"],
    },
    {
        "name": "Istio",
        "vendor": "Cloud Native Computing Foundation",
        "category": "container",
        "patterns": [
            r"istio\s*v?\d+\.\d+",
            r"\bistio\b",
        ],
        "version_re": r"istio\s*v?(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["istio", "istio service mesh"],
    },
    {
        "name": "LXC",
        "vendor": "Linux Containers Project",
        "category": "container",
        "patterns": [
            r"\blxc\b",
            r"lxd\b",
        ],
        "version_re": None,
        "aliases": ["lxc", "linux container", "lxd"],
    },

    # ============================ DEVOPS / CI-CD ============================
    {
        "name": "Jenkins",
        "vendor": "CloudBees / Jenkins Project",
        "category": "devops",
        "patterns": [
            r"jenkins\s*\d+\.\d+",
            r"\bjenkins\b",
        ],
        "version_re": r"jenkins[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["jenkins", "jenkins ci", "jenkins server"],
    },
    {
        "name": "GitLab CI/CD",
        "vendor": "GitLab Inc",
        "category": "devops",
        "patterns": [
            r"gitlab\s*(?:ci|cd|pipelines)\s*\d+\.\d+",
            r"gitlab\s*(?:ci|cd|pipelines)",
            r"gitlab\s*ci\s*/?\s*cd",
        ],
        "version_re": r"gitlab[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["gitlab ci", "gitlab cicd", "gitlab pipelines", "gitlab ci/cd"],
    },
    {
        "name": "GitHub Actions",
        "vendor": "GitHub (Microsoft)",
        "category": "devops",
        "patterns": [
            r"github\s*actions",
            r"\bgh\s*actions\b",
            r"github\s*workflows",
        ],
        "version_re": None,
        "aliases": ["github actions", "gh actions"],
    },
    {
        "name": "Bitbucket",
        "vendor": "Atlassian",
        "category": "devops",
        "patterns": [
            r"bitbucket\s*(?:pipelines)?\s*\d+(?:\.\d+)?",
            r"\bbitbucket\b",
        ],
        "version_re": r"bitbucket[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["bitbucket", "bitbucket pipelines"],
    },
    {
        "name": "Ansible",
        "vendor": "Red Hat",
        "category": "devops",
        "patterns": [
            r"ansible\s*(?:tower|automation\s*platform)?\s*\d+\.\d+",
            r"\bansible\b",
        ],
        "version_re": r"ansible[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["ansible", "ansible tower", "ansible automation platform"],
    },
    {
        "name": "Chef",
        "vendor": "Progress Software",
        "category": "devops",
        "patterns": [
            r"chef\s*(?:automate)?\s*\d+\.\d+",
            r"\bchef\b",
        ],
        "version_re": r"chef[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["chef", "chef automate", "chef infra"],
    },
    {
        "name": "Puppet",
        "vendor": "Puppet Inc",
        "category": "devops",
        "patterns": [
            r"puppet\s*(?:enterprise)?\s*\d+\.\d+",
            r"\bpuppet\b",
        ],
        "version_re": r"puppet[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["puppet", "puppet enterprise"],
    },
    {
        "name": "Terraform",
        "vendor": "HashiCorp",
        "category": "devops",
        "patterns": [
            r"terraform\s*v?\d+\.\d+",
            r"\bterraform\b",
        ],
        "version_re": r"terraform\s*v?(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["terraform", "hashicorp terraform", "terraform cloud"],
    },
    {
        "name": "CircleCI",
        "vendor": "CircleCI",
        "category": "devops",
        "patterns": [
            r"circleci\s*v?\d+\.\d+",
            r"\bcircleci\b",
        ],
        "version_re": r"circleci\s*v?(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["circleci", "circle ci"],
    },
    {
        "name": "Azure DevOps",
        "vendor": "Microsoft Corporation",
        "category": "devops",
        "patterns": [
            r"azure\s*dev\s*ops",
            r"\bazure\s*pipelines\b",
            r"\btfs\b",
        ],
        "version_re": None,
        "aliases": ["azure devops", "azure pipelines", "vsts", "tfs"],
    },
    {
        "name": "ArgoCD",
        "vendor": "Cloud Native Computing Foundation",
        "category": "devops",
        "patterns": [
            r"argo\s*cd\s*v?\d+\.\d+",
            r"\bargocd\b",
            r"\bargo\s*cd\b",
        ],
        "version_re": r"argo\s*cd\s*v?(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["argocd", "argo cd"],
    },
    {
        "name": "SonarQube",
        "vendor": "SonarSource",
        "category": "devops",
        "patterns": [
            r"sonarqube\s*\d+\.\d+",
            r"\bsonarqube\b",
        ],
        "version_re": r"sonarqube[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["sonarqube", "sonar cube"],
    },
    {
        "name": "Vagrant",
        "vendor": "HashiCorp",
        "category": "devops",
        "patterns": [
            r"vagrant\s*\d+\.\d+",
            r"\bvagrant\b",
        ],
        "version_re": r"vagrant[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["vagrant", "hashicorp vagrant"],
    },

    # ============================ MONITORING ============================
    {
        "name": "Prometheus",
        "vendor": "Cloud Native Computing Foundation",
        "category": "monitoring",
        "patterns": [
            r"prometheus\s*v?\d+\.\d+",
            r"\bprometheus\b",
        ],
        "version_re": r"prometheus\s*v?(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["prometheus", "prometheus monitoring"],
    },
    {
        "name": "Grafana",
        "vendor": "Grafana Labs",
        "category": "monitoring",
        "patterns": [
            r"grafana\s*\d+\.\d+",
            r"\bgrafana\b",
        ],
        "version_re": r"grafana[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["grafana", "grafana dashboard"],
    },
    {
        "name": "Nagios",
        "vendor": "Nagios Enterprises",
        "category": "monitoring",
        "patterns": [
            r"nagios\s*(?:core|xi)?\s*\d+\.\d+",
            r"\bnagios\b",
        ],
        "version_re": r"nagios[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["nagios", "nagios core", "nagios xi"],
    },
    {
        "name": "Zabbix",
        "vendor": "Zabbix SIA",
        "category": "monitoring",
        "patterns": [
            r"zabbix\s*\d+\.\d+",
            r"\bzabbix\b",
        ],
        "version_re": r"zabbix[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["zabbix", "zabbix server"],
    },
    {
        "name": "Datadog",
        "vendor": "Datadog Inc",
        "category": "monitoring",
        "patterns": [
            r"datadog\s*\d+(?:\.\d+)?",
            r"\bdatadog\b",
        ],
        "version_re": r"datadog[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["datadog", "datadog agent"],
    },
    {
        "name": "New Relic",
        "vendor": "New Relic Inc",
        "category": "monitoring",
        "patterns": [
            r"new\s*relic\s*\d+(?:\.\d+)?",
            r"\bnew\s*relic\b",
        ],
        "version_re": r"new\s*relic[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["new relic", "newrelic"],
    },
    {
        "name": "Dynatrace",
        "vendor": "Dynatrace Inc",
        "category": "monitoring",
        "patterns": [
            r"dynatrace\s*\d+(?:\.\d+)?",
            r"\bdynatrace\b",
        ],
        "version_re": r"dynatrace[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["dynatrace", "dynatrace agent"],
    },
    {
        "name": "Kibana",
        "vendor": "Elastic",
        "category": "monitoring",
        "patterns": [
            r"kibana\s*\d+\.\d+",
            r"\bkibana\b",
        ],
        "version_re": r"kibana[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["kibana", "kibana dashboard"],
    },
    {
        "name": "ELK Stack",
        "vendor": "Elastic",
        "category": "monitoring",
        "patterns": [
            r"elk\s*stack",
            r"elastic\s*stack",
            r"\belk\b",
        ],
        "version_re": None,
        "aliases": ["elk", "elastic stack", "elk stack"],
    },
    {
        "name": "SolarWinds",
        "vendor": "SolarWinds Inc",
        "category": "monitoring",
        "patterns": [
            r"solarwinds\s*\d+(?:\.\d+)?",
            r"\bsolarwinds\b",
        ],
        "version_re": r"solarwinds[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["solarwinds", "solarwinds observability"],
    },
    {
        "name": "PRTG",
        "vendor": "Paessler AG",
        "category": "monitoring",
        "patterns": [
            r"prtg\s*(?:network\s*monitor)?\s*\d+",
            r"\bprtg\b",
        ],
        "version_re": r"prtg[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["prtg", "prtg network monitor"],
    },
    {
        "name": "AppDynamics",
        "vendor": "Cisco Systems",
        "category": "monitoring",
        "patterns": [
            r"appdynamics\s*\d+(?:\.\d+)?",
            r"\bappdynamics\b",
        ],
        "version_re": r"appdynamics[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["appdynamics", "app dynamics"],
    },
    {
        "name": "PagerDuty",
        "vendor": "PagerDuty Inc",
        "category": "monitoring",
        "patterns": [
            r"pager\s*duty\s*\d+",
            r"\bpagerduty\b",
        ],
        "version_re": r"pagerduty[^\d]*(\d+)",
        "aliases": ["pagerduty", "pager duty"],
    },
    {
        "name": "Splunk",
        "vendor": "Splunk Inc",
        "category": "monitoring",
        "patterns": [
            r"splunk\s*(?:enterprise)?\s*\d+\.\d+",
            r"\bsplunk\b",
        ],
        "version_re": r"splunk[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["splunk", "splunk enterprise", "splunk cloud"],
    },

    # ============================ SECURITY TOOLS ============================
    {
        "name": "Palo Alto Networks",
        "vendor": "Palo Alto Networks",
        "category": "security_tools",
        "patterns": [
            r"palo\s*alto\s*networks",
            r"palo\s*alto\s*(?:firewall|pan-os|panos)",
            r"\bpan-os\b",
            r"\bpalo\s*alto\b",
        ],
        "version_re": r"pan[-\s]?os[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["palo alto", "pan-os", "palo alto networks", "panos"],
    },
    {
        "name": "Cisco ASA",
        "vendor": "Cisco Systems",
        "category": "security_tools",
        "patterns": [
            r"cisco\s*asa\s*\d+(?:\.\d+)?",
            r"adaptive\s*security\s*appliance",
            r"\basa\s*\d{3,}\b",
        ],
        "version_re": r"cisco\s*asa[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["cisco asa", "asa", "adaptive security appliance"],
    },
    {
        "name": "Fortinet FortiGate",
        "vendor": "Fortinet",
        "category": "security_tools",
        "patterns": [
            r"fortigate\s*\d+\.\d+",
            r"fortinet\s*fortigate",
            r"\bfortigate\b",
            r"\bfortios\b",
        ],
        "version_re": r"fortios[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["fortigate", "fortinet", "fortios", "forti gate"],
    },
    {
        "name": "Check Point",
        "vendor": "Check Point Software Technologies",
        "category": "security_tools",
        "patterns": [
            r"check\s*point\s*gaia",
            r"check\s*point\s*firewall",
            r"\bcheck\s*point\b",
        ],
        "version_re": r"check\s*point[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["check point", "checkpoint", "gaia"],
    },
    {
        "name": "Wazuh",
        "vendor": "Wazuh Inc",
        "category": "security_tools",
        "patterns": [
            r"wazuh\s*\d+\.\d+",
            r"\bwazuh\b",
        ],
        "version_re": r"wazuh[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["wazuh", "wazuh siem"],
    },
    {
        "name": "OPNsense",
        "vendor": "Deciso",
        "category": "security_tools",
        "patterns": [
            r"opnsense\s*\d+\.\d+",
            r"\bopnsense\b",
        ],
        "version_re": r"opnsense[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["opnsense", "opn sense"],
    },
    {
        "name": "pfSense",
        "vendor": "Netgate",
        "category": "security_tools",
        "patterns": [
            r"pfsense\s*\d+\.\d+",
            r"\bpfsense\b",
        ],
        "version_re": r"pfsense[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["pfsense", "pf sense"],
    },
    {
        "name": "Suricata",
        "vendor": "OISF (Open Information Security Foundation)",
        "category": "security_tools",
        "patterns": [
            r"suricata\s*\d+\.\d+",
            r"\bsuricata\b",
        ],
        "version_re": r"suricata[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["suricata", "suricata ids"],
    },
    {
        "name": "Snort",
        "vendor": "Cisco Systems",
        "category": "security_tools",
        "patterns": [
            r"snort\s*\d+\.\d+",
            r"\bsnort\b",
        ],
        "version_re": r"snort[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["snort", "snort ids"],
    },
    {
        "name": "CrowdStrike",
        "vendor": "CrowdStrike Inc",
        "category": "security_tools",
        "patterns": [
            r"crowdstrike\s*\d+(?:\.\d+)?",
            r"falcon\s*sensor",
            r"\bcrowdstrike\b",
        ],
        "version_re": r"crowdstrike[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["crowdstrike", "crowdstrike falcon", "falcon sensor"],
    },
    {
        "name": "SentinelOne",
        "vendor": "SentinelOne Inc",
        "category": "security_tools",
        "patterns": [
            r"sentinel\s*one\s*\d+(?:\.\d+)?",
            r"\bsentinelone\b",
        ],
        "version_re": r"sentinel\s*one[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["sentinelone", "sentinel one"],
    },
    {
        "name": "Symantec",
        "vendor": "Broadcom (Symantec)",
        "category": "security_tools",
        "patterns": [
            r"symantec\s*endpoint\s*protection",
            r"norton\b",
            r"\bsymantec\b",
        ],
        "version_re": r"symantec[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["symantec", "symantec endpoint protection", "norton"],
    },
    {
        "name": "McAfee",
        "vendor": "McAfee",
        "category": "security_tools",
        "patterns": [
            r"mcafee\s*(?:endpoint|epo|firewall)?\s*\d+\.\d+",
            r"\bmcafee\b",
        ],
        "version_re": r"mcafee[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["mcafee", "mcafee epo", "mcafee endpoint"],
    },
    {
        "name": "Qualys",
        "vendor": "Qualys Inc",
        "category": "security_tools",
        "patterns": [
            r"qualys\s*\d+(?:\.\d+)?",
            r"\bqualys\b",
        ],
        "version_re": r"qualys[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["qualys", "qualys vm", "qualys guard"],
    },
    {
        "name": "Tenable Nessus",
        "vendor": "Tenable Inc",
        "category": "security_tools",
        "patterns": [
            r"tenable\s*nessus\s*\d+\.\d+",
            r"nessus\s*professional",
            r"\bnessus\b",
            r"\btenable\b",
        ],
        "version_re": r"nessus[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["nessus", "tenable", "tenable nessus"],
    },
    {
        "name": "OpenSSL",
        "vendor": "The OpenSSL Project",
        "category": "security_tools",
        "patterns": [
            r"openssl\s*\d+\.\d+\.\d+",
            r"\bopenssl\b",
        ],
        "version_re": r"openssl[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["openssl", "open ssl"],
    },
    {
        "name": "OpenSSH",
        "vendor": "OpenBSD Project",
        "category": "security_tools",
        "patterns": [
            r"openssh\s*\d+\.\d+",
            r"\bopenssh\b",
        ],
        "version_re": r"openssh[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["openssh", "open ssh", "ssh"],
    },
    {
        "name": "Wireshark",
        "vendor": "Wireshark Foundation",
        "category": "security_tools",
        "patterns": [
            r"wireshark\s*\d+\.\d+",
            r"\bwireshark\b",
        ],
        "version_re": r"wireshark[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["wireshark", "ethereal"],
    },
    {
        "name": "Nmap",
        "vendor": "Nmap Project",
        "category": "security_tools",
        "patterns": [
            r"nmap\s*\d+\.\d+",
            r"\bnmap\b",
        ],
        "version_re": r"nmap[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["nmap", "network mapper"],
    },
    {
        "name": "Metasploit",
        "vendor": "Rapid7",
        "category": "security_tools",
        "patterns": [
            r"metasploit\s*\d+\.\d+",
            r"\bmetasploit\b",
        ],
        "version_re": r"metasploit[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["metasploit", "metasploit framework", "msf"],
    },
    {
        "name": "Burp Suite",
        "vendor": "PortSwigger",
        "category": "security_tools",
        "patterns": [
            r"burp\s*suite\s*(?:professional|community)?",
            r"\bburp\s*suite\b",
        ],
        "version_re": None,
        "aliases": ["burp suite", "burp", "burpsuite"],
    },
    {
        "name": "ModSecurity",
        "vendor": "OWASP Foundation",
        "category": "security_tools",
        "patterns": [
            r"modsecurity\s*\d+\.\d+",
            r"\bmodsecurity\b",
        ],
        "version_re": r"modsecurity[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["modsecurity", "mod security"],
    },
    {
        "name": "Cloudflare",
        "vendor": "Cloudflare Inc",
        "category": "security_tools",
        "patterns": [
            r"cloudflare\s*waf",
            r"\bcloudflare\b",
        ],
        "version_re": None,
        "aliases": ["cloudflare", "cloudflare waf"],
    },
    {
        "name": "Imperva",
        "vendor": "Imperva (Thales)",
        "category": "security_tools",
        "patterns": [
            r"imperva\s*(?:app\s*protect|waf)?",
            r"\bimperva\b",
        ],
        "version_re": None,
        "aliases": ["imperva", "imperva waf", "imperva app protect"],
    },
    {
        "name": "Akamai",
        "vendor": "Akamai Technologies",
        "category": "security_tools",
        "patterns": [
            r"akamai\s*(?:waf|kona)?",
            r"\bakamai\b",
        ],
        "version_re": None,
        "aliases": ["akamai", "akamai waf", "kona site defender"],
    },

    # ============================ NETWORK DEVICES ============================
    {
        "name": "Cisco IOS",
        "vendor": "Cisco Systems",
        "category": "network_devices",
        "patterns": [
            r"cisco\s*ios\s*xe\s*\d+\.\d+",
            r"cisco\s*ios\s*\d+\.\d+",
            r"\bios[\s-]?xe\b",
        ],
        "version_re": r"cisco\s*ios[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["cisco ios", "ios xe", "cisco ios xe", "ios-xe"],
    },
    {
        "name": "Cisco Nexus",
        "vendor": "Cisco Systems",
        "category": "network_devices",
        "patterns": [
            r"cisco\s*nexus\s*\d{4}",
            r"\bnexus\s*\d{4}\b",
        ],
        "version_re": r"nexus\s*(\d{4})",
        "aliases": ["cisco nexus", "nexus os", "nx-os"],
    },
    {
        "name": "Juniper Junos",
        "vendor": "Juniper Networks",
        "category": "network_devices",
        "patterns": [
            r"juniper\s*junos\s*\d+\.\d+",
            r"junos\s*s?\d+\.\d+",
            r"\bjunos\b",
        ],
        "version_re": r"junos[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["juniper", "junos", "juniper junos"],
    },
    {
        "name": "Arista EOS",
        "vendor": "Arista Networks",
        "category": "network_devices",
        "patterns": [
            r"arista\s*eos\s*\d+\.\d+",
            r"\barista\b",
        ],
        "version_re": r"arista\s*eos[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["arista", "arista eos", "eos"],
    },
    {
        "name": "Extreme Networks",
        "vendor": "Extreme Networks",
        "category": "network_devices",
        "patterns": [
            r"extreme\s*networks\s*\d+(?:\.\d+)?",
        ],
        "version_re": r"extreme\s*networks[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["extreme networks", "extreme"],
    },
    {
        "name": "MikroTik",
        "vendor": "MikroTik",
        "category": "network_devices",
        "patterns": [
            r"mikrotik\s*router\s*os\s*\d+\.\d+",
            r"router\s*os\s*\d+\.\d+",
            r"\bmikrotik\b",
        ],
        "version_re": r"router\s*os[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["mikrotik", "routeros", "router os", "mikrotik router os", "mikrotik routeros"],
    },
    {
        "name": "Ubiquiti",
        "vendor": "Ubiquiti Inc",
        "category": "network_devices",
        "patterns": [
            r"ubiquiti\s*(?:unifi)?\s*\d+(?:\.\d+)?",
            r"unifi\s*controller",
            r"\bubiquiti\b",
        ],
        "version_re": r"ubiquiti[^\d]*(\d+(?:\.\d+)?)",
        "aliases": ["ubiquiti", "unifi", "ubiquiti unifi"],
    },
{
        "name": "F5 BIG-IP",
        "vendor": "F5 Networks",
        "category": "network_devices",
        "patterns": [
            r"f5\s*big['-]?ip\s*\d+\.\d+",
            r"\bbig-ip\b",
            r"\bbigip\b",
            r"\bf5\b",
        ],
        # Require the version to immediately follow the tech name (bounded, same clause),
        # so we don't accidentally grab a distant version number (e.g. "Ubuntu 22.04").
        "version_re": r"\bf5\s*big['-]?ip\s+(?:ltm|gtm|aam|afm|apm|asm|awaf|viprion)?\s*v?(\d+\.\d+(?:\.\d+)?)\b",
        "aliases": ["f5", "big-ip", "bigip", "f5 big-ip"],
    },
    {
        "name": "Citrix NetScaler",
        "vendor": "Citrix Systems",
        "category": "network_devices",
        "patterns": [
            r"citrix\s*netscaler\s*\d+\.\d+",
            r"netscaler\s*(?:adc)?\s*\d+\.\d+",
            r"\bnetscaler\b",
        ],
        "version_re": r"netscaler[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["netscaler", "citrix netscaler", "netscaler adc"],
    },
    {
        "name": "Riverbed",
        "vendor": "Riverbed Technology",
        "category": "network_devices",
        "patterns": [
            r"riverbed\s*steelhead\s*\d+\.\d+",
            r"\briverbed\b",
        ],
        "version_re": r"riverbed[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["riverbed", "steelhead"],
    },
    {
        "name": "Aruba",
        "vendor": "HPE Aruba",
        "category": "network_devices",
        "patterns": [
            r"aruba\s*(?:networks|os|wireless)?\s*\d+\.\d+",
            r"\baruba\b",
        ],
        "version_re": r"aruba[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["aruba", "hpe aruba", "aruba networks"],
    },
    {
        "name": "Cisco Firepower",
        "vendor": "Cisco Systems",
        "category": "network_devices",
        "patterns": [
            r"cisco\s*firepower\s*\d+",
            r"\bfirepower\b",
        ],
        "version_re": r"firepower[^\d]*(\d+)",
        "aliases": ["cisco firepower", "firepower", "ftd"],
    },

    # ============================ PROGRAMMING LANGUAGES / FRAMEWORKS ============================
    {
        "name": "Java",
        "vendor": "Oracle Corporation",
        "category": "programming_language",
        "patterns": [
            r"\bjava\s*(?:jdk|jre|se)?\s*\d+(?:\.\d+)*",
            r"\bjava\b",
        ],
        "version_re": r"\bjava[^\d]*(\d+(?:\.\d+)*)",
        "aliases": ["java", "jdk", "jre"],
    },
    {
        "name": "Python",
        "vendor": "Python Software Foundation",
        "category": "programming_language",
        "patterns": [
            r"\bpython\s*\d+\.\d+",
            r"\bpython\b",
        ],
        "version_re": r"\bpython[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["python", "python runtime"],
    },
    {
        "name": ".NET",
        "vendor": "Microsoft Corporation",
        "category": "framework",
        "patterns": [
            r"\.net\s*(?:core|framework)?\s*\d+\.\d+",
            r"\basp\.net\b",
            r"\.net\s*framework",
        ],
        "version_re": r"\.net[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": [".net", "dotnet", "asp.net", ".net framework"],
    },
    {
        "name": "PHP",
        "vendor": "PHP Group",
        "category": "programming_language",
        "patterns": [
            r"\bphp\s*\d+\.\d+",
            r"\bphp\b",
        ],
        "version_re": r"\bphp[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["php", "php runtime"],
    },
    {
        "name": "Ruby on Rails",
        "vendor": "Rails Core Team",
        "category": "framework",
        "patterns": [
            r"ruby\s*on\s*rails\s*\d+\.\d+",
            r"\brails\s*\d+\.\d+",
            r"\bruby\s*on\s*rails\b",
        ],
        "version_re": r"rails[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["rails", "ruby on rails", "ror"],
    },
    {
        "name": "Spring",
        "vendor": "VMware (Pivotal)",
        "category": "framework",
        "patterns": [
            r"spring\s*(?:boot|framework|cloud)?\s*\d+\.\d+",
            r"\bspring\s*boot\b",
        ],
        "version_re": r"spring[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["spring", "spring boot", "spring framework"],
    },
    {
        "name": "React",
        "vendor": "Meta (Facebook)",
        "category": "framework",
        "patterns": [
            r"\breact(?:\.?js)?\s*\d+\.\d+",
            r"\breact\.?js\b",
        ],
        "version_re": r"\breact[^\d]*(\d+\.\d+(?:\.\d+)?)",
        "aliases": ["react", "reactjs", "react.js"],
    },
    {
        "name": "Angular",
        "vendor": "Google LLC",
        "category": "framework",
        "patterns": [
            r"angular(?:\s*\d+)?",
            r"\bangular\b",
        ],
        "version_re": r"angular\s*(\d+(?:\.\d+)*)",
        "aliases": ["angular", "angularjs", "angular js"],
    },
]


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def get_technology_by_name(name: str) -> Dict:
    """Return the canonical pattern entry whose name matches (case-insensitive)."""
    if not name:
        return {}
    target = name.strip().lower()
    for entry in TECHNOLOGY_PATTERNS:
        if entry["name"].lower() == target:
            return entry
    return {}


def get_aliases() -> Dict[str, str]:
    """Build a mapping of every alias/name -> canonical technology name.

    Useful for normalizing results from different extraction sources.
    """
    mapping: Dict[str, str] = {}
    for entry in TECHNOLOGY_PATTERNS:
        canonical = entry["name"]
        mapping[canonical.lower()] = canonical
        for alias in entry.get("aliases", []):
            mapping[alias.lower()] = canonical
    return mapping


def list_categories() -> List[str]:
    """Return the known set of categories."""
    return list(KNOWN_CATEGORIES)


def count_technologies() -> int:
    """Return the number of technology entries in the database."""
    return len(TECHNOLOGY_PATTERNS)
