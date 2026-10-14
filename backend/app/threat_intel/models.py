from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class ThreatArticleModel:
    title: str
    url: str
    source: str
    published_date: Optional[datetime] = None
    content: Optional[str] = None
    threat_type: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
