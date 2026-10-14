from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, HttpUrl


class ThreatArticleBase(BaseModel):
    title: str
    url: HttpUrl
    source: str
    published_date: Optional[datetime]
    content: Optional[str]
    threat_type: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    summary: Optional[str] = None
    severity: Optional[str] = None
    vendors: Optional[List[str]] = Field(default_factory=list)
    products: Optional[List[str]] = Field(default_factory=list)
    cves: Optional[List[str]] = Field(default_factory=list)
    malware: Optional[List[str]] = Field(default_factory=list)
    threat_actors: Optional[List[str]] = Field(default_factory=list)
    mitre_techniques: Optional[List[str]] = Field(default_factory=list)
    attack_scenario: Optional[str] = None
    technical_impact: Optional[str] = None
    exploitation_context: Optional[str] = None
    affected_technologies: Optional[List[str]] = Field(default_factory=list)
    customer_relevance: Optional[str] = None
    recommendation: Optional[str] = None
    confidence: Optional[float] = None


class ThreatArticleCreate(ThreatArticleBase):
    pass


class ThreatArticleResponse(ThreatArticleBase):
    id: int
    created_at: datetime


class ThreatArticleList(BaseModel):
    page: int
    limit: int
    total: int
    articles: list[ThreatArticleResponse]


class ThreatCollectionResult(BaseModel):
    source: str
    fetched: int
    inserted: int
    duplicates: int


class ThreatProcessResult(BaseModel):
    processed: int
    failed: int
