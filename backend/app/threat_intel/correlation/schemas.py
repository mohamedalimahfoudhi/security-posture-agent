from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class ThreatCorrelationMatch(BaseModel):
    id: int
    article_id: int
    article_title: str
    asset_id: Optional[int]
    asset_technology: Optional[str]
    asset_vendor: Optional[str]
    asset_version: Optional[str]
    match_type: str
    match_text: str
    correlation_score: int
    risk_score: int
    priority: str
    correlation_details: Dict[str, Any]
    created_at: datetime


class ThreatCorrelationList(BaseModel):
    page: int
    limit: int
    total: int
    correlations: List[ThreatCorrelationMatch]


class ThreatCorrelationProcessResult(BaseModel):
    processed_articles: int
    correlations_created: int
