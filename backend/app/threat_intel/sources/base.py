from abc import ABC, abstractmethod
from typing import Any, Dict, List


class ThreatIntelSource(ABC):
    @abstractmethod
    def fetch_articles(self) -> List[Dict[str, Any]]:
        """Fetch raw items from the source."""
        raise NotImplementedError

    @abstractmethod
    def normalize_article(self, raw_article: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a source-specific raw item into the common threat article schema."""
        raise NotImplementedError
