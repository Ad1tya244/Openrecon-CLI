from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Evidence:
    type: str                     # e.g., "header", "cookie", "script", "JavaScript", "HTML"
    source: Optional[str] = None  # e.g., "Server", "cf-ray", "/js/app.js", "inline script #2"
    location: Optional[str] = None # e.g., "fetchCall", "form#login"
    snippet: Optional[str] = None  # e.g., matched pattern value or code snippet
    rule: Optional[str] = None     # e.g., "implies", "requires"
    detection_engine: str = "technology-engine" # "technology-engine", "ast-endpoint-parser", "endpoint-parser", or "fallback"
    confidence: Optional[float] = None

    def get_identity(self):
        return (
            self.detection_engine,
            self.type,
            self.source or "",
            self.snippet or "",
            self.location or ""
        )

@dataclass
class Finding:
    value: str                     # e.g., "WordPress", "/api/event"
    category: Optional[str] = None # e.g., "CMS", "API Endpoint"
    version: Optional[str] = None
    confidence: Optional[float] = None
    evidence: List[Evidence] = field(default_factory=list)
    inference: Optional[str] = None # "DIRECT", "INFERRED", "RELATIONAL", or "FALLBACK"
