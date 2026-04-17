"""
Wazuh LLM Assistant Functions
"""

# Import all function modules
from . import analyze_alerts
from . import investigate_entity
from . import _shared

__all__ = [
    "analyze_alerts",
    "investigate_entity",
    "_shared"
]