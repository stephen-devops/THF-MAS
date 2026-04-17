"""
Relationship mapping functions
"""

from .entity_to_entity import execute as entity_to_entity_execute
from .behavioural_correlation import execute as behavioural_correlation_execute

__all__ = [
    "entity_to_entity_execute",
    "behavioural_correlation_execute"
]