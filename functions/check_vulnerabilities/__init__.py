"""
Vulnerability checking functions for Wazuh SIEM data
"""

from .list_by_entity import execute as execute_list_by_entity
from .check_cve import execute as execute_check_cve
from .check_patches import execute as execute_check_patches

__all__ = [
    "execute_list_by_entity",
    "execute_check_cve", 
    "execute_check_patches"
]