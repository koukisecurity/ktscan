"""
Check registry for discovery of available check categories.

This module replaces the old validator registry with a new system
that supports standards-based filtering and profiles.
"""

import importlib
import pkgutil
from typing import Dict, List, Optional

from .models import BaseCheck, CheckInfo, ValidationCheck
from .standards_loader import standards_loader


class CheckRegistry:
    """Central registry for all check categories"""
    
    def __init__(self):
        self._checks: Dict[str, BaseCheck] = {}
        self._auto_discover_checks()
    
    def _auto_discover_checks(self) -> None:
        """Auto-discover check categories by scanning the checks package"""
        import ktscan.checks as checks_pkg
        
        for _, module_name, _ in pkgutil.iter_modules(checks_pkg.__path__, 'ktscan.checks.'):
            if module_name.endswith('.__init__'):
                continue
                
            try:
                module = importlib.import_module(module_name)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and 
                        issubclass(attr, BaseCheck) and 
                        attr != BaseCheck):
                        check_instance = attr()
                        self.register_check_category(check_instance)
            except Exception as e:
                print(f"Failed to load check category from {module_name}: {e}")
    
    def register_check_category(self, check_category: BaseCheck) -> None:
        """Register a check category"""
        info = check_category.get_check_info()
        self._checks[info.check_id] = check_category
    
    def get_all_check_categories(self) -> List[CheckInfo]:
        """Get info for all registered check categories"""
        return [c.get_check_info() for c in self._checks.values()]
    
    def get_check_category(self, category_id: str) -> Optional[BaseCheck]:
        """Get a specific check category by ID"""
        return self._checks.get(category_id)
    
    def get_all_checks(self) -> Dict[str, List[ValidationCheck]]:
        """Get all checks organized by category"""
        result = {}
        for category_id, check_category in self._checks.items():
            result[category_id] = check_category.get_all_checks()
        return result
    
    def get_check(self, check_id: str) -> Optional[ValidationCheck]:
        """Get a specific check by its global ID (searches all categories)"""
        for check_category in self._checks.values():
            check = check_category.get_check(check_id)
            if check:
                return check
        return None
    
    def get_checks_for_standards(self, standards: List[str]) -> List[ValidationCheck]:
        """Get all checks that are covered by the specified standards"""
        all_checks = []
        
        for check_category in self._checks.values():
            for check in check_category.get_all_checks():
                # Check if this check is covered by any of the specified standards
                check_standards = {ref.standard for ref in check.standard_refs}
                if check_standards.intersection(set(standards)):
                    all_checks.append(check)
                # Note: Don't include checks without standards when filtering by specific standards
        
        return all_checks
    
    def get_checks_for_profile(self, profile_name: str) -> List[ValidationCheck]:
        """Get all checks for a specific profile"""
        profile_standards = standards_loader.get_profile_standards(profile_name)
        return self.get_checks_for_standards(profile_standards)
    
    def configure_for_standards(self, standards: List[str]) -> None:
        """Configure all check categories to only run checks for specified standards"""
        for check_category in self._checks.values():
            check_category.enabled_standards = set(standards)
    
    def configure_for_profile(self, profile_name: str) -> None:
        """Configure all check categories for a specific profile"""
        profile_standards = standards_loader.get_profile_standards(profile_name)
        self.configure_for_standards(profile_standards)


# Global registry instance
check_registry = CheckRegistry()