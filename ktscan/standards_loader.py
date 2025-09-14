"""
Standards and profiles loader for the certificate scanner.

This module loads standards definitions and profiles from YAML files.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .models import StandardReference, ValidationSeverity


class StandardsLoader:
    """Loads standards and profiles from YAML files"""
    
    def __init__(self, standards_dir: Optional[str] = None):
        if standards_dir is None:
            # Default to standards directory relative to this file
            self.standards_dir = Path(__file__).parent / "standards"
        else:
            self.standards_dir = Path(standards_dir)
        
        self.logger = logging.getLogger(__name__)
        self._standards_cache: Dict[str, dict] = {}
        self._profiles_cache: Optional[dict] = None
    
    def load_profiles(self) -> Dict[str, List[str]]:
        """Load profile definitions from profiles.yaml and add dynamic profiles"""
        if self._profiles_cache is not None:
            return self._profiles_cache
            
        profiles_file = self.standards_dir / "profiles.yaml"
        if not profiles_file.exists():
            return {}
        
        try:
            with open(profiles_file, 'r') as f:
                data = yaml.safe_load(f)
                profiles = data.get('profiles', {})
                
                # Add dynamic "ALL" profile with all available standards
                available_standards = self.get_available_standards()
                profiles["ALL"] = available_standards
                
                self._profiles_cache = profiles
                return self._profiles_cache
        except FileNotFoundError:
            raise RuntimeError(f"Profiles file not found: {profiles_file}")
        except yaml.YAMLError as e:
            raise RuntimeError(f"Invalid YAML in profiles file {profiles_file}: {e}")
        except (KeyError, TypeError, AttributeError) as e:
            raise RuntimeError(f"Invalid profiles file structure in {profiles_file}: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error loading profiles from {profiles_file}: {e}")
    
    def get_profile_standards(self, profile_name: str) -> List[str]:
        """Get list of standards for a specific profile"""
        profiles = self.load_profiles()
        return profiles.get(profile_name, [])
    
    def load_standard(self, standard_name: str) -> dict:
        """Load a specific standard definition"""
        if standard_name in self._standards_cache:
            return self._standards_cache[standard_name]
        
        standard_file = self.standards_dir / f"{standard_name}.yaml"
        if not standard_file.exists():
            raise FileNotFoundError(f"Standard file not found: {standard_file}")
        
        try:
            with open(standard_file, 'r') as f:
                data = yaml.safe_load(f)
                self._standards_cache[standard_name] = data
                return data
        except yaml.YAMLError as e:
            raise RuntimeError(f"Invalid YAML in standard file {standard_file}: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error loading standard from {standard_file}: {e}")
    
    def get_available_standards(self) -> List[str]:
        """Get list of all available standards"""
        if not self.standards_dir.exists():
            return []
        
        standards = []
        for yaml_file in self.standards_dir.glob("*.yaml"):
            if yaml_file.name != "profiles.yaml":
                standards.append(yaml_file.stem)
        
        return sorted(standards)
    
    def get_available_profiles(self) -> List[str]:
        """Get list of all available profiles"""
        profiles = self.load_profiles()
        return sorted(profiles.keys())
    
    def get_standard_reference(self, standard_name: str, check_id: str) -> Optional[StandardReference]:
        """Get standard reference for a specific check"""
        try:
            standard_data = self.load_standard(standard_name)
            checks = standard_data.get('checks', {})
            
            if check_id not in checks:
                return None
            
            check_data = checks[check_id]
            
            return StandardReference(
                standard=standard_name,
                title=standard_data['title'],
                section=check_data['section'],
                url=check_data['url'],
                severity=ValidationSeverity(check_data['severity'])
            )
        except (KeyError, ValueError, TypeError) as e:
            self.logger.debug(f"Failed to get standard reference for {standard_name}:{check_id}: {e}")
            return None
        except Exception as e:
            self.logger.warning(f"Unexpected error getting standard reference for {standard_name}:{check_id}: {e}")
            return None
    
    def get_all_standard_references(self, check_id: str, enabled_standards: Optional[List[str]] = None) -> List[StandardReference]:
        """Get all standard references for a check across all enabled standards"""
        references = []
        
        # Determine which standards to check
        standards_to_check = enabled_standards if enabled_standards else self.get_available_standards()
        
        for standard_name in standards_to_check:
            ref = self.get_standard_reference(standard_name, check_id)
            if ref:
                references.append(ref)
        
        return references
    
    def validate_profiles(self) -> List[str]:
        """Validate all profiles reference existing standards"""
        errors = []
        profiles = self.load_profiles()
        available_standards = self.get_available_standards()
        
        for profile_name, standards in profiles.items():
            for standard in standards:
                if standard not in available_standards:
                    errors.append(f"Profile '{profile_name}' references unknown standard '{standard}'")
        
        return errors


# Global instance
standards_loader = StandardsLoader()