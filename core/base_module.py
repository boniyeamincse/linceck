"""
Base Module Class for Linux Server Auditor

This module defines the abstract base class that all audit modules must inherit from.
It provides a standardized interface and common functionality for all security audit modules.
"""

import abc
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum

class ModuleStatus(Enum):
    """Status of module execution."""
    SUCCESS = "success"
    PARTIAL = "partial"
    ERROR = "error"
    SKIPPED = "skipped"

class SeverityLevel(Enum):
    """Severity levels for security issues."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityIssue:
    """Represents a security issue found during audit."""
    title: str
    description: str
    severity: SeverityLevel
    recommendation: str
    affected_files: List[str] = None
    evidence: List[str] = None
    cve_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'recommendation': self.recommendation,
            'affected_files': self.affected_files or [],
            'evidence': self.evidence or [],
            'cve_id': self.cve_id
        }

@dataclass
class ModuleResult:
    """Result structure returned by audit modules."""
    status: ModuleStatus
    score: float
    issues: List[SecurityIssue]
    metadata: Dict[str, Any]
    timestamp: str
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'status': self.status.value,
            'score': self.score,
            'issues': [issue.to_dict() for issue in self.issues],
            'metadata': self.metadata,
            'timestamp': self.timestamp,
            'error_message': self.error_message
        }

class BaseModule(abc.ABC):
    """
    Abstract base class for all audit modules.
    
    All audit modules must inherit from this class and implement the required methods.
    """
    
    def __init__(self, config):
        """
        Initialize the module with configuration.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.module_name = self.__class__.__name__
        
    @property
    @abc.abstractmethod
    def module_name(self) -> str:
        """Return the module name."""
        pass
    
    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Return a brief description of what this module audits."""
        pass
    
    @property
    @abc.abstractmethod
    def version(self) -> str:
        """Return the module version."""
        pass
    
    @abc.abstractmethod
    def check_dependencies(self) -> bool:
        """
        Check if required dependencies and permissions are available.
        
        Returns:
            True if dependencies are met, False otherwise
        """
        pass
    
    @abc.abstractmethod
    def run(self) -> ModuleResult:
        """
        Execute the audit module.
        
        Returns:
            ModuleResult containing the audit results
        """
        pass
    
    def get_score(self) -> float:
        """
        Calculate and return the module's security score.
        
        Returns:
            Float between 0.0 and 100.0 representing the security score
        """
        return 0.0
    
    def get_issues(self) -> List[SecurityIssue]:
        """
        Return a list of security issues found.
        
        Returns:
            List of SecurityIssue objects
        """
        return []
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Return module-specific metadata.
        
        Returns:
            Dictionary containing module metadata
        """
        return {}
    
    def log_info(self, message: str, **kwargs):
        """Log an info message with module context."""
        self.logger.info(f"[{self.module_name}] {message}", **kwargs)
    
    def log_warning(self, message: str, **kwargs):
        """Log a warning message with module context."""
        self.logger.warning(f"[{self.module_name}] {message}", **kwargs)
    
    def log_error(self, message: str, **kwargs):
        """Log an error message with module context."""
        self.logger.error(f"[{self.module_name}] {message}", **kwargs)
    
    def log_debug(self, message: str, **kwargs):
        """Log a debug message with module context."""
        self.logger.debug(f"[{self.module_name}] {message}", **kwargs)
    
    def create_issue(self, title: str, description: str, severity: SeverityLevel,
                    recommendation: str, affected_files: List[str] = None,
                    evidence: List[str] = None, cve_id: str = None) -> SecurityIssue:
        """
        Create a SecurityIssue object.
        
        Args:
            title: Brief title of the issue
            description: Detailed description
            severity: Severity level
            recommendation: Recommended fix
            affected_files: List of affected files
            evidence: List of evidence strings
            cve_id: CVE identifier if applicable
            
        Returns:
            SecurityIssue object
        """
        return SecurityIssue(
            title=title,
            description=description,
            severity=severity,
            recommendation=recommendation,
            affected_files=affected_files or [],
            evidence=evidence or [],
            cve_id=cve_id
        )
    
    def validate_result(self, result: ModuleResult) -> bool:
        """
        Validate the result structure.
        
        Args:
            result: ModuleResult to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not isinstance(result, ModuleResult):
            return False
        
        if not 0.0 <= result.score <= 100.0:
            return False
        
        if result.status not in ModuleStatus:
            return False
        
        return True
    
    def format_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now().isoformat()
    
    def safe_run(self) -> ModuleResult:
        """
        Safely execute the module with error handling.
        
        Returns:
            ModuleResult object
        """
        try:
            self.log_info("Starting module execution")
            
            # Check dependencies
            if not self.check_dependencies():
                return ModuleResult(
                    status=ModuleStatus.SKIPPED,
                    score=0.0,
                    issues=[],
                    metadata={'reason': 'Dependencies not met'},
                    timestamp=self.format_timestamp(),
                    error_message="Module dependencies not satisfied"
                )
            
            # Run the actual module
            result = self.run()
            
            # Validate result
            if not self.validate_result(result):
                self.log_error("Invalid result structure returned")
                return ModuleResult(
                    status=ModuleStatus.ERROR,
                    score=0.0,
                    issues=[],
                    metadata={},
                    timestamp=self.format_timestamp(),
                    error_message="Invalid result structure"
                )
            
            self.log_info(f"Module completed with score: {result.score}")
            return result
            
        except Exception as e:
            self.log_error(f"Module execution failed: {str(e)}")
            import traceback
            self.log_debug(f"Traceback: {traceback.format_exc()}")
            
            return ModuleResult(
                status=ModuleStatus.ERROR,
                score=0.0,
                issues=[],
                metadata={},
                timestamp=self.format_timestamp(),
                error_message=str(e)
            )
    
    def calculate_score_from_issues(self, issues: List[SecurityIssue], 
                                   base_score: float = 100.0) -> float:
        """
        Calculate score based on security issues found.
        
        Args:
            issues: List of security issues
            base_score: Starting score (default 100.0)
            
        Returns:
            Calculated score
        """
        if not issues:
            return base_score
        
        score = base_score
        
        # Deduct points based on severity
        severity_weights = {
            SeverityLevel.LOW: 2.0,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.HIGH: 10.0,
            SeverityLevel.CRITICAL: 20.0
        }
        
        for issue in issues:
            score -= severity_weights.get(issue.severity, 1.0)
        
        return max(0.0, min(100.0, score))
    
    def get_config_value(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value with fallback to default.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)
    
    def require_root(self) -> bool:
        """
        Check if the module requires root privileges.
        
        Returns:
            True if root is required, False otherwise
        """
        return False
    
    def get_module_info(self) -> Dict[str, Any]:
        """Get module information."""
        return {
            'name': self.module_name,
            'description': self.description,
            'version': self.version,
            'requires_root': self.require_root()
        }