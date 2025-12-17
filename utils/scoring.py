"""
Scoring and Grading System for Linux Server Auditor

This module implements the scoring algorithms and grading system used to evaluate
the security posture of a Linux server based on audit results.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from core.config import ConfigManager
from core.base_module import SecurityIssue, SeverityLevel

class Grade(Enum):
    """Security grade enum."""
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"
    N_A = "N/A"

@dataclass
class ScoreBreakdown:
    """Detailed score breakdown for a module."""
    module_name: str
    base_score: float
    deductions: List[Dict[str, Any]]
    final_score: float
    weight: float

@dataclass
class OverallScore:
    """Overall security score with breakdown."""
    total_score: float
    grade: Grade
    weighted_scores: Dict[str, float]
    breakdown: List[ScoreBreakdown]
    max_possible_score: float

class ScoringEngine:
    """
    Core scoring engine that calculates security scores and grades.
    
    Features:
    - Weighted scoring based on module importance
    - Severity-based deductions
    - Grade calculation with configurable thresholds
    - Score normalization and scaling
    """
    
    def __init__(self, config: ConfigManager):
        """
        Initialize scoring engine with configuration.
        
        Args:
            config: Configuration manager instance
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Load scoring configuration
        self.weights = self._load_weights()
        self.severity_weights = self._load_severity_weights()
        self.grade_thresholds = self._load_grade_thresholds()
        
        self.logger.info("Scoring engine initialized")
    
    def _load_weights(self) -> Dict[str, float]:
        """Load module weights from configuration."""
        weights = {}
        scoring_config = self.config.get('scoring', {})
        
        # Define expected modules
        expected_modules = [
            'system_info', 'network_security', 'user_management', 
            'service_management', 'file_permissions', 'logging_monitoring',
            'firewall_config', 'package_management', 'disk_security', 'kernel_security'
        ]
        
        for module in expected_modules:
            weight_key = f'weight_{module}'
            weight = scoring_config.get(weight_key, 10.0)  # Default weight
            weights[module] = float(weight)
        
        # Normalize weights to sum to 100
        total_weight = sum(weights.values())
        if total_weight > 0:
            weights = {k: (v / total_weight) * 100 for k, v in weights.items()}
        
        return weights
    
    def _load_severity_weights(self) -> Dict[str, float]:
        """Load severity weights from configuration."""
        default_weights = {
            'low': 1.0,
            'medium': 3.0,
            'high': 5.0,
            'critical': 10.0
        }
        
        config_weights = self.config.get('scoring.severity_weights', {})
        return {**default_weights, **config_weights}
    
    def _load_grade_thresholds(self) -> Dict[str, float]:
        """Load grade thresholds from configuration."""
        default_thresholds = {
            'A': 90.0,
            'B': 80.0,
            'C': 70.0,
            'D': 60.0,
            'F': 0.0
        }
        
        config_thresholds = self.config.get('scoring.grade_thresholds', {})
        return {**default_thresholds, **config_thresholds}
    
    def calculate_module_score(self, module_name: str, issues: List[SecurityIssue], 
                              metadata: Dict[str, Any] = None) -> float:
        """
        Calculate score for a single module.
        
        Args:
            module_name: Name of the module
            issues: List of security issues found
            metadata: Module metadata
            
        Returns:
            Module score (0.0-100.0)
        """
        base_score = 100.0
        deductions = []
        
        # Apply base deductions for critical issues
        critical_issues = [i for i in issues if i.severity == SeverityLevel.CRITICAL]
        if critical_issues:
            base_score -= len(critical_issues) * 15.0
            deductions.append({
                'reason': f'{len(critical_issues)} critical issues',
                'amount': len(critical_issues) * 15.0
            })
        
        # Apply severity-based deductions
        for issue in issues:
            severity_weight = self.severity_weights.get(issue.severity.value, 1.0)
            deduction = severity_weight
            
            # Additional penalties for specific issue types
            if issue.severity == SeverityLevel.CRITICAL:
                deduction += 5.0
            elif issue.severity == SeverityLevel.HIGH:
                deduction += 2.0
            
            # Context-specific penalties
            deduction += self._calculate_context_penalty(issue, metadata)
            
            base_score -= deduction
            deductions.append({
                'reason': f'{issue.severity.value} - {issue.title}',
                'amount': deduction
            })
        
        # Ensure score is within bounds
        final_score = max(0.0, min(100.0, base_score))
        
        self.logger.debug(f"Module {module_name} score: {final_score} (base: {base_score}, deductions: {len(deductions)})")
        
        return final_score
    
    def _calculate_context_penalty(self, issue: SecurityIssue, metadata: Dict[str, Any]) -> float:
        """Calculate context-specific penalty for an issue."""
        penalty = 0.0
        
        if not metadata:
            return penalty
        
        # System-specific penalties
        if metadata.get('is_virtual_machine', False):
            # Virtual machines might have different security requirements
            if issue.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
                penalty -= 1.0  # Slightly reduced penalty
        
        # Environment-specific adjustments
        if metadata.get('environment') == 'production':
            # Higher penalties for production environments
            if issue.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
                penalty += 2.0
        
        # Service-specific penalties
        critical_services = self.config.get('security.critical_services', [])
        for service in critical_services:
            if service.lower() in issue.title.lower() or service.lower() in issue.description.lower():
                penalty += 3.0
                break
        
        return penalty
    
    def calculate_overall_score(self, module_results: Dict[str, Any]) -> float:
        """
        Calculate overall security score from module results.
        
        Args:
            module_results: Dictionary of module results
            
        Returns:
            Overall score (0.0-100.0)
        """
        weighted_scores = {}
        total_weight = 0.0
        max_possible_score = 0.0
        
        for module_name, result in module_results.items():
            if result.get('status') != 'success':
                continue
            
            # Get module weight
            weight = self.weights.get(module_name, 10.0)
            
            # Calculate module score
            issues = self._extract_issues(result)
            score = self.calculate_module_score(module_name, issues, result.get('metadata', {}))
            
            # Apply weight
            weighted_score = score * (weight / 100.0)
            weighted_scores[module_name] = weighted_score
            total_weight += weight
            max_possible_score += weight
        
        # Calculate overall score
        if total_weight > 0:
            overall_score = (sum(weighted_scores.values()) / total_weight) * 100.0
        else:
            overall_score = 0.0
        
        self.logger.info(f"Overall security score: {overall_score:.1f}")
        
        return round(overall_score, 1)
    
    def get_grade(self, score: float) -> Grade:
        """
        Determine grade based on score.
        
        Args:
            score: Security score
            
        Returns:
            Corresponding grade
        """
        if score >= self.grade_thresholds['A']:
            return Grade.A
        elif score >= self.grade_thresholds['B']:
            return Grade.B
        elif score >= self.grade_thresholds['C']:
            return Grade.C
        elif score >= self.grade_thresholds['D']:
            return Grade.D
        else:
            return Grade.F
    
    def get_score_breakdown(self, module_results: Dict[str, Any]) -> List[ScoreBreakdown]:
        """
        Get detailed score breakdown for all modules.
        
        Args:
            module_results: Dictionary of module results
            
        Returns:
            List of score breakdowns
        """
        breakdowns = []
        
        for module_name, result in module_results.items():
            if result.get('status') != 'success':
                continue
            
            issues = self._extract_issues(result)
            metadata = result.get('metadata', {})
            
            # Calculate base score before deductions
            base_score = 100.0
            for issue in issues:
                base_score -= self.severity_weights.get(issue.severity.value, 1.0)
            
            # Calculate final score
            final_score = self.calculate_module_score(module_name, issues, metadata)
            
            # Get weight
            weight = self.weights.get(module_name, 10.0)
            
            # Calculate deductions
            deductions = []
            for issue in issues:
                severity_weight = self.severity_weights.get(issue.severity.value, 1.0)
                context_penalty = self._calculate_context_penalty(issue, metadata)
                total_deduction = severity_weight + context_penalty
                
                if issue.severity == SeverityLevel.CRITICAL:
                    total_deduction += 5.0
                elif issue.severity == SeverityLevel.HIGH:
                    total_deduction += 2.0
                
                deductions.append({
                    'reason': f'{issue.severity.value} - {issue.title}',
                    'amount': total_deduction
                })
            
            breakdown = ScoreBreakdown(
                module_name=module_name,
                base_score=base_score,
                deductions=deductions,
                final_score=final_score,
                weight=weight
            )
            
            breakdowns.append(breakdown)
        
        return breakdowns
    
    def generate_score_report(self, module_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive score report.
        
        Args:
            module_results: Dictionary of module results
            
        Returns:
            Detailed score report
        """
        overall_score = self.calculate_overall_score(module_results)
        grade = self.get_grade(overall_score)
        breakdown = self.get_score_breakdown(module_results)
        
        # Calculate weighted scores
        weighted_scores = {}
        for module_name, result in module_results.items():
            if result.get('status') == 'success':
                issues = self._extract_issues(result)
                score = self.calculate_module_score(module_name, issues, result.get('metadata', {}))
                weighted_scores[module_name] = score
        
        # Calculate statistics
        total_issues = sum(len(self._extract_issues(result)) for result in module_results.values())
        severity_counts = self._count_severity_issues(module_results)
        
        report = {
            'overall_score': overall_score,
            'grade': grade.value,
            'grade_thresholds': self.grade_thresholds,
            'weighted_scores': weighted_scores,
            'score_breakdown': [asdict(b) for b in breakdown],
            'statistics': {
                'total_modules': len(module_results),
                'successful_modules': sum(1 for r in module_results.values() if r.get('status') == 'success'),
                'total_issues': total_issues,
                'severity_counts': severity_counts,
                'average_module_score': sum(weighted_scores.values()) / len(weighted_scores) if weighted_scores else 0.0
            },
            'recommendations': self._generate_score_recommendations(module_results, overall_score)
        }
        
        return report
    
    def _extract_issues(self, result: Dict[str, Any]) -> List[SecurityIssue]:
        """Extract SecurityIssue objects from result."""
        issues = []
        
        if 'issues' in result:
            for issue_data in result['issues']:
                if isinstance(issue_data, dict):
                    # Convert dict to SecurityIssue
                    severity = SeverityLevel(issue_data.get('severity', 'low'))
                    issue = SecurityIssue(
                        title=issue_data.get('title', ''),
                        description=issue_data.get('description', ''),
                        severity=severity,
                        recommendation=issue_data.get('recommendation', ''),
                        affected_files=issue_data.get('affected_files', []),
                        evidence=issue_data.get('evidence', []),
                        cve_id=issue_data.get('cve_id')
                    )
                    issues.append(issue)
                elif isinstance(issue_data, SecurityIssue):
                    issues.append(issue_data)
        
        return issues
    
    def _count_severity_issues(self, module_results: Dict[str, Any]) -> Dict[str, int]:
        """Count issues by severity level."""
        counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        for result in module_results.values():
            issues = self._extract_issues(result)
            for issue in issues:
                counts[issue.severity.value] += 1
        
        return counts
    
    def _generate_score_recommendations(self, module_results: Dict[str, Any], 
                                      overall_score: float) -> List[str]:
        """Generate recommendations based on score and issues."""
        recommendations = []
        
        # Overall recommendations based on grade
        grade = self.get_grade(overall_score)
        if grade in [Grade.D, Grade.F]:
            recommendations.append("Immediate security improvements required - prioritize critical and high-severity issues")
        elif grade == Grade.C:
            recommendations.append("Security posture needs improvement - address medium and high-severity issues")
        
        # Module-specific recommendations
        for module_name, result in module_results.items():
            if result.get('status') != 'success':
                continue
            
            issues = self._extract_issues(result)
            critical_count = sum(1 for i in issues if i.severity == SeverityLevel.CRITICAL)
            high_count = sum(1 for i in issues if i.severity == SeverityLevel.HIGH)
            
            if critical_count > 0:
                recommendations.append(f"{module_name}: Address {critical_count} critical security issues immediately")
            if high_count > 0:
                recommendations.append(f"{module_name}: Review and fix {high_count} high-severity security issues")
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def normalize_score(self, score: float, min_score: float = 0.0, 
                       max_score: float = 100.0) -> float:
        """
        Normalize score to a specific range.
        
        Args:
            score: Original score
            min_score: Minimum value of target range
            max_score: Maximum value of target range
            
        Returns:
            Normalized score
        """
        # Clamp score to 0-100 range first
        clamped_score = max(0.0, min(100.0, score))
        
        # Normalize to target range
        normalized = min_score + (clamped_score / 100.0) * (max_score - min_score)
        
        return round(normalized, 2)
    
    def get_risk_level(self, score: float) -> str:
        """
        Determine risk level based on score.
        
        Args:
            score: Security score
            
        Returns:
            Risk level string
        """
        if score >= 90:
            return "Low Risk"
        elif score >= 70:
            return "Medium Risk"
        elif score >= 50:
            return "High Risk"
        else:
            return "Critical Risk"