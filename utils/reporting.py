"""
Report Generation Utilities for Linux Server Auditor

This module provides functionality to generate comprehensive security audit reports
in multiple formats (JSON, YAML, HTML) with customizable templates and styling.
"""

import json
import yaml
import logging
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
from pathlib import Path
from jinja2 import Template, Environment, FileSystemLoader, select_autoescape
import markdown
from dataclasses import asdict

from core.config import ConfigManager
from utils.scoring import ScoringEngine, Grade

class ReportGenerator:
    """
    Report generator for audit results.
    
    Features:
    - Multiple output formats (JSON, YAML, HTML)
    - Customizable templates
    - Score visualization
    - Security recommendations
    - Executive summaries
    """
    
    def __init__(self, config: ConfigManager):
        """
        Initialize report generator.
        
        Args:
            config: Configuration manager instance
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.scoring_engine = ScoringEngine(config)
        
        # Template configuration
        self.template_dir = self.config.get('reporting.template_dir', 'templates')
        self.template_name = self.config.get('reporting.template_name', 'audit_report.html')
        
        self.logger.info("Report generator initialized")
    
    def generate_json_report(self, audit_data: Dict[str, Any]) -> str:
        """
        Generate JSON format report.
        
        Args:
            audit_data: Audit results data
            
        Returns:
            JSON string
        """
        try:
            # Process and enhance the audit data
            processed_data = self._process_audit_data(audit_data)
            
            # Add metadata
            processed_data['report_metadata'] = {
                'generator': 'Linux Server Auditor',
                'version': self.config.get('general.version', '1.0.0'),
                'generated_at': datetime.now().isoformat(),
                'format': 'json'
            }
            
            # Pretty print JSON
            return json.dumps(processed_data, indent=2, ensure_ascii=False)
            
        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {str(e)}")
            raise
    
    def generate_yaml_report(self, audit_data: Dict[str, Any]) -> str:
        """
        Generate YAML format report.
        
        Args:
            audit_data: Audit results data
            
        Returns:
            YAML string
        """
        try:
            # Process and enhance the audit data
            processed_data = self._process_audit_data(audit_data)
            
            # Add metadata
            processed_data['report_metadata'] = {
                'generator': 'Linux Server Auditor',
                'version': self.config.get('general.version', '1.0.0'),
                'generated_at': datetime.now().isoformat(),
                'format': 'yaml'
            }
            
            # Generate YAML with proper formatting
            return yaml.dump(
                processed_data, 
                default_flow_style=False, 
                indent=2,
                allow_unicode=True,
                sort_keys=False
            )
            
        except Exception as e:
            self.logger.error(f"Failed to generate YAML report: {str(e)}")
            raise
    
    def generate_html_report(self, audit_data: Dict[str, Any]) -> str:
        """
        Generate HTML format report.
        
        Args:
            audit_data: Audit results data
            
        Returns:
            HTML string
        """
        try:
            # Process and enhance the audit data
            processed_data = self._process_audit_data(audit_data)
            
            # Generate score report
            score_report = self.scoring_engine.generate_score_report(
                processed_data.get('module_results', {})
            )
            processed_data['score_report'] = score_report
            
            # Add metadata
            processed_data['report_metadata'] = {
                'generator': 'Linux Server Auditor',
                'version': self.config.get('general.version', '1.0.0'),
                'generated_at': datetime.now().isoformat(),
                'format': 'html'
            }
            
            # Load and render template
            html_content = self._render_html_template(processed_data)
            
            return html_content
            
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {str(e)}")
            raise
    
    def _process_audit_data(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process and enhance audit data for reporting."""
        processed = audit_data.copy()
        
        # Enhance module results
        if 'module_results' in processed:
            for module_name, result in processed['module_results'].items():
                if result.get('status') == 'success':
                    # Add severity counts
                    issues = result.get('issues', [])
                    severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
                    
                    for issue in issues:
                        if isinstance(issue, dict):
                            severity = issue.get('severity', 'low')
                        else:
                            severity = getattr(issue, 'severity', 'low')
                            if hasattr(severity, 'value'):
                                severity = severity.value
                        
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                    
                    result['severity_counts'] = severity_counts
        
        # Add executive summary
        processed['executive_summary'] = self._generate_executive_summary(processed)
        
        return processed
    
    def _generate_executive_summary(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary."""
        summary = {
            'overview': 'Security audit completed successfully',
            'key_findings': [],
            'recommendations': [],
            'risk_assessment': 'Unknown'
        }
        
        # Calculate overall statistics
        module_results = audit_data.get('module_results', {})
        total_modules = len(module_results)
        successful_modules = sum(1 for r in module_results.values() if r.get('status') == 'success')
        total_issues = sum(len(r.get('issues', [])) for r in module_results.values())
        
        # Count issues by severity
        severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for result in module_results.values():
            for issue in result.get('issues', []):
                if isinstance(issue, dict):
                    severity = issue.get('severity', 'low')
                else:
                    severity = getattr(issue, 'severity', 'low')
                    if hasattr(severity, 'value'):
                        severity = severity.value
                
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        # Generate key findings
        if severity_counts['critical'] > 0:
            summary['key_findings'].append(f"{severity_counts['critical']} critical security issues found")
        if severity_counts['high'] > 0:
            summary['key_findings'].append(f"{severity_counts['high']} high-severity security issues found")
        if total_issues > 50:
            summary['key_findings'].append("Large number of security issues detected")
        
        # Generate risk assessment
        if severity_counts['critical'] > 0:
            summary['risk_assessment'] = 'Critical Risk'
        elif severity_counts['high'] > 5:
            summary['risk_assessment'] = 'High Risk'
        elif severity_counts['medium'] > 10:
            summary['risk_assessment'] = 'Medium Risk'
        else:
            summary['risk_assessment'] = 'Low Risk'
        
        # Add recommendations
        if severity_counts['critical'] > 0:
            summary['recommendations'].append("Address all critical security issues immediately")
        if severity_counts['high'] > 0:
            summary['recommendations'].append("Review and fix high-severity security issues")
        if total_issues > 20:
            summary['recommendations'].append("Implement comprehensive security hardening measures")
        
        return summary
    
    def _render_html_template(self, audit_data: Dict[str, Any]) -> str:
        """Render HTML template with audit data."""
        try:
            # Try to load template from configured directory
            template_path = Path(self.template_dir)
            if template_path.exists():
                env = Environment(
                    loader=FileSystemLoader(str(template_path)),
                    autoescape=select_autoescape(['html', 'xml'])
                )
                template = env.get_template(self.template_name)
            else:
                # Use default template
                template = Template(self._get_default_html_template())
            
            # Render template
            html_content = template.render(
                audit_data=audit_data,
                timestamp=datetime.now(),
                config=self.config.get_all()
            )
            
            return html_content
            
        except Exception as e:
            self.logger.error(f"Failed to render HTML template: {str(e)}")
            # Fallback to simple HTML
            return self._generate_simple_html_report(audit_data)
    
    def _generate_simple_html_report(self, audit_data: Dict[str, Any]) -> str:
        """Generate a simple HTML report as fallback."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Linux Server Security Audit Report</title>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #666; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
                .summary {{ background: #f9f9f9; padding: 20px; border-left: 4px solid #007bff; margin: 20px 0; }}
                .issue {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; }}
                .critical {{ border-color: #dc3545; background: #f8d7da; }}
                .high {{ border-color: #fd7e14; background: #ffeaa7; }}
                .medium {{ border-color: #ffc107; background: #fff3cd; }}
                .low {{ border-color: #28a745; background: #d4edda; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Linux Server Security Audit Report</h1>
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Overall Risk:</strong> {audit_data.get('summary', {}).get('overall_grade', 'Unknown')}</p>
                <p><strong>Total Issues:</strong> {sum(len(r.get('issues', [])) for r in audit_data.get('module_results', {}).values())}</p>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <h2>Module Results</h2>
            <table>
                <tr>
                    <th>Module</th>
                    <th>Status</th>
                    <th>Score</th>
                    <th>Issues</th>
                </tr>
        """
        
        for module_name, result in audit_data.get('module_results', {}).items():
            status = result.get('status', 'unknown')
            score = result.get('score', 0)
            issue_count = len(result.get('issues', []))
            
            html += f"""
                <tr>
                    <td>{module_name}</td>
                    <td>{status}</td>
                    <td>{score}</td>
                    <td>{issue_count}</td>
                </tr>
            """
        
        html += """
            </table>
            
            <h2>Security Issues</h2>
        """
        
        for module_name, result in audit_data.get('module_results', {}).items():
            issues = result.get('issues', [])
            if issues:
                html += f"<h3>{module_name}</h3>"
                
                for issue in issues:
                    if isinstance(issue, dict):
                        severity = issue.get('severity', 'low')
                        title = issue.get('title', 'Unknown issue')
                        description = issue.get('description', '')
                    else:
                        severity = getattr(issue, 'severity', 'low')
                        if hasattr(severity, 'value'):
                            severity = severity.value
                        title = getattr(issue, 'title', 'Unknown issue')
                        description = getattr(issue, 'description', '')
                    
                    css_class = severity.lower()
                    html += f"""
                    <div class="issue {css_class}">
                        <strong>{severity.upper()}:</strong> {title}<br>
                        <small>{description}</small>
                    </div>
                    """
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def _get_default_html_template(self) -> str:
        """Get default HTML template as string."""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>Linux Server Security Audit Report</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 40px; }
        .summary-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin: 20px 0; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }
        .summary-item { background: rgba(255,255,255,0.2); padding: 20px; border-radius: 8px; text-align: center; }
        .grade { font-size: 48px; font-weight: bold; margin: 20px 0; }
        .grade.A { color: #2ecc71; }
        .grade.B { color: #f1c40f; }
        .grade.C { color: #e67e22; }
        .grade.D { color: #e74c3c; }
        .grade.F { color: #c0392b; }
        .module-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .module-card { background: #ecf0f1; padding: 20px; border-radius: 8px; border-left: 4px solid #3498db; }
        .score-bar { width: 100%; height: 20px; background: #ecf0f1; border-radius: 10px; overflow: hidden; margin: 10px 0; }
        .score-fill { height: 100%; background: linear-gradient(90deg, #2ecc71, #f1c40f); }
        .issue-list { margin: 10px 0; }
        .issue-item { margin: 10px 0; padding: 10px; border-radius: 5px; border-left: 4px solid #bdc3c7; }
        .severity-critical { border-left-color: #e74c3c; background: #fadbd8; }
        .severity-high { border-left-color: #e67e22; background: #fdeaa7; }
        .severity-medium { border-left-color: #f1c40f; background: #fef9e7; }
        .severity-low { border-left-color: #2ecc71; background: #d5f4e6; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Linux Server Security Audit Report</h1>
        
        <div class="summary-card">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h3>Overall Grade</h3>
                    <div class="grade grade.{{ audit_data.summary.overall_grade }}">{{ audit_data.summary.overall_grade }}</div>
                </div>
                <div class="summary-item">
                    <h3>Total Score</h3>
                    <div style="font-size: 24px; font-weight: bold;">{{ "%.1f"|format(audit_data.summary.overall_score) }}%</div>
                </div>
                <div class="summary-item">
                    <h3>Total Issues</h3>
                    <div style="font-size: 24px; font-weight: bold;">{{ audit_data.summary.total_issues|default(0) }}</div>
                </div>
                <div class="summary-item">
                    <h3>Risk Level</h3>
                    <div style="font-size: 24px; font-weight: bold;">{{ audit_data.executive_summary.risk_assessment }}</div>
                </div>
            </div>
        </div>
        
        <h2>Module Results</h2>
        <div class="module-grid">
        {% for module_name, result in audit_data.module_results.items() %}
            <div class="module-card">
                <h3>{{ module_name|title }}</h3>
                <div class="score-bar">
                    <div class="score-fill" style="width: {{ result.score }}%;"></div>
                </div>
                <p><strong>Score:</strong> {{ "%.1f"|format(result.score) }}%</p>
                <p><strong>Status:</strong> {{ result.status }}</p>
                <p><strong>Issues:</strong> {{ result.issues|length }}</p>
                {% if result.severity_counts %}
                <p><strong>Severity Breakdown:</strong></p>
                <ul>
                    <li>Critical: {{ result.severity_counts.critical }}</li>
                    <li>High: {{ result.severity_counts.high }}</li>
                    <li>Medium: {{ result.severity_counts.medium }}</li>
                    <li>Low: {{ result.severity_counts.low }}</li>
                </ul>
                {% endif %}
            </div>
        {% endfor %}
        </div>
        
        <h2>Security Issues</h2>
        {% for module_name, result in audit_data.module_results.items() %}
            {% if result.issues %}
            <h3>{{ module_name|title }}</h3>
            <div class="issue-list">
            {% for issue in result.issues %}
                {% set severity_class = "severity-" + issue.severity.value if issue.severity.value in ['critical', 'high', 'medium', 'low'] else "severity-low" %}
                <div class="issue-item {{ severity_class }}">
                    <strong>{{ issue.severity.value|title }}:</strong> {{ issue.title }}<br>
                    <small>{{ issue.description }}</small>
                    {% if issue.recommendation %}
                    <br><em>Recommendation: {{ issue.recommendation }}</em>
                    {% endif %}
                </div>
            {% endfor %}
            </div>
            {% endif %}
        {% endfor %}
        
        <h2>Recommendations</h2>
        <ul>
        {% for recommendation in audit_data.summary.recommendations %}
            <li>{{ recommendation }}</li>
        {% endfor %}
        </ul>
        
        <div class="footer">
            <p>Report generated by Linux Server Auditor v{{ audit_data.report_metadata.version }}</p>
            <p>Generated at: {{ audit_data.report_metadata.generated_at }}</p>
        </div>
    </div>
</body>
</html>
        """
    
    def save_report(self, content: str, file_path: str, format: str = 'html'):
        """
        Save report to file.
        
        Args:
            content: Report content
            file_path: Output file path
            format: Report format
        """
        try:
            path = Path(file_path).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.logger.info(f"Report saved to {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save report: {str(e)}")
            raise
    
    def generate_markdown_report(self, audit_data: Dict[str, Any]) -> str:
        """
        Generate Markdown format report.
        
        Args:
            audit_data: Audit results data
            
        Returns:
            Markdown string
        """
        try:
            # Process audit data
            processed_data = self._process_audit_data(audit_data)
            
            # Generate markdown content
            md_content = self._generate_markdown_content(processed_data)
            
            # Convert to HTML if needed
            if self.config.get('reporting.convert_markdown_to_html', False):
                return markdown.markdown(md_content, extensions=['tables'])
            else:
                return md_content
                
        except Exception as e:
            self.logger.error(f"Failed to generate Markdown report: {str(e)}")
            raise
    
    def _generate_markdown_content(self, audit_data: Dict[str, Any]) -> str:
        """Generate Markdown content."""
        md = f"""
# Linux Server Security Audit Report

## Executive Summary

**Overall Grade:** {audit_data.get('summary', {}).get('overall_grade', 'Unknown')}
**Total Score:** {audit_data.get('summary', {}).get('overall_score', 0):.1f}%
**Risk Level:** {audit_data.get('executive_summary', {}).get('risk_assessment', 'Unknown')}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Module Results

| Module | Status | Score | Issues |
|--------|--------|-------|--------|
"""
        
        for module_name, result in audit_data.get('module_results', {}).items():
            status = result.get('status', 'unknown')
            score = result.get('score', 0)
            issue_count = len(result.get('issues', []))
            md += f"| {module_name} | {status} | {score:.1f}% | {issue_count} |\n"
        
        md += "\n## Security Issues\n\n"
        
        for module_name, result in audit_data.get('module_results', {}).items():
            issues = result.get('issues', [])
            if issues:
                md += f"### {module_name}\n\n"
                
                for issue in issues:
                    if isinstance(issue, dict):
                        severity = issue.get('severity', 'low')
                        title = issue.get('title', 'Unknown issue')
                        description = issue.get('description', '')
                        recommendation = issue.get('recommendation', '')
                    else:
                        severity = getattr(issue, 'severity', 'low')
                        if hasattr(severity, 'value'):
                            severity = severity.value
                        title = getattr(issue, 'title', 'Unknown issue')
                        description = getattr(issue, 'description', '')
                        recommendation = getattr(issue, 'recommendation', '')
                    
                    md += f"#### {severity.upper()}: {title}\n\n"
                    md += f"{description}\n\n"
                    if recommendation:
                        md += f"**Recommendation:** {recommendation}\n\n"
        
        md += "## Recommendations\n\n"
        for rec in audit_data.get('summary', {}).get('recommendations', []):
            md += f"- {rec}\n"
        
        return md