#!/usr/bin/env python3
"""
Linux Server Auditor - Main CLI Entry Point

This script serves as the main entry point for the Linux Server Auditor tool.
It handles command-line argument parsing, module orchestration, and overall execution flow.
"""

import argparse
import sys
import os
import logging
import json
import yaml
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

# Import core modules
from core.config import ConfigManager
from core.logger import setup_logging
from core.base_module import BaseModule
from utils.scoring import ScoringEngine
from utils.reporting import ReportGenerator

# Import audit modules
from modules.system_info import SystemInfoModule
from modules.network_security import NetworkSecurityModule
from modules.user_management import UserManagementModule
from modules.service_management import ServiceManagementModule
from modules.file_permissions import FilePermissionsModule
from modules.logging_monitoring import LoggingMonitoringModule
from modules.firewall_config import FirewallConfigModule
from modules.package_management import PackageManagementModule
from modules.disk_security import DiskSecurityModule
from modules.kernel_security import KernelSecurityModule

class LinuxServerAuditor:
    """Main auditor class that orchestrates the execution of all modules."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the auditor with configuration.
        
        Args:
            config_path: Path to configuration file
        """
        self.config = ConfigManager(config_path)
        self.scoring_engine = ScoringEngine(self.config)
        self.report_generator = ReportGenerator(self.config)
        
        # Setup logging
        setup_logging(
            level=self.config.get('logging.level', 'INFO'),
            log_file=self.config.get('logging.file', None),
            verbose=self.config.get('general.verbose', False)
        )
        
        self.logger = logging.getLogger(__name__)
        
        # Initialize all modules
        self.modules = self._initialize_modules()
        
    def _initialize_modules(self) -> Dict[str, BaseModule]:
        """Initialize all audit modules."""
        modules = {
            'system_info': SystemInfoModule(self.config),
            'network_security': NetworkSecurityModule(self.config),
            'user_management': UserManagementModule(self.config),
            'service_management': ServiceManagementModule(self.config),
            'file_permissions': FilePermissionsModule(self.config),
            'logging_monitoring': LoggingMonitoringModule(self.config),
            'firewall_config': FirewallConfigModule(self.config),
            'package_management': PackageManagementModule(self.config),
            'disk_security': DiskSecurityModule(self.config),
            'kernel_security': KernelSecurityModule(self.config),
        }
        
        self.logger.info(f"Initialized {len(modules)} audit modules")
        return modules
    
    def run_audit(self, selected_modules: Optional[List[str]] = None, 
                  output_format: str = 'json', output_file: Optional[str] = None,
                  summary_only: bool = False) -> Dict[str, Any]:
        """
        Run the security audit.
        
        Args:
            selected_modules: List of module names to run (None runs all)
            output_format: Output format ('json', 'yaml', 'html')
            output_file: Output file path (None outputs to stdout)
            summary_only: Whether to show only summary
            
        Returns:
            Audit results dictionary
        """
        self.logger.info("Starting Linux Server Security Audit")
        
        # Determine which modules to run
        if selected_modules is None:
            modules_to_run = list(self.modules.keys())
        else:
            modules_to_run = [m for m in selected_modules if m in self.modules]
            if not modules_to_run:
                self.logger.error("No valid modules specified")
                return {}
        
        self.logger.info(f"Running modules: {', '.join(modules_to_run)}")
        
        # Execute modules
        results = {}
        for module_name in modules_to_run:
            module = self.modules[module_name]
            self.logger.info(f"Running {module_name} module...")
            
            try:
                result = module.run()
                results[module_name] = result
                self.logger.info(f"Completed {module_name} module")
            except Exception as e:
                self.logger.error(f"Error running {module_name} module: {str(e)}")
                results[module_name] = {
                    'status': 'error',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }
        
        # Calculate overall scores
        overall_score = self.scoring_engine.calculate_overall_score(results)
        
        # Generate report
        report_data = {
            'audit_metadata': {
                'timestamp': datetime.now().isoformat(),
                'modules_run': modules_to_run,
                'overall_score': overall_score,
                'version': self.config.get('general.version', '1.0.0')
            },
            'module_results': results,
            'summary': self._generate_summary(results, overall_score)
        }
        
        # Output results
        self._output_results(report_data, output_format, output_file, summary_only)
        
        return report_data
    
    def _generate_summary(self, results: Dict[str, Any], overall_score: float) -> Dict[str, Any]:
        """Generate audit summary."""
        summary = {
            'overall_grade': self.scoring_engine.get_grade(overall_score),
            'total_modules': len(results),
            'passed_modules': sum(1 for r in results.values() 
                                if r.get('status') == 'success' and r.get('score', 0) >= 70),
            'failed_modules': sum(1 for r in results.values() 
                                if r.get('status') == 'success' and r.get('score', 0) < 70),
            'error_modules': sum(1 for r in results.values() 
                               if r.get('status') == 'error'),
            'recommendations': self._generate_recommendations(results)
        }
        
        return summary
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on audit results."""
        recommendations = []
        
        for module_name, result in results.items():
            if result.get('status') == 'success':
                issues = result.get('issues', [])
                for issue in issues:
                    if issue.get('severity') in ['high', 'critical']:
                        recommendations.append(f"{module_name}: {issue.get('description', '')}")
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def _output_results(self, report_data: Dict[str, Any], output_format: str, 
                       output_file: Optional[str], summary_only: bool):
        """Output audit results in specified format."""
        if summary_only:
            output_data = {
                'audit_metadata': report_data['audit_metadata'],
                'summary': report_data['summary']
            }
        else:
            output_data = report_data
        
        # Generate output
        if output_format.lower() == 'json':
            output_content = self.report_generator.generate_json_report(output_data)
        elif output_format.lower() == 'yaml':
            output_content = self.report_generator.generate_yaml_report(output_data)
        elif output_format.lower() == 'html':
            output_content = self.report_generator.generate_html_report(output_data)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        # Write to file or stdout
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output_content)
            self.logger.info(f"Report written to {output_file}")
        else:
            print(output_content)

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Linux Server Security Auditor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --modules system_info,network_security --output audit.json
  %(prog)s --all --format html --output /tmp/audit_report.html
  %(prog)s --summary --verbose
        """
    )
    
    # Module selection
    module_group = parser.add_mutually_exclusive_group()
    module_group.add_argument(
        '--modules', 
        help='Comma-separated list of modules to run'
    )
    module_group.add_argument(
        '--all', 
        action='store_true', 
        help='Run all available modules (default)'
    )
    
    # Output options
    parser.add_argument(
        '--output', 
        '-o',
        help='Output file path (default: stdout)'
    )
    parser.add_argument(
        '--format', 
        '-f',
        choices=['json', 'yaml', 'html'],
        default='json',
        help='Output format (default: json)'
    )
    parser.add_argument(
        '--summary', 
        action='store_true',
        help='Show only summary information'
    )
    
    # Configuration and verbosity
    parser.add_argument(
        '--config',
        help='Path to configuration file'
    )
    parser.add_argument(
        '--verbose', 
        '-v',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='Linux Server Auditor 1.0.0'
    )
    
    return parser.parse_args()

def main():
    """Main entry point."""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Create auditor instance
        auditor = LinuxServerAuditor(config_path=args.config)
        
        # Set verbose mode if requested
        if args.verbose:
            auditor.config.set('general.verbose', True)
        
        # Determine modules to run
        selected_modules = None
        if args.modules:
            selected_modules = args.modules.split(',')
        
        # Run audit
        results = auditor.run_audit(
            selected_modules=selected_modules,
            output_format=args.format,
            output_file=args.output,
            summary_only=args.summary
        )
        
        # Exit with appropriate code
        if results:
            print("\nAudit completed successfully!")
            sys.exit(0)
        else:
            print("\nAudit failed!")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nAudit interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()