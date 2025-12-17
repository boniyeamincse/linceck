# Module Interface Specifications

## Overview

This document provides detailed interface specifications for all audit modules in the Linux Server Auditor Tool. Each module implements a standardized interface while providing specialized auditing capabilities.

## Base Module Interface

### AuditModule Abstract Base Class

```python
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class CheckResult:
    """Result of a single audit check"""
    check_id: str
    description: str
    status: str  # 'pass', 'fail', 'warning', 'na'
    score: float  # 0.0 to 1.0
    severity: str  # 'low', 'medium', 'high', 'critical'
    evidence: str = ""
    recommendation: str = ""
    timestamp: datetime = None
    compliance_refs: List[str] = None  # NIST control references

@dataclass
class ModuleResult:
    """Result of a module audit"""
    module_name: str
    module_version: str
    status: str  # 'success', 'partial', 'failed'
    total_checks: int
    passed_checks: int
    failed_checks: int
    score: float  # 0.0 to 100.0
    grade: str  # 'A', 'B', 'C', 'D', 'F'
    checks: List[CheckResult]
    duration: float  # execution time in seconds
    error_message: Optional[str] = None

class AuditModule(ABC):
    """Abstract base class for all audit modules"""
    
    @abstractmethod
    def get_name(self) -> str:
        """Return the module name"""
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """Return a brief description of the module"""
        pass
    
    @abstractmethod
    def get_version(self) -> str:
        """Return the module version"""
        pass
    
    @abstractmethod
    def get_dependencies(self) -> List[str]:
        """Return list of required system dependencies"""
        pass
    
    @abstractmethod
    def is_compatible(self) -> bool:
        """Check if module is compatible with current platform"""
        pass
    
    @abstractmethod
    def execute(self, config: Dict[str, Any]) -> ModuleResult:
        """Execute the audit and return results"""
        pass
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return module metadata"""
        return {
            'name': self.get_name(),
            'description': self.get_description(),
            'version': self.get_version(),
            'dependencies': self.get_dependencies(),
            'compatible': self.is_compatible()
        }
```

## Module Specifications

### 1. System Module

**Module Name**: `system`  
**Purpose**: Audit system-level configurations and security settings

#### Interface Implementation

```python
class SystemModule(AuditModule):
    def get_name(self) -> str:
        return "system"
    
    def get_description(self) -> str:
        return "Audits system-level configurations, kernel security, and OS settings"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def get_dependencies(self) -> List[str]:
        return ["uname", "uptime", "free", "df", "cat"]
    
    def is_compatible(self) -> bool:
        return platform.system().lower() == 'linux'
    
    def execute(self, config: Dict[str, Any]) -> ModuleResult:
        start_time = time.time()
        checks = []
        
        try:
            # Check 1: Kernel Version and Security
            checks.append(self._check_kernel_security())
            
            # Check 2: System Updates
            checks.append(self._check_system_updates())
            
            # Check 3: Resource Usage
            checks.append(self._check_resource_usage())
            
            # Check 4: Boot Configuration
            checks.append(self._check_boot_security())
            
            # Calculate results
            total_checks = len(checks)
            passed_checks = sum(1 for c in checks if c.status == 'pass')
            score = (passed_checks / total_checks) * 100 if total_checks > 0 else 0
            grade = self._calculate_grade(score)
            
            duration = time.time() - start_time
            
            return ModuleResult(
                module_name=self.get_name(),
                module_version=self.get_version(),
                status="success",
                total_checks=total_checks,
                passed_checks=passed_checks,
                failed_checks=total_checks - passed_checks,
                score=score,
                grade=grade,
                checks=checks,
                duration=duration
            )
            
        except Exception as e:
            return ModuleResult(
                module_name=self.get_name(),
                module_version=self.get_version(),
                status="failed",
                total_checks=0,
                passed_checks=0,
                failed_checks=0,
                score=0.0,
                grade="F",
                checks=[],
                duration=time.time() - start_time,
                error_message=str(e)
            )
```

#### Check Implementations

```python
def _check_kernel_security(self) -> CheckResult:
    """Check kernel version and security patches"""
    try:
        kernel_version = platform.release()
        
        # Check if kernel is up to date (example logic)
        is_secure = self._is_kernel_secure(kernel_version)
        
        if is_secure:
            status = "pass"
            score = 1.0
            evidence = f"Kernel version {kernel_version} is secure"
        else:
            status = "fail"
            score = 0.0
            evidence = f"Kernel version {kernel_version} may have vulnerabilities"
        
        return CheckResult(
            check_id="SYS-001",
            description="Kernel security and version check",
            status=status,
            score=score,
            severity="high",
            evidence=evidence,
            recommendation="Update kernel to latest secure version",
            compliance_refs=["NIST-AC-6", "NIST-SI-2"]
        )
    except Exception as e:
        return CheckResult(
            check_id="SYS-001",
            description="Kernel security and version check",
            status="failed",
            score=0.0,
            severity="high",
            evidence=f"Error checking kernel: {str(e)}",
            recommendation="Manual kernel security assessment required"
        )

def _check_system_updates(self) -> CheckResult:
    """Check for available system updates"""
    try:
        # Check package manager for updates
        update_count = self._get_pending_updates()
        
        if update_count == 0:
            status = "pass"
            score = 1.0
            evidence = "No pending security updates found"
        elif update_count <= 5:
            status = "warning"
            score = 0.5
            evidence = f"{update_count} updates pending"
        else:
            status = "fail"
            score = 0.0
            evidence = f"{update_count} updates pending, including security updates"
        
        return CheckResult(
            check_id="SYS-002",
            description="System update status",
            status=status,
            score=score,
            severity="high",
            evidence=evidence,
            recommendation="Apply pending security updates",
            compliance_refs=["NIST-SI-2"]
        )
    except Exception as e:
        return CheckResult(
            check_id="SYS-002",
            description="System update status",
            status="warning",
            score=0.5,
            severity="medium",
            evidence=f"Could not determine update status: {str(e)}",
            recommendation="Manual update status verification required"
        )
```

### 2. Users Module

**Module Name**: `users`  
**Purpose**: Audit user account management and authentication security

#### Key Interface Methods

```python
class UsersModule(AuditModule):
    def execute(self, config: Dict[str, Any]) -> ModuleResult:
        checks = [
            self._check_password_policy(),
            self._check_inactive_accounts(),
            self._check_sudo_configuration(),
            self._check_default_accounts(),
            self._check_user_groups(),
            self._check_account_lockout()
        ]
        # ... result processing
```

#### Critical Checks

```python
def _check_password_policy(self) -> CheckResult:
    """Validate password policy compliance"""
    # Check /etc/login.defs, PAM configuration
    # Validate minimum length, complexity, expiration

def _check_inactive_accounts(self) -> CheckResult:
    """Detect inactive and unused accounts"""
    # Check last login times, account expiration
    # Identify service accounts with interactive shells

def _check_sudo_configuration(self) -> CheckResult:
    """Audit sudoers file and privilege escalation"""
    # Parse /etc/sudoers and /etc/sudoers.d/
    # Check for overly permissive rules
```

### 3. Files Module

**Module Name**: `files`  
**Purpose**: Audit file system permissions and integrity

#### Key Interface Methods

```python
class FilesModule(AuditModule):
    def execute(self, config: Dict[str, Any]) -> ModuleResult:
        checks = [
            self._check_critical_file_permissions(),
            self._check_world_writable_files(),
            self._check_suid_sgid_files(),
            self._check_filesystem_mount_options(),
            self._check_log_file_protection()
        ]
        # ... result processing
```

#### Critical Checks

```python
def _check_critical_file_permissions(self) -> CheckResult:
    """Check permissions on critical system files"""
    critical_files = [
        '/etc/passwd', '/etc/shadow', '/etc/sudoers',
        '/etc/ssh/sshd_config', '/etc/hosts'
    ]
    # Validate ownership and permissions

def _check_world_writable_files(self) -> CheckResult:
    """Detect world-writable files in sensitive locations"""
    # Search for files with 777, 666 permissions
    # Focus on /tmp, /var/tmp, user directories

def _check_suid_sgid_files(self) -> CheckResult:
    """Audit SUID/SGID files for security risks"""
    # Find all SUID/SGID files
    # Compare against known safe list
    # Flag unusual or dangerous binaries
```

### 4. Services Module

**Module Name**: `services`  
**Purpose**: Audit running services and their configurations

#### Key Interface Methods

```python
class ServicesModule(AuditModule):
    def execute(self, config: Dict[str, Any]) -> ModuleResult:
        checks = [
            self._check_running_services(),
            self._check_service_configurations(),
            self._check_unnecessary_services(),
            self._check_service_dependencies(),
            self._check_service_autostart()
        ]
        # ... result processing
```

#### Critical Checks

```python
def _check_running_services(self) -> CheckResult:
    """Enumerate and analyze running services"""
    # Use systemctl, service, or ps commands
    # Categorize services by necessity and risk
    # Check for unexpected or malicious services

def _check_service_configurations(self) -> CheckResult:
    """Validate service configuration security"""
    # Check service file permissions
    # Validate configuration parameters
    # Check for insecure defaults

def _check_unnecessary_services(self) -> CheckResult:
    """Identify services that should be disabled"""
    # Check for legacy services (telnet, rsh, rlogin)
    # Identify development/test services
    # Flag services not needed for system role
```

### 5. Network Module

**Module Name**: `network`  
**Purpose**: Audit network configuration and security

#### Key Interface Methods

```python
class NetworkModule(AuditModule):
    def execute(self, config: Dict[str, Any]) -> ModuleResult:
        checks = [
            self._check_network_interfaces(),
            self._check_firewall_configuration(),
            self._check_network_services(),
            self._check_dns_configuration(),
            self._check_network_encryption()
        ]
        # ... result processing
```

#### Critical Checks

```python
def _check_firewall_configuration(self) -> CheckResult:
    """Audit firewall rules and configuration"""
    # Check iptables, firewalld, ufw status
    # Analyze rule sets for security
    # Check for open ports and services

def _check_network_services(self) -> CheckResult:
    """Audit network-facing services"""
    # Check listening ports and associated services
    # Validate service configurations
    # Check for insecure protocols

def _check_network_encryption(self) -> CheckResult:
    """Verify encryption in network communications"""
    # Check for use of TLS/SSL
    # Validate certificate configurations
    # Check for plaintext protocols
```

### 6. Security Module

**Module Name**: `security`  
**Purpose**: Audit security frameworks and controls

#### Key Interface Methods

```python
class SecurityModule(AuditModule):
    def execute(self, config: Dict[str, Any]) -> ModuleResult:
        checks = [
            self._check_selinux_apparmor(),
            self._check_audit_configuration(),
            self._check_intrusion_detection(),
            self._check_security_patches(),
            self._check_vulnerability_scanning()
        ]
        # ... result processing
```

#### Critical Checks

```python
def _check_selinux_apparmor(self) -> CheckResult:
    """Audit mandatory access control systems"""
    # Check SELinux/AppArmor status and configuration
    # Validate policy enforcement
    # Check for permissive modes

def _check_audit_configuration(self) -> CheckResult:
    """Audit system auditing configuration"""
    # Check auditd service status
    # Validate audit rules
    # Check log file protection

def _check_intrusion_detection(self) -> CheckResult:
    """Check intrusion detection systems"""
    # Check fail2ban, OSSEC, or similar tools
    # Validate configuration and rules
    # Check for active threats
```

### 7. Logs Module

**Module Name**: `logs`  
**Purpose**: Audit logging configuration and management

#### Key Interface Methods

```python
class LogsModule(AuditModule):
    def execute(self, config: Dict[str, Any]) -> ModuleResult:
        checks = [
            self._check_log_configuration(),
            self._check_log_file_permissions(),
            self._check_log_rotation(),
            self._check_log_integrity(),
            self._check_centralized_logging()
        ]
        # ... result processing
```

#### Critical Checks

```python
def _check_log_configuration(self) -> CheckResult:
    """Audit logging system configuration"""
    # Check rsyslog/syslog-ng configuration
    # Validate log levels and facilities
    # Check log destination configuration

def _check_log_rotation(self) -> CheckResult:
    """Verify log rotation is properly configured"""
    # Check logrotate configuration
    # Validate rotation schedules
    # Check disk space management

def _check_log_integrity(self) -> CheckResult:
    """Check log file integrity and protection"""
    # Verify log file permissions
    # Check for log tampering protection
    # Validate log signing/verification
```

### 8. Cron Module

**Module Name**: `cron`  
**Purpose**: Audit scheduled task security

#### Key Interface Methods

```python
class CronModule(AuditModule):
    def execute(self, config: Dict[str, Any]) -> ModuleResult:
        checks = [
            self._check_cron_jobs(),
            self._check_cron_permissions(),
            self._check_anacron_configuration(),
            self._check_scheduled_task_security()
        ]
        # ... result processing
```

#### Critical Checks

```python
def _check_cron_jobs(self) -> CheckResult:
    """Audit cron job configurations"""
    # Check /etc/crontab, /etc/cron.d/
    # Check user crontabs
    # Validate script locations and permissions

def _check_cron_permissions(self) -> CheckResult:
    """Verify cron file permissions"""
    # Check /etc/cron.allow, /etc/cron.deny
    # Validate crontab file ownership
    # Check for unauthorized access

def _check_scheduled_task_security(self) -> CheckResult:
    """Check for security issues in scheduled tasks"""
    # Look for suspicious commands
    # Check for privilege escalation
    # Validate task execution context
```

### 9. SSH Module

**Module Name**: `ssh`  
**Purpose**: Audit SSH configuration and security

#### Key Interface Methods

```python
class SSHModule(AuditModule):
    def execute(self, config: Dict[str, Any]) -> ModuleResult:
        checks = [
            self._check_ssh_configuration(),
            self._check_ssh_authentication(),
            self._check_ssh_encryption(),
            self._check_ssh_access_control(),
            self._check_ssh_key_management()
        ]
        # ... result processing
```

#### Critical Checks

```python
def _check_ssh_configuration(self) -> CheckResult:
    """Audit SSH daemon configuration"""
    # Check /etc/ssh/sshd_config
    # Validate protocol version
    # Check for insecure options

def _check_ssh_authentication(self) -> CheckResult:
    """Verify SSH authentication security"""
    # Check authentication methods
    # Validate key-based auth setup
    # Check for password authentication risks

def _check_ssh_access_control(self) -> CheckResult:
    """Audit SSH access controls"""
    # Check allowed users/groups
    # Validate source address restrictions
    # Check port configuration
```

## Module Configuration Interface

### Configuration Schema

```python
class ModuleConfig:
    """Configuration structure for audit modules"""
    
    def __init__(self, module_name: str, config_data: Dict[str, Any]):
        self.module_name = module_name
        self.enabled = config_data.get('enabled', True)
        self.timeout = config_data.get('timeout', 300)
        self.severity_filter = config_data.get('severity_filter', 'all')
        self.checks_enabled = config_data.get('checks_enabled', [])
        self.checks_disabled = config_data.get('checks_disabled', [])
        self.parameters = config_data.get('parameters', {})
    
    def is_check_enabled(self, check_id: str) -> bool:
        """Check if a specific check is enabled"""
        if self.checks_enabled and check_id not in self.checks_enabled:
            return False
        if self.checks_disabled and check_id in self.checks_disabled:
            return False
        return True
    
    def get_parameter(self, key: str, default: Any = None) -> Any:
        """Get a module-specific parameter"""
        return self.parameters.get(key, default)
```

### Example Module Configuration

```json
{
  "system": {
    "enabled": true,
    "timeout": 300,
    "severity_filter": "medium,high,critical",
    "checks_enabled": ["SYS-001", "SYS-002"],
    "parameters": {
      "max_kernel_age_days": 180,
      "min_update_severity": "medium"
    }
  },
  "users": {
    "enabled": true,
    "timeout": 180,
    "checks_disabled": ["USR-005"],
    "parameters": {
      "max_password_age_days": 90,
      "min_password_length": 12,
      "allowed_shell_types": ["/bin/bash", "/bin/sh"]
    }
  }
}
```

## Module Execution Flow

### Standard Execution Pattern

```python
def execute_module(module: AuditModule, config: ModuleConfig) -> ModuleResult:
    """Execute a module with proper error handling and timing"""
    
    if not module.is_compatible():
        return ModuleResult(
            module_name=module.get_name(),
            module_version=module.get_version(),
            status="failed",
            total_checks=0,
            passed_checks=0,
            failed_checks=0,
            score=0.0,
            grade="F",
            checks=[],
            duration=0.0,
            error_message="Module not compatible with current platform"
        )
    
    start_time = time.time()
    
    try:
        # Execute module with timeout
        result = module.execute(config.parameters)
        result.duration = time.time() - start_time
        return result
        
    except Exception as e:
        return ModuleResult(
            module_name=module.get_name(),
            module_version=module.get_version(),
            status="failed",
            total_checks=0,
            passed_checks=0,
            failed_checks=0,
            score=0.0,
            grade="F",
            checks=[],
            duration=time.time() - start_time,
            error_message=str(e)
        )
```

### Module Result Aggregation

```python
class ModuleAggregator:
    """Aggregate results from multiple modules"""
    
    def aggregate_results(self, results: List[ModuleResult]) -> Dict[str, Any]:
        """Aggregate module results into overall audit report"""
        
        total_modules = len(results)
        successful_modules = sum(1 for r in results if r.status == "success")
        failed_modules = total_modules - successful_modules
        
        # Calculate weighted average score
        weighted_score = self._calculate_weighted_score(results)
        overall_grade = self._calculate_overall_grade(weighted_score)
        
        # Aggregate check results
        all_checks = []
        for result in results:
            all_checks.extend(result.checks)
        
        total_checks = sum(r.total_checks for r in results)
        passed_checks = sum(r.passed_checks for r in results)
        
        return {
            'audit_summary': {
                'total_modules': total_modules,
                'successful_modules': successful_modules,
                'failed_modules': failed_modules,
                'overall_score': weighted_score,
                'overall_grade': overall_grade
            },
            'module_results': results,
            'aggregated_checks': all_checks,
            'statistics': {
                'total_checks': total_checks,
                'passed_checks': passed_checks,
                'failed_checks': total_checks - passed_checks,
                'success_rate': (passed_checks / total_checks) * 100 if total_checks > 0 else 0
            }
        }
```

This comprehensive interface specification ensures that all modules follow consistent patterns while providing specialized auditing capabilities for their respective domains.