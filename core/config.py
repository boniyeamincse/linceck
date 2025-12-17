"""
Configuration Management System for Linux Server Auditor

This module provides centralized configuration management with support for
multiple configuration sources, validation, and dynamic updates.
"""

import os
import json
import yaml
import logging
from typing import Any, Dict, Optional, Union, List
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

class ConfigSource(Enum):
    """Configuration source types."""
    DEFAULT = "default"
    FILE = "file"
    ENVIRONMENT = "environment"
    COMMAND_LINE = "command_line"

@dataclass
class ConfigValidation:
    """Configuration validation rules."""
    required: bool = False
    type: Optional[type] = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    allowed_values: Optional[List[Any]] = None
    pattern: Optional[str] = None

class ConfigManager:
    """
    Centralized configuration management system.
    
    Supports multiple configuration sources with priority:
    1. Command line arguments
    2. Environment variables
    3. Configuration files
    4. Default values
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Path to configuration file
        """
        self.logger = logging.getLogger(__name__)
        self._config = {}
        self._sources = {}
        self._validations = {}
        
        # Load configuration
        self._load_default_config()
        self._load_file_config(config_path)
        self._load_environment_config()
        
        self.logger.info("Configuration manager initialized")
    
    def _load_default_config(self):
        """Load default configuration values."""
        default_config = {
            # General settings
            'general': {
                'version': '1.0.0',
                'verbose': False,
                'timeout': 30,
                'max_concurrent_modules': 4
            },
            
            # Logging configuration
            'logging': {
                'level': 'INFO',
                'file': None,
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'max_file_size': 10485760,  # 10MB
                'backup_count': 5
            },
            
            # Scoring configuration
            'scoring': {
                'weight_system_info': 5.0,
                'weight_network_security': 15.0,
                'weight_user_management': 12.0,
                'weight_service_management': 10.0,
                'weight_file_permissions': 12.0,
                'weight_logging_monitoring': 8.0,
                'weight_firewall_config': 10.0,
                'weight_package_management': 8.0,
                'weight_disk_security': 10.0,
                'weight_kernel_security': 10.0,
                'severity_weights': {
                    'low': 1.0,
                    'medium': 3.0,
                    'high': 5.0,
                    'critical': 10.0
                },
                'grade_thresholds': {
                    'A': 90.0,
                    'B': 80.0,
                    'C': 70.0,
                    'D': 60.0,
                    'F': 0.0
                }
            },
            
            # Module configuration
            'modules': {
                'enabled': True,
                'timeout': 60,
                'retry_attempts': 2,
                'skip_on_error': False
            },
            
            # Output configuration
            'output': {
                'default_format': 'json',
                'formats': ['json', 'yaml', 'html'],
                'include_metadata': True,
                'include_timestamps': True,
                'compress_large_outputs': True
            },
            
            # Security thresholds
            'security': {
                'max_failed_login_attempts': 5,
                'password_min_length': 8,
                'password_min_complexity': 3,
                'max_file_permissions': 644,
                'max_directory_permissions': 755,
                'critical_services': ['sshd', 'httpd', 'nginx'],
                'required_packages': ['fail2ban', 'auditd', 'firewalld']
            }
        }
        
        self._set_config_recursive(default_config, ConfigSource.DEFAULT)
        self.logger.debug("Loaded default configuration")
    
    def _load_file_config(self, config_path: Optional[str]):
        """Load configuration from file."""
        if not config_path:
            # Try default locations
            default_paths = [
                'config.yaml',
                'config.yml',
                'config.json',
                '/etc/linux-auditor/config.yaml',
                '~/.config/linux-auditor/config.yaml'
            ]
            
            for path in default_paths:
                try:
                    resolved_path = Path(path).expanduser()
                    if resolved_path.exists():
                        config_path = str(resolved_path)
                        break
                except Exception:
                    continue
        
        if not config_path:
            self.logger.debug("No configuration file found, using defaults")
            return
        
        try:
            config_path = Path(config_path).expanduser()
            if not config_path.exists():
                self.logger.warning(f"Configuration file not found: {config_path}")
                return
            
            with open(config_path, 'r') as f:
                if config_path.suffix.lower() in ['.yaml', '.yml']:
                    file_config = yaml.safe_load(f)
                elif config_path.suffix.lower() == '.json':
                    file_config = json.load(f)
                else:
                    self.logger.error(f"Unsupported configuration file format: {config_path}")
                    return
            
            if file_config:
                self._set_config_recursive(file_config, ConfigSource.FILE)
                self.logger.info(f"Loaded configuration from {config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration file {config_path}: {str(e)}")
    
    def _load_environment_config(self):
        """Load configuration from environment variables."""
        env_prefix = 'AUDITOR_'
        
        # Define environment variable mappings
        env_mappings = {
            f'{env_prefix}VERBOSE': ('general.verbose', bool),
            f'{env_prefix}LOG_LEVEL': ('logging.level', str),
            f'{env_prefix}TIMEOUT': ('general.timeout', int),
            f'{env_prefix}OUTPUT_FORMAT': ('output.default_format', str),
            f'{env_prefix}CONFIG_PATH': ('general.config_path', str)
        }
        
        for env_var, (config_key, value_type) in env_mappings.items():
            env_value = os.environ.get(env_var)
            if env_value is not None:
                try:
                    if value_type == bool:
                        parsed_value = env_value.lower() in ('true', '1', 'yes', 'on')
                    elif value_type == int:
                        parsed_value = int(env_value)
                    else:
                        parsed_value = env_value
                    
                    self.set(config_key, parsed_value, ConfigSource.ENVIRONMENT)
                    self.logger.debug(f"Loaded environment variable {env_var} -> {config_key} = {parsed_value}")
                    
                except ValueError as e:
                    self.logger.warning(f"Invalid value for {env_var}: {env_value} - {str(e)}")
    
    def _set_config_recursive(self, config_dict: Dict[str, Any], source: ConfigSource, prefix: str = ''):
        """Recursively set configuration values."""
        for key, value in config_dict.items():
            if isinstance(value, dict):
                nested_prefix = f"{prefix}.{key}" if prefix else key
                self._set_config_recursive(value, source, nested_prefix)
            else:
                config_key = f"{prefix}.{key}" if prefix else key
                self.set(config_key, value, source)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            key: Configuration key (dot notation supported)
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        try:
            value = self._get_recursive(self._config, key.split('.'))
            self.logger.debug(f"Retrieved config {key} = {value}")
            return value
        except KeyError:
            self.logger.debug(f"Config key {key} not found, returning default: {default}")
            return default
    
    def set(self, key: str, value: Any, source: ConfigSource = ConfigSource.COMMAND_LINE):
        """
        Set a configuration value.
        
        Args:
            key: Configuration key (dot notation supported)
            value: Configuration value
            source: Source of the configuration value
        """
        # Validate value if validation rules exist
        validation = self._validations.get(key)
        if validation:
            value = self._validate_value(key, value, validation)
        
        self._set_recursive(self._config, key.split('.'), value)
        self._sources[key] = source
        self.logger.debug(f"Set config {key} = {value} (source: {source.value})")
    
    def _get_recursive(self, config_dict: Dict[str, Any], keys: List[str]) -> Any:
        """Recursively get a value from nested dictionary."""
        if not keys:
            return config_dict
        
        key = keys[0]
        if key not in config_dict:
            raise KeyError(f"Configuration key not found: {'.'.join(keys)}")
        
        if len(keys) == 1:
            return config_dict[key]
        else:
            return self._get_recursive(config_dict[key], keys[1:])
    
    def _set_recursive(self, config_dict: Dict[str, Any], keys: List[str], value: Any):
        """Recursively set a value in nested dictionary."""
        key = keys[0]
        
        if len(keys) == 1:
            config_dict[key] = value
        else:
            if key not in config_dict:
                config_dict[key] = {}
            self._set_recursive(config_dict[key], keys[1:], value)
    
    def _validate_value(self, key: str, value: Any, validation: ConfigValidation) -> Any:
        """Validate a configuration value."""
        # Check required
        if validation.required and value is None:
            raise ValueError(f"Configuration key {key} is required but not provided")
        
        # Check type
        if validation.type and not isinstance(value, validation.type):
            if validation.type == bool and isinstance(value, str):
                value = value.lower() in ('true', '1', 'yes', 'on')
            elif validation.type in (int, float) and isinstance(value, str):
                try:
                    value = validation.type(value)
                except ValueError:
                    raise ValueError(f"Invalid value for {key}: {value} (expected {validation.type.__name__})")
            else:
                raise ValueError(f"Invalid type for {key}: {type(value).__name__} (expected {validation.type.__name__})")
        
        # Check min/max values
        if validation.min_value is not None and value < validation.min_value:
            raise ValueError(f"Value for {key} is below minimum: {validation.min_value}")
        
        if validation.max_value is not None and value > validation.max_value:
            raise ValueError(f"Value for {key} exceeds maximum: {validation.max_value}")
        
        # Check allowed values
        if validation.allowed_values and value not in validation.allowed_values:
            raise ValueError(f"Value for {key} not in allowed values: {validation.allowed_values}")
        
        return value
    
    def set_validation(self, key: str, validation: ConfigValidation):
        """
        Set validation rules for a configuration key.
        
        Args:
            key: Configuration key
            validation: ConfigValidation object with validation rules
        """
        self._validations[key] = validation
    
    def get_source(self, key: str) -> Optional[ConfigSource]:
        """
        Get the source of a configuration value.
        
        Args:
            key: Configuration key
            
        Returns:
            ConfigSource or None if key not found
        """
        return self._sources.get(key)
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values."""
        return self._config.copy()
    
    def merge(self, other_config: Dict[str, Any], source: ConfigSource = ConfigSource.COMMAND_LINE):
        """
        Merge configuration from a dictionary.
        
        Args:
            other_config: Dictionary with configuration values
            source: Source of the configuration values
        """
        self._set_config_recursive(other_config, source)
    
    def reset(self):
        """Reset configuration to defaults."""
        self._config = {}
        self._sources = {}
        self._validations = {}
        self._load_default_config()
        self.logger.info("Configuration reset to defaults")
    
    def save(self, file_path: str, format: str = 'yaml'):
        """
        Save current configuration to file.
        
        Args:
            file_path: Path to save file
            format: Output format ('yaml' or 'json')
        """
        try:
            file_path = Path(file_path).expanduser()
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w') as f:
                if format.lower() == 'yaml':
                    yaml.dump(self._config, f, default_flow_style=False, indent=2)
                elif format.lower() == 'json':
                    json.dump(self._config, f, indent=2)
                else:
                    raise ValueError(f"Unsupported format: {format}")
            
            self.logger.info(f"Configuration saved to {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {str(e)}")
            raise
    
    def get_module_config(self, module_name: str) -> Dict[str, Any]:
        """
        Get configuration specific to a module.
        
        Args:
            module_name: Name of the module
            
        Returns:
            Dictionary with module-specific configuration
        """
        module_config = {}
        prefix = f"modules.{module_name}."
        
        for key in self._config:
            if key.startswith(prefix):
                module_key = key[len(prefix):]
                module_config[module_key] = self._config[key]
        
        return module_config
    
    def is_enabled(self, module_name: str) -> bool:
        """
        Check if a module is enabled.
        
        Args:
            module_name: Name of the module
            
        Returns:
            True if module is enabled, False otherwise
        """
        return self.get(f'modules.{module_name}.enabled', True)