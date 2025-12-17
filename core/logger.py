"""
Centralized Logging System for Linux Server Auditor

This module provides a centralized logging system with support for multiple log levels,
file rotation, structured logging, and customizable formatting.
"""

import logging
import logging.handlers
import sys
import os
import json
import yaml
from typing import Optional, Dict, Any, Union
from pathlib import Path
from datetime import datetime
import traceback

class StructuredFormatter(logging.Formatter):
    """
    Custom formatter that outputs structured logs in JSON format.
    """
    
    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None, 
                 style: str = '%', use_json: bool = False):
        """
        Initialize the formatter.
        
        Args:
            fmt: Log format string
            datefmt: Date format string
            style: Format style ('%', '{', or '$')
            use_json: Whether to output JSON format
        """
        super().__init__(fmt, datefmt, style)
        self.use_json = use_json
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record.
        
        Args:
            record: Log record to format
            
        Returns:
            Formatted log string
        """
        if self.use_json:
            return self._format_json(record)
        else:
            return super().format(record)
    
    def _format_json(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.
        
        Args:
            record: Log record to format
            
        Returns:
            JSON formatted log string
        """
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add extra fields if present
        if hasattr(record, 'module_name'):
            log_data['module_name'] = record.module_name
        
        if hasattr(record, 'audit_id'):
            log_data['audit_id'] = record.audit_id
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Add stack info if present
        if record.stack_info:
            log_data['stack_info'] = record.stack_info
        
        return json.dumps(log_data, ensure_ascii=False)

class AuditLoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter that adds audit context to log records.
    """
    
    def __init__(self, logger: logging.Logger, audit_id: Optional[str] = None):
        """
        Initialize the adapter.
        
        Args:
            logger: Base logger
            audit_id: Audit session ID
        """
        super().__init__(logger, {})
        self.audit_id = audit_id
    
    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """
        Process the log message with audit context.
        
        Args:
            msg: Log message
            kwargs: Log keyword arguments
            
        Returns:
            Tuple of (processed message, updated kwargs)
        """
        extra = kwargs.setdefault('extra', {})
        if self.audit_id:
            extra['audit_id'] = self.audit_id
        
        return msg, kwargs

class LoggerManager:
    """
    Centralized logging manager for the Linux Server Auditor.
    
    Provides:
    - Multiple log levels and handlers
    - File rotation based on size and time
    - Structured logging support
    - Audit session tracking
    - Performance metrics logging
    """
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if LoggerManager._initialized:
            return
        
        self.loggers: Dict[str, logging.Logger] = {}
        self.adapters: Dict[str, AuditLoggerAdapter] = {}
        self.config: Dict[str, Any] = {}
        
        LoggerManager._initialized = True
    
    def setup(self, config: Dict[str, Any]):
        """
        Setup the logging system with configuration.
        
        Args:
            config: Logging configuration dictionary
        """
        self.config = config
        self._configure_logging()
    
    def _configure_logging(self):
        """Configure the logging system based on configuration."""
        # Clear existing handlers
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Set root logger level
        level = getattr(logging, self.config.get('level', 'INFO').upper())
        root_logger.setLevel(level)
        
        # Create formatter
        use_json = self.config.get('format_type', 'text').lower() == 'json'
        formatter = StructuredFormatter(
            fmt=self.config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
            datefmt=self.config.get('date_format', '%Y-%m-%d %H:%M:%S'),
            use_json=use_json
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(level)
        root_logger.addHandler(console_handler)
        
        # File handler with rotation
        log_file = self.config.get('file')
        if log_file:
            log_file = Path(log_file).expanduser()
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            max_size = self.config.get('max_file_size', 10485760)  # 10MB
            backup_count = self.config.get('backup_count', 5)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(level)
            root_logger.addHandler(file_handler)
        
        # Audit log handler
        audit_log_file = self.config.get('audit_file')
        if audit_log_file:
            audit_log_file = Path(audit_log_file).expanduser()
            audit_log_file.parent.mkdir(parents=True, exist_ok=True)
            
            audit_handler = logging.handlers.RotatingFileHandler(
                audit_log_file,
                maxBytes=self.config.get('audit_max_file_size', 52428800),  # 50MB
                backupCount=self.config.get('audit_backup_count', 10),
                encoding='utf-8'
            )
            audit_formatter = StructuredFormatter(use_json=True)
            audit_handler.setFormatter(audit_formatter)
            audit_handler.setLevel(logging.INFO)
            
            audit_logger = logging.getLogger('audit')
            audit_logger.addHandler(audit_handler)
            audit_logger.setLevel(logging.INFO)
            audit_logger.propagate = False
    
    def get_logger(self, name: str) -> logging.Logger:
        """
        Get a logger instance.
        
        Args:
            name: Logger name
            
        Returns:
            Logger instance
        """
        if name not in self.loggers:
            self.loggers[name] = logging.getLogger(name)
        
        return self.loggers[name]
    
    def get_audit_logger(self, audit_id: Optional[str] = None) -> AuditLoggerAdapter:
        """
        Get an audit logger adapter.
        
        Args:
            audit_id: Audit session ID
            
        Returns:
            Audit logger adapter
        """
        key = audit_id or 'default'
        
        if key not in self.adapters:
            base_logger = logging.getLogger('audit')
            self.adapters[key] = AuditLoggerAdapter(base_logger, audit_id)
        
        return self.adapters[key]
    
    def log_audit_event(self, event_type: str, module: str, message: str, 
                       audit_id: Optional[str] = None, **kwargs):
        """
        Log an audit event.
        
        Args:
            event_type: Type of audit event
            module: Module name
            message: Event message
            audit_id: Audit session ID
            **kwargs: Additional event data
        """
        audit_logger = self.get_audit_logger(audit_id)
        
        event_data = {
            'event_type': event_type,
            'module': module,
            'message': message,
            **kwargs
        }
        
        audit_logger.info(f"Audit Event: {json.dumps(event_data, ensure_ascii=False)}")
    
    def log_performance_metric(self, metric_name: str, value: Union[int, float], 
                              unit: str = '', audit_id: Optional[str] = None, **kwargs):
        """
        Log a performance metric.
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            unit: Unit of measurement
            audit_id: Audit session ID
            **kwargs: Additional metric data
        """
        audit_logger = self.get_audit_logger(audit_id)
        
        metric_data = {
            'metric_name': metric_name,
            'value': value,
            'unit': unit,
            **kwargs
        }
        
        audit_logger.info(f"Performance Metric: {json.dumps(metric_data, ensure_ascii=False)}")
    
    def log_security_event(self, severity: str, event_type: str, description: str,
                          audit_id: Optional[str] = None, **kwargs):
        """
        Log a security event.
        
        Args:
            severity: Event severity level
            event_type: Type of security event
            description: Event description
            audit_id: Audit session ID
            **kwargs: Additional event data
        """
        audit_logger = self.get_audit_logger(audit_id)
        
        security_data = {
            'severity': severity,
            'event_type': event_type,
            'description': description,
            **kwargs
        }
        
        level = getattr(logging, severity.upper(), logging.WARNING)
        audit_logger.log(level, f"Security Event: {json.dumps(security_data, ensure_ascii=False)}")
    
    def log_module_result(self, module_name: str, result: Dict[str, Any], 
                         audit_id: Optional[str] = None):
        """
        Log module execution result.
        
        Args:
            module_name: Name of the module
            result: Module result dictionary
            audit_id: Audit session ID
        """
        audit_logger = self.get_audit_logger(audit_id)
        
        result_data = {
            'module_name': module_name,
            'result': result
        }
        
        audit_logger.info(f"Module Result: {json.dumps(result_data, ensure_ascii=False)}")
    
    def log_error_details(self, error: Exception, context: str = '', 
                         audit_id: Optional[str] = None):
        """
        Log detailed error information.
        
        Args:
            error: Exception object
            context: Error context
            audit_id: Audit session ID
        """
        audit_logger = self.get_audit_logger(audit_id)
        
        error_data = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context,
            'traceback': traceback.format_exc()
        }
        
        audit_logger.error(f"Error Details: {json.dumps(error_data, ensure_ascii=False)}")

def setup_logging(level: str = 'INFO', log_file: Optional[str] = None, 
                 verbose: bool = False, format_type: str = 'text'):
    """
    Setup centralized logging.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file
        verbose: Enable verbose logging
        format_type: Output format ('text' or 'json')
    """
    # Configure logging
    config = {
        'level': level if not verbose else 'DEBUG',
        'file': log_file,
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'date_format': '%Y-%m-%d %H:%M:%S',
        'format_type': format_type,
        'max_file_size': 10485760,  # 10MB
        'backup_count': 5,
        'audit_file': None,
        'audit_max_file_size': 52428800,  # 50MB
        'audit_backup_count': 10
    }
    
    # Setup audit log file if environment variable is set
    audit_log_env = os.environ.get('AUDITOR_AUDIT_LOG')
    if audit_log_env:
        config['audit_file'] = audit_log_env
    
    # Initialize logger manager
    logger_manager = LoggerManager()
    logger_manager.setup(config)
    
    # Log setup completion
    logger = logger_manager.get_logger(__name__)
    logger.info(f"Logging initialized - Level: {config['level']}, File: {log_file}, Format: {format_type}")

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    logger_manager = LoggerManager()
    return logger_manager.get_logger(name)

def get_audit_logger(audit_id: Optional[str] = None) -> AuditLoggerAdapter:
    """
    Get an audit logger adapter.
    
    Args:
        audit_id: Audit session ID
        
    Returns:
        Audit logger adapter
    """
    logger_manager = LoggerManager()
    return logger_manager.get_audit_logger(audit_id)