"""
Shared Utility Functions for Linux Server Auditor

This module provides common utility functions used across all audit modules,
including system information gathering, file operations, command execution,
and security-related utilities.
"""

import os
import re
import pwd
import grp
import stat
import subprocess
import json
import yaml
import hashlib
import socket
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Union, Tuple
from pathlib import Path
from datetime import datetime, timedelta
import psutil
import platform
import shutil
import fnmatch
import tarfile
import gzip
import tempfile
import threading
from contextlib import contextmanager
import time

class SystemUtils:
    """System utility functions for gathering system information."""
    
    @staticmethod
    def get_os_info() -> Dict[str, str]:
        """
        Get operating system information.
        
        Returns:
            Dictionary with OS details
        """
        try:
            # Try to get distribution info
            distro_info = {}
            for path in ['/etc/os-release', '/usr/lib/os-release']:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        for line in f:
                            if '=' in line:
                                key, value = line.strip().split('=', 1)
                                # Remove quotes
                                value = value.strip('"\'')
                                distro_info[key] = value
                    break
            
            return {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'distribution': distro_info.get('PRETTY_NAME', distro_info.get('NAME', 'Unknown')),
                'distribution_id': distro_info.get('ID', 'unknown'),
                'distribution_version': distro_info.get('VERSION_ID', 'unknown')
            }
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to get OS info: {str(e)}")
            return {'error': str(e)}
    
    @staticmethod
    def get_kernel_version() -> str:
        """Get kernel version."""
        try:
            return platform.release()
        except Exception:
            return "Unknown"
    
    @staticmethod
    def is_virtual_machine() -> bool:
        """Check if running in a virtual machine."""
        try:
            # Check various VM indicators
            vm_indicators = [
                '/sys/class/dmi/id/product_name',
                '/sys/class/dmi/id/sys_vendor',
                '/proc/vz',
                '/proc/xen'
            ]
            
            for indicator in vm_indicators:
                if os.path.exists(indicator):
                    try:
                        with open(indicator, 'r') as f:
                            content = f.read().lower()
                            if any(vm in content for vm in ['vmware', 'virtualbox', 'qemu', 'kvm', 'xen', 'hyper-v']):
                                return True
                    except:
                        pass
            
            return False
        except Exception:
            return False
    
    @staticmethod
    def get_uptime() -> Dict[str, Any]:
        """Get system uptime information."""
        try:
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            
            return {
                'boot_time': boot_time.isoformat(),
                'uptime_seconds': int(uptime.total_seconds()),
                'uptime_human': str(uptime).split('.')[0]  # Remove microseconds
            }
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to get uptime: {str(e)}")
            return {'error': str(e)}

class FileUtils:
    """File and directory utility functions."""
    
    @staticmethod
    def get_file_permissions(file_path: str) -> Dict[str, Any]:
        """
        Get detailed file permissions.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with permission details
        """
        try:
            stat_info = os.stat(file_path)
            file_stat = stat.filemode(stat_info.st_mode)
            
            # Get owner and group
            try:
                owner = pwd.getpwuid(stat_info.st_uid).pw_name
            except:
                owner = str(stat_info.st_uid)
            
            try:
                group = grp.getgrgid(stat_info.st_gid).gr_name
            except:
                group = str(stat_info.st_gid)
            
            return {
                'permissions': file_stat,
                'numeric': oct(stat_info.st_mode)[-4:],
                'owner': owner,
                'group': group,
                'size': stat_info.st_size,
                'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat()
            }
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to get file permissions for {file_path}: {str(e)}")
            return {'error': str(e)}
    
    @staticmethod
    def find_files(pattern: str, path: str = '/', max_depth: Optional[int] = None) -> List[str]:
        """
        Find files matching a pattern.
        
        Args:
            pattern: Glob pattern to match
            path: Root directory to search
            max_depth: Maximum directory depth to search
            
        Returns:
            List of matching file paths
        """
        matches = []
        
        def _search(current_path: Path, current_depth: int):
            if max_depth is not None and current_depth > max_depth:
                return
            
            try:
                for item in current_path.iterdir():
                    if item.is_file() and fnmatch.fnmatch(item.name, pattern):
                        matches.append(str(item))
                    elif item.is_dir():
                        _search(item, current_depth + 1)
            except PermissionError:
                pass  # Skip directories we can't read
        
        _search(Path(path), 0)
        return matches
    
    @staticmethod
    def get_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """
        Calculate file hash.
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm ('md5', 'sha1', 'sha256', etc.)
            
        Returns:
            File hash as hex string, or None if failed
        """
        try:
            hash_func = getattr(hashlib, algorithm)()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to calculate hash for {file_path}: {str(e)}")
            return None
    
    @staticmethod
    def is_suid_file(file_path: str) -> bool:
        """Check if file has SUID bit set."""
        try:
            return bool(os.stat(file_path).st_mode & stat.S_ISUID)
        except:
            return False
    
    @staticmethod
    def is_writable_by_others(file_path: str) -> bool:
        """Check if file is writable by group or others."""
        try:
            mode = os.stat(file_path).st_mode
            return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))
        except:
            return False

class CommandUtils:
    """Command execution utilities."""
    
    @staticmethod
    def run_command(command: Union[str, List[str]], timeout: int = 30, 
                   capture_output: bool = True, shell: bool = False) -> Dict[str, Any]:
        """
        Run a system command with timeout.
        
        Args:
            command: Command to execute (string or list)
            timeout: Command timeout in seconds
            capture_output: Whether to capture stdout/stderr
            shell: Whether to run in shell mode
            
        Returns:
            Dictionary with execution results
        """
        try:
            if isinstance(command, str):
                if shell:
                    cmd = command
                else:
                    cmd = command.split()
            else:
                cmd = command
            
            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                shell=shell
            )
            
            return {
                'returncode': result.returncode,
                'stdout': result.stdout if capture_output else None,
                'stderr': result.stderr if capture_output else None,
                'success': result.returncode == 0
            }
            
        except subprocess.TimeoutExpired:
            return {
                'returncode': -1,
                'stdout': None,
                'stderr': f"Command timed out after {timeout} seconds",
                'success': False,
                'timeout': True
            }
        except Exception as e:
            return {
                'returncode': -1,
                'stdout': None,
                'stderr': str(e),
                'success': False,
                'error': str(e)
            }
    
    @staticmethod
    def check_command_exists(command: str) -> bool:
        """Check if a command exists in PATH."""
        return shutil.which(command) is not None
    
    @staticmethod
    def get_process_list() -> List[Dict[str, Any]]:
        """Get list of running processes."""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time']):
                try:
                    proc_info = proc.info
                    processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                        'username': proc_info['username'],
                        'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to get process list: {str(e)}")
        
        return processes

class NetworkUtils:
    """Network-related utility functions."""
    
    @staticmethod
    def get_network_interfaces() -> List[Dict[str, Any]]:
        """Get network interface information."""
        interfaces = []
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {'name': interface, 'addresses': []}
                
                for addr in addrs:
                    addr_info = {
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
                    interface_info['addresses'].append(addr_info)
                
                interfaces.append(interface_info)
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to get network interfaces: {str(e)}")
        
        return interfaces
    
    @staticmethod
    def get_listening_ports() -> List[Dict[str, Any]]:
        """Get list of listening ports."""
        ports = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    ports.append({
                        'port': conn.laddr.port,
                        'protocol': 'tcp' if conn.type == socket.SOCK_STREAM else 'udp',
                        'address': conn.laddr.ip,
                        'pid': conn.pid,
                        'process': psutil.Process(conn.pid).name() if conn.pid else None
                    })
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to get listening ports: {str(e)}")
        
        return ports
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP address is private."""
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False
    
    @staticmethod
    def resolve_hostname(hostname: str) -> List[str]:
        """Resolve hostname to IP addresses."""
        try:
            return socket.gethostbyname_ex(hostname)[2]
        except:
            return []

class SecurityUtils:
    """Security-related utility functions."""
    
    @staticmethod
    def check_password_policy(password: str, min_length: int = 8, 
                            min_complexity: int = 3) -> Dict[str, Any]:
        """
        Check password against policy.
        
        Args:
            password: Password to check
            min_length: Minimum password length
            min_complexity: Minimum character types (lower, upper, digit, special)
            
        Returns:
            Dictionary with policy check results
        """
        checks = {
            'length': len(password) >= min_length,
            'lowercase': any(c.islower() for c in password),
            'uppercase': any(c.isupper() for c in password),
            'digit': any(c.isdigit() for c in password),
            'special': any(not c.isalnum() for c in password)
        }
        
        complexity_count = sum(checks.values()) - 1  # Exclude length check
        
        return {
            'meets_length': checks['length'],
            'meets_complexity': complexity_count >= min_complexity,
            'complexity_count': complexity_count,
            'character_types': {
                'lowercase': checks['lowercase'],
                'uppercase': checks['uppercase'],
                'digit': checks['digit'],
                'special': checks['special']
            }
        }
    
    @staticmethod
    def get_user_info(username: str) -> Optional[Dict[str, Any]]:
        """Get user information."""
        try:
            user = pwd.getpwnam(username)
            return {
                'username': user.pw_name,
                'uid': user.pw_uid,
                'gid': user.pw_gid,
                'home': user.pw_dir,
                'shell': user.pw_shell,
                'gecos': user.pw_gecos
            }
        except KeyError:
            return None
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to get user info for {username}: {str(e)}")
            return None
    
    @staticmethod
    def get_group_members(groupname: str) -> List[str]:
        """Get members of a group."""
        try:
            group = grp.getgrnam(groupname)
            return group.gr_mem
        except KeyError:
            return []
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to get group members for {groupname}: {str(e)}")
            return []

class TimeUtils:
    """Time and date utility functions."""
    
    @staticmethod
    def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
        """Parse various timestamp formats."""
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S.%fZ'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        return None
    
    @staticmethod
    def get_time_range(hours: int = 24) -> Tuple[datetime, datetime]:
        """Get time range from now going back specified hours."""
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        return start_time, end_time

class ConfigUtils:
    """Configuration file parsing utilities."""
    
    @staticmethod
    def parse_config_file(file_path: str) -> Optional[Dict[str, Any]]:
        """Parse configuration file (JSON or YAML)."""
        try:
            with open(file_path, 'r') as f:
                if file_path.endswith(('.yaml', '.yml')):
                    return yaml.safe_load(f)
                elif file_path.endswith('.json'):
                    return json.load(f)
                else:
                    # Try both formats
                    try:
                        return json.load(f)
                    except json.JSONDecodeError:
                        f.seek(0)
                        return yaml.safe_load(f)
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to parse config file {file_path}: {str(e)}")
            return None

class ArchiveUtils:
    """Archive and compression utilities."""
    
    @staticmethod
    def create_tar_archive(source_dir: str, output_file: str, 
                          compression: str = 'gz') -> bool:
        """
        Create a tar archive.
        
        Args:
            source_dir: Directory to archive
            output_file: Output archive file path
            compression: Compression type ('gz', 'bz2', 'xz', or None)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            mode = f'w:{compression}' if compression else 'w'
            
            with tarfile.open(output_file, mode) as tar:
                tar.add(source_dir, arcname=os.path.basename(source_dir))
            
            return True
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to create archive {output_file}: {str(e)}")
            return False
    
    @staticmethod
    def extract_tar_archive(archive_file: str, output_dir: str) -> bool:
        """Extract a tar archive."""
        try:
            with tarfile.open(archive_file, 'r:*') as tar:
                tar.extractall(output_dir)
            return True
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to extract archive {archive_file}: {str(e)}")
            return False

@contextmanager
def temporary_directory():
    """Create and cleanup a temporary directory."""
    temp_dir = tempfile.mkdtemp()
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def retry_with_backoff(func, max_retries: int = 3, base_delay: float = 1.0, 
                      max_delay: float = 60.0, exceptions: tuple = (Exception,)):
    """
    Retry function with exponential backoff.
    
    Args:
        func: Function to execute
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay between retries
        max_delay: Maximum delay between retries
        exceptions: Tuple of exceptions to catch
        
    Returns:
        Function result
    """
    for attempt in range(max_retries + 1):
        try:
            return func()
        except exceptions as e:
            if attempt == max_retries:
                raise e
            
            delay = min(base_delay * (2 ** attempt), max_delay)
            logging.getLogger(__name__).warning(
                f"Attempt {attempt + 1} failed: {str(e)}. Retrying in {delay:.1f}s..."
            )
            time.sleep(delay)

def format_bytes(bytes_value: int) -> str:
    """Format bytes into human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"

def is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0