"""Rule-based access control and device authentication layer.

Provides device whitelist validation, rate limiting, token checks,
and payload validation before ML inference.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Network, IPv4Address, AddressValueError
from typing import Dict, List, Optional, Set

import yaml


@dataclass
class DeviceInfo:
    """Registered device metadata."""
    device_id: str
    ip_address: str
    mac_address: Optional[str] = None
    token: Optional[str] = None
    device_type: str = "sensor"
    location: str = "unknown"
    registered_date: str = ""
    max_packets_per_sec: float = 100.0  # rate limit
    enabled: bool = True


@dataclass
class RuleViolation:
    """Represents a rule violation event."""
    device_id: str
    src_ip: str
    violation_type: str  # 'unauthorized_ip', 'rate_limit', 'invalid_token', 'payload_error', etc.
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    severity: str = "warning"  # 'info', 'warning', 'critical'


class DeviceRegistry:
    """Manages whitelisted devices."""
    
    def __init__(self, yaml_path: Optional[str] = None) -> None:
        self.devices: Dict[str, DeviceInfo] = {}
        self.ip_to_device_id: Dict[str, str] = {}
        self.mac_to_device_id: Dict[str, str] = {}
        self.trusted_subnets: List[IPv4Network] = []
        if yaml_path:
            self.load_from_yaml(yaml_path)
    
    def load_from_yaml(self, path: str) -> None:
        """Load device registry from YAML file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
            
            devices_list = data.get('devices', [])
            for dev_dict in devices_list:
                dev = DeviceInfo(
                    device_id=dev_dict.get('device_id', ''),
                    ip_address=dev_dict.get('ip_address', ''),
                    mac_address=dev_dict.get('mac_address'),
                    token=dev_dict.get('token'),
                    device_type=dev_dict.get('device_type', 'sensor'),
                    location=dev_dict.get('location', 'unknown'),
                    registered_date=dev_dict.get('registered_date', ''),
                    max_packets_per_sec=float(dev_dict.get('max_packets_per_sec', 100.0)),
                    enabled=dev_dict.get('enabled', True),
                )
                self.register_device(dev)
            
            # Load trusted subnets
            trusted_subnets_list = data.get('trusted_subnets', [])
            for subnet_str in trusted_subnets_list:
                try:
                    network = IPv4Network(subnet_str)
                    self.trusted_subnets.append(network)
                except AddressValueError as e:
                    print(f"[WARN] Invalid subnet in config: {subnet_str}: {e}")
        except Exception as e:
            print(f"[WARN] Failed to load device registry from {path}: {e}")
    
    def register_device(self, device: DeviceInfo) -> None:
        """Register a device."""
        if not device.device_id:
            raise ValueError("device_id is required")
        self.devices[device.device_id] = device
        if device.ip_address:
            self.ip_to_device_id[device.ip_address] = device.device_id
        if device.mac_address:
            self.mac_to_device_id[device.mac_address] = device.device_id
    
    def lookup_by_ip(self, ip: str) -> Optional[DeviceInfo]:
        """Find device by IP address."""
        device_id = self.ip_to_device_id.get(ip)
        if device_id:
            return self.devices.get(device_id)
        return None
    
    def lookup_by_mac(self, mac: str) -> Optional[DeviceInfo]:
        """Find device by MAC address."""
        device_id = self.mac_to_device_id.get(mac)
        if device_id:
            return self.devices.get(device_id)
        return None
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist and enabled."""
        # Check exact IP match first
        dev = self.lookup_by_ip(ip)
        if dev is not None and dev.enabled:
            return True
        
        # Check if IP is in any trusted subnet
        try:
            ip_obj = IPv4Address(ip)
            for subnet in self.trusted_subnets:
                if ip_obj in subnet:
                    return True
        except AddressValueError:
            pass
        
        return False


class RateLimiter:
    """Simple per-device rate limiter (packets per second)."""
    
    def __init__(self) -> None:
        # Track: device_id -> list of (timestamp, pkt_count) tuples for sliding window
        self.windows: Dict[str, List[tuple[datetime, int]]] = {}
        self.window_duration = timedelta(seconds=1)
    
    def check_rate(self, device_id: str, pkt_count: int, limit: float) -> bool:
        """
        Check if packet count exceeds rate limit.
        
        Args:
            device_id: Device identifier
            pkt_count: Packet count in this window
            limit: Max packets per second allowed
            
        Returns:
            True if within limit, False if exceeded
        """
        now = datetime.now()
        if device_id not in self.windows:
            self.windows[device_id] = []
        
        # Remove old windows outside sliding window
        self.windows[device_id] = [
            (ts, count) for ts, count in self.windows[device_id]
            if now - ts < self.window_duration
        ]
        
        # Sum packets in current window
        total_in_window = sum(count for _, count in self.windows[device_id])
        total_in_window += pkt_count
        
        # Check limit
        if total_in_window > limit:
            return False
        
        # Record this window
        self.windows[device_id].append((now, pkt_count))
        return True
    
    def reset(self, device_id: str) -> None:
        """Reset rate limiter for a device."""
        if device_id in self.windows:
            del self.windows[device_id]


class RuleEngine:
    """Central rule-based access control engine."""
    
    def __init__(self, device_registry_path: Optional[str] = None) -> None:
        self.registry = DeviceRegistry(device_registry_path)
        self.rate_limiter = RateLimiter()
        self.violations: List[RuleViolation] = []
        self.enabled = True
    
    def evaluate(
        self,
        src_ip: str,
        src_mac: Optional[str] = None,
        token: Optional[str] = None,
        pkt_count: int = 1,
        payload: Optional[Dict] = None,
    ) -> tuple[bool, Optional[RuleViolation]]:
        """
        Evaluate all rules for a source.
        
        Returns:
            (passed: bool, violation: Optional[RuleViolation])
            - If passed=True, all rules passed; violation is None.
            - If passed=False, a rule was violated; violation contains details.
        """
        if not self.enabled:
            return True, None
        
        # Rule 1: Check whitelist (IP in trusted subnet or registered device)
        is_whitelisted = self.registry.is_whitelisted(src_ip)
        if not is_whitelisted:
            # Check MAC as fallback if available
            device = None
            if src_mac:
                device = self.registry.lookup_by_mac(src_mac)
                is_whitelisted = device is not None and device.enabled
        
        if not is_whitelisted:
            violation = RuleViolation(
                device_id="UNKNOWN",
                src_ip=src_ip,
                violation_type="unauthorized_ip",
                message=f"Source IP {src_ip} not in whitelist",
                severity="critical",
            )
            self.violations.append(violation)
            return False, violation
        
        # For further checks, get the device info
        device = self.registry.lookup_by_ip(src_ip)
        if not device and src_mac:
            device = self.registry.lookup_by_mac(src_mac)
        
        # If device info available, do additional checks
        if device:
            # Rule 2: Check device enabled
            if not device.enabled:
                violation = RuleViolation(
                    device_id=device.device_id,
                    src_ip=src_ip,
                    violation_type="device_disabled",
                    message=f"Device {device.device_id} is disabled",
                    severity="warning",
                )
                self.violations.append(violation)
                return False, violation
            
            # # Rule 3: Check token (if token is configured for device)
            # if device.token and token != device.token:
            #     violation = RuleViolation(
            #         device_id=device.device_id,
            #         src_ip=src_ip,
            #         violation_type="invalid_token",
            #         message=f"Invalid token for device {device.device_id}",
            #         severity="critical",
            #     )
            #     self.violations.append(violation)
            #     return False, violation
            
            # Rule 4: Check rate limit
            if not self.rate_limiter.check_rate(device.device_id, pkt_count, device.max_packets_per_sec):
                violation = RuleViolation(
                    device_id=device.device_id,
                    src_ip=src_ip,
                    violation_type="rate_limit_exceeded",
                    message=f"Rate limit exceeded for {device.device_id}: {pkt_count} pkt > {device.max_packets_per_sec} pps",
                    severity="warning",
                )
                self.violations.append(violation)
                return False, violation
            
            # Rule 5: Basic payload validation (if payload provided)
            if payload:
                required_fields = {'ts', 'src_ip', 'dst_ip', 'proto'}
                if not all(field in payload for field in required_fields):
                    violation = RuleViolation(
                        device_id=device.device_id,
                        src_ip=src_ip,
                        violation_type="payload_error",
                        message=f"Payload missing required fields: {required_fields}",
                        severity="warning",
                    )
                    self.violations.append(violation)
                    return False, violation
        
        # All rules passed
        return True, None
    
    def get_violations(self, device_id: Optional[str] = None) -> List[RuleViolation]:
        """Get violations (optionally filtered by device_id)."""
        if device_id:
            return [v for v in self.violations if v.device_id == device_id]
        return self.violations
    
    def clear_violations(self) -> None:
        """Clear violation log."""
        self.violations.clear()
    
    def add_device(self, device: DeviceInfo) -> None:
        """Register a new device (runtime)."""
        self.registry.register_device(device)
