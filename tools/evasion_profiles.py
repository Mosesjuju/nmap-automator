#!/usr/bin/env python3
"""
Traffic Analysis Evasion Profiles for NMAP Automator v1.2.1
Advanced evasion techniques to bypass security controls and avoid detection
"""

import random
import time
import logging
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class EvasionLevel(Enum):
    """Evasion intensity levels"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    EXTREME = "extreme"


class DetectionSystem(Enum):
    """Types of detection systems to evade"""
    IDS = "ids"
    IPS = "ips"
    FIREWALL = "firewall"
    DPI = "dpi"
    WAF = "waf"
    RATE_LIMITING = "rate_limiting"
    BEHAVIORAL = "behavioral"


@dataclass
class EvasionProfile:
    """Evasion profile configuration"""
    name: str
    level: EvasionLevel
    description: str
    timing_template: str
    fragmentation: Optional[str]
    decoys: Optional[List[str]]
    source_spoof: Optional[str]
    data_length: Optional[int]
    scan_delay: Optional[float]
    randomize_hosts: bool
    use_proxies: bool
    custom_args: List[str]
    target_systems: List[DetectionSystem]


class EvasionProfileManager:
    """Manages and applies evasion profiles"""
    
    def __init__(self):
        self.profiles = self._initialize_profiles()
        self.active_profile = None
        
    def _initialize_profiles(self) -> Dict[str, EvasionProfile]:
        """Initialize predefined evasion profiles"""
        
        profiles = {}
        
        # 1. Stealth Profile - Minimal detection risk
        profiles["stealth"] = EvasionProfile(
            name="Stealth Scanning",
            level=EvasionLevel.HIGH,
            description="Maximum stealth with minimal detection footprint",
            timing_template="-T1",  # Paranoid timing
            fragmentation="-f",     # Fragment packets
            decoys=["RND:5"],      # 5 random decoys
            source_spoof=None,
            data_length=25,        # Random data padding
            scan_delay=2.0,        # 2 second delays
            randomize_hosts=True,
            use_proxies=False,
            custom_args=["--scan-delay", "2s", "--max-rate", "1"],
            target_systems=[DetectionSystem.IDS, DetectionSystem.IPS, DetectionSystem.FIREWALL]
        )
        
        # 2. Firewall Evasion Profile
        profiles["firewall_evasion"] = EvasionProfile(
            name="Firewall Evasion",
            level=EvasionLevel.MEDIUM,
            description="Bypass firewall rules and port filtering",
            timing_template="-T2",
            fragmentation="-ff",    # Tiny fragments
            decoys=["RND:3"],
            source_spoof=None,
            data_length=16,
            scan_delay=1.0,
            randomize_hosts=True,
            use_proxies=False,
            custom_args=[
                "--source-port", "53",      # Use DNS source port
                "--scan-delay", "1s",
                "--max-retries", "1"
            ],
            target_systems=[DetectionSystem.FIREWALL, DetectionSystem.RATE_LIMITING]
        )
        
        # 3. IDS/IPS Evasion Profile
        profiles["ids_evasion"] = EvasionProfile(
            name="IDS/IPS Evasion",
            level=EvasionLevel.HIGH,
            description="Evade intrusion detection and prevention systems",
            timing_template="-T1",
            fragmentation="--mtu 24",    # Custom tiny MTU
            decoys=["RND:8"],           # More decoys
            source_spoof=None,
            data_length=32,
            scan_delay=3.0,
            randomize_hosts=True,
            use_proxies=False,
            custom_args=[
                "--scan-delay", "3s",
                "--max-rate", "1",
                "--randomize-hosts",
                "--spoof-mac", "Dell"       # Spoof MAC vendor
            ],
            target_systems=[DetectionSystem.IDS, DetectionSystem.IPS, DetectionSystem.DPI]
        )
        
        # 4. WAF Evasion Profile (for web scanning)
        profiles["waf_evasion"] = EvasionProfile(
            name="WAF Evasion",
            level=EvasionLevel.MEDIUM,
            description="Bypass Web Application Firewalls",
            timing_template="-T2",
            fragmentation=None,
            decoys=["RND:2"],
            source_spoof=None,
            data_length=None,
            scan_delay=0.5,
            randomize_hosts=False,
            use_proxies=True,
            custom_args=[
                "--scan-delay", "500ms",
                "--max-rate", "10"
            ],
            target_systems=[DetectionSystem.WAF, DetectionSystem.DPI]
        )
        
        # 5. Behavioral Evasion Profile
        profiles["behavioral_evasion"] = EvasionProfile(
            name="Behavioral Evasion",
            level=EvasionLevel.EXTREME,
            description="Mimic legitimate traffic patterns",
            timing_template="-T0",      # Paranoid timing
            fragmentation="-f",
            decoys=["RND:10"],         # Many decoys
            source_spoof=None,
            data_length=64,            # Larger padding
            scan_delay=5.0,            # Long delays
            randomize_hosts=True,
            use_proxies=True,
            custom_args=[
                "--scan-delay", "5s",
                "--max-rate", "1",
                "--randomize-hosts",
                "--host-timeout", "300s"
            ],
            target_systems=[DetectionSystem.BEHAVIORAL, DetectionSystem.RATE_LIMITING]
        )
        
        # 6. Fast Evasion Profile (minimal impact)
        profiles["fast_evasion"] = EvasionProfile(
            name="Fast Evasion",
            level=EvasionLevel.LOW,
            description="Light evasion with minimal performance impact",
            timing_template="-T3",
            fragmentation=None,
            decoys=["RND:1"],
            source_spoof=None,
            data_length=8,
            scan_delay=0.1,
            randomize_hosts=False,
            use_proxies=False,
            custom_args=["--scan-delay", "100ms"],
            target_systems=[DetectionSystem.RATE_LIMITING]
        )
        
        # 7. Advanced Persistent Threat (APT) Profile
        profiles["apt_stealth"] = EvasionProfile(
            name="APT Stealth",
            level=EvasionLevel.EXTREME,
            description="Advanced persistent threat simulation with maximum stealth",
            timing_template="-T0",
            fragmentation="--mtu 8",    # Extremely small fragments
            decoys=["RND:15"],         # Maximum decoys
            source_spoof=None,
            data_length=128,           # Large padding
            scan_delay=10.0,           # Very long delays
            randomize_hosts=True,
            use_proxies=True,
            custom_args=[
                "--scan-delay", "10s",
                "--max-rate", "1",
                "--randomize-hosts",
                "--host-timeout", "600s",
                "--max-retries", "0",
                "--spoof-mac", "0"
            ],
            target_systems=[
                DetectionSystem.IDS, DetectionSystem.IPS, DetectionSystem.FIREWALL,
                DetectionSystem.DPI, DetectionSystem.BEHAVIORAL, DetectionSystem.RATE_LIMITING
            ]
        )
        
        return profiles
        
    def get_profile(self, profile_name: str) -> Optional[EvasionProfile]:
        """Get evasion profile by name"""
        return self.profiles.get(profile_name.lower())
        
    def list_profiles(self) -> List[str]:
        """List available evasion profiles"""
        return list(self.profiles.keys())
        
    def get_profile_info(self, profile_name: str) -> Dict:
        """Get detailed profile information"""
        profile = self.get_profile(profile_name)
        if not profile:
            return {}
            
        return {
            'name': profile.name,
            'level': profile.level.value,
            'description': profile.description,
            'target_systems': [sys.value for sys in profile.target_systems],
            'estimated_time_multiplier': self._estimate_time_impact(profile),
            'stealth_rating': self._calculate_stealth_rating(profile)
        }
        
    def _estimate_time_impact(self, profile: EvasionProfile) -> float:
        """Estimate scan time multiplier for profile"""
        multipliers = {
            EvasionLevel.NONE: 1.0,
            EvasionLevel.LOW: 1.2,
            EvasionLevel.MEDIUM: 2.0,
            EvasionLevel.HIGH: 5.0,
            EvasionLevel.EXTREME: 10.0
        }
        return multipliers.get(profile.level, 1.0)
        
    def _calculate_stealth_rating(self, profile: EvasionProfile) -> int:
        """Calculate stealth rating (1-10)"""
        rating = 1
        
        # Timing impact
        if "T0" in profile.timing_template: rating += 3
        elif "T1" in profile.timing_template: rating += 2
        elif "T2" in profile.timing_template: rating += 1
        
        # Fragmentation impact
        if profile.fragmentation:
            if "mtu" in profile.fragmentation.lower(): rating += 2
            else: rating += 1
            
        # Decoy impact
        if profile.decoys:
            decoy_count = int(profile.decoys[0].split(':')[1]) if ':' in profile.decoys[0] else 1
            rating += min(decoy_count // 3, 2)
            
        # Delay impact
        if profile.scan_delay and profile.scan_delay > 1.0:
            rating += 2
            
        return min(rating, 10)
        
    def build_evasion_command(self, base_command: List[str], 
                            profile_name: str,
                            target_ip: Optional[str] = None) -> List[str]:
        """Build command with evasion profile applied"""
        
        profile = self.get_profile(profile_name)
        if not profile:
            logger.warning(f"Evasion profile '{profile_name}' not found")
            return base_command
            
        logger.info(f"Applying evasion profile: {profile.name} (Level: {profile.level.value})")
        
        # Start with base command
        evasion_command = base_command.copy()
        
        # Apply timing template
        if profile.timing_template:
            evasion_command.extend(profile.timing_template.split())
            
        # Apply fragmentation
        if profile.fragmentation:
            evasion_command.extend(profile.fragmentation.split())
            
        # Apply decoys
        if profile.decoys and target_ip:
            decoy_list = self._generate_decoys(profile.decoys[0], target_ip)
            if decoy_list:
                evasion_command.extend(["-D", decoy_list])
                
        # Apply source spoofing
        if profile.source_spoof:
            evasion_command.extend(["-S", profile.source_spoof])
            
        # Apply data length
        if profile.data_length:
            evasion_command.extend(["--data-length", str(profile.data_length)])
            
        # Apply custom arguments
        evasion_command.extend(profile.custom_args)
        
        # Log evasion details
        logger.info(f"Evasion techniques applied:")
        logger.info(f"  - Timing: {profile.timing_template}")
        logger.info(f"  - Fragmentation: {profile.fragmentation or 'None'}")
        logger.info(f"  - Decoys: {profile.decoys or 'None'}")
        logger.info(f"  - Scan delay: {profile.scan_delay}s")
        logger.info(f"  - Stealth rating: {self._calculate_stealth_rating(profile)}/10")
        
        return evasion_command
        
    def _generate_decoys(self, decoy_spec: str, target_ip: str) -> str:
        """Generate decoy IP addresses"""
        
        if decoy_spec.startswith("RND:"):
            # Generate random decoys
            count = int(decoy_spec.split(":")[1])
            decoys = []
            
            # Generate random IPs in same subnet as target
            try:
                import ipaddress
                target_net = ipaddress.ip_network(f"{target_ip}/24", strict=False)
                
                for _ in range(count):
                    # Generate random IP in network
                    random_host = random.randint(1, 254)
                    decoy_ip = str(target_net.network_address + random_host)
                    decoys.append(decoy_ip)
                    
                # Add 'ME' to hide real source among decoys
                decoys.append("ME")
                return ",".join(decoys)
                
            except Exception as e:
                logger.warning(f"Could not generate decoys: {e}")
                return "RND:3,ME"
        else:
            return decoy_spec
            
    def apply_behavioral_evasion(self, targets: List[str]) -> List[str]:
        """Apply behavioral evasion to target list"""
        
        if not self.active_profile or not self.active_profile.randomize_hosts:
            return targets
            
        # Randomize target order
        randomized_targets = targets.copy()
        random.shuffle(randomized_targets)
        
        logger.info("Applied behavioral evasion: randomized target order")
        return randomized_targets
        
    def get_scan_delay(self, profile_name: str) -> float:
        """Get scan delay for profile"""
        profile = self.get_profile(profile_name)
        return profile.scan_delay if profile else 0.0
        
    def print_evasion_banner(self, profile_name: str):
        """Print evasion profile banner"""
        
        profile = self.get_profile(profile_name)
        if not profile:
            return
            
        print(f"\n🥷 EVASION PROFILE ACTIVE 🥷")
        print("=" * 50)
        print(f"Profile: {profile.name}")
        print(f"Level: {profile.level.value.upper()}")
        print(f"Description: {profile.description}")
        print(f"Stealth Rating: {self._calculate_stealth_rating(profile)}/10")
        print(f"Time Impact: {self._estimate_time_impact(profile):.1f}x slower")
        print(f"Target Systems: {', '.join([sys.value.upper() for sys in profile.target_systems])}")
        print("=" * 50)


class TrafficAnalysisCounter:
    """Counter-surveillance techniques against traffic analysis"""
    
    def __init__(self):
        self.techniques = {
            'timing_obfuscation': self._timing_obfuscation,
            'volume_padding': self._volume_padding,
            'pattern_breaking': self._pattern_breaking,
            'protocol_mixing': self._protocol_mixing,
            'traffic_shaping': self._traffic_shaping
        }
        
    def _timing_obfuscation(self, interval: float) -> float:
        """Add random jitter to timing patterns"""
        jitter = random.uniform(0.1, 2.0)
        return interval + jitter
        
    def _volume_padding(self, packet_size: int) -> int:
        """Add random padding to packet sizes"""
        padding = random.randint(1, 64)
        return packet_size + padding
        
    def _pattern_breaking(self, sequence: List) -> List:
        """Break predictable patterns in sequences"""
        if len(sequence) > 2:
            # Insert random elements to break patterns
            break_points = random.sample(range(len(sequence)), 
                                       min(3, len(sequence) // 2))
            for bp in break_points:
                sequence.insert(bp, None)  # Placeholder for pattern break
        return sequence
        
    def _protocol_mixing(self, protocols: List[str]) -> List[str]:
        """Mix different protocol types to confuse analysis"""
        mixed = protocols.copy()
        # Add decoy protocols
        decoy_protocols = ['dns', 'http', 'https', 'ftp']
        mixed.extend(random.sample(decoy_protocols, 2))
        random.shuffle(mixed)
        return mixed
        
    def _traffic_shaping(self, traffic_profile: Dict) -> Dict:
        """Shape traffic to mimic legitimate patterns"""
        # Simulate business hours pattern
        current_hour = time.localtime().tm_hour
        if 9 <= current_hour <= 17:  # Business hours
            traffic_profile['intensity'] = 'medium'
        elif 18 <= current_hour <= 22:  # Evening
            traffic_profile['intensity'] = 'low'
        else:  # Night/early morning
            traffic_profile['intensity'] = 'minimal'
            
        return traffic_profile


# Convenience functions for easy integration
def get_evasion_manager() -> EvasionProfileManager:
    """Get global evasion manager instance"""
    return EvasionProfileManager()


def apply_evasion_profile(command: List[str], profile: str, target: str = None) -> List[str]:
    """Quick function to apply evasion profile to command"""
    manager = get_evasion_manager()
    return manager.build_evasion_command(command, profile, target)


def list_evasion_profiles() -> None:
    """List all available evasion profiles"""
    manager = get_evasion_manager()
    
    print(f"\n🥷 AVAILABLE EVASION PROFILES 🥷")
    print("=" * 60)
    
    for profile_name in manager.list_profiles():
        info = manager.get_profile_info(profile_name)
        print(f"📋 {info['name']}")
        print(f"   Level: {info['level'].upper()}")
        print(f"   Stealth: {info['stealth_rating']}/10")
        print(f"   Speed Impact: {info['estimated_time_multiplier']:.1f}x")
        print(f"   Description: {info['description']}")
        print(f"   Targets: {', '.join(info['target_systems'])}")
        print()


if __name__ == "__main__":
    # Demonstration
    list_evasion_profiles()
    
    # Example usage
    manager = get_evasion_manager()
    base_cmd = ["nmap", "-sV", "-sC"]
    
    # Apply stealth profile
    stealth_cmd = manager.build_evasion_command(base_cmd, "stealth", "192.168.1.1")
    print(f"Stealth command: {' '.join(stealth_cmd)}")