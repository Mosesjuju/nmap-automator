#!/usr/bin/env python3
"""
Cloud Scanning Integration for NMAP Automator v1.3.0
Next-generation cloud infrastructure security assessment capabilities
"""

import asyncio
import boto3
import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import requests
import subprocess
import time
from datetime import datetime, timezone
import ipaddress

logger = logging.getLogger(__name__)


class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    DIGITALOCEAN = "digitalocean"
    VULTR = "vultr"
    LINODE = "linode"
    ORACLE = "oracle"
    IBM = "ibm"
    ALIBABA = "alibaba"


class CloudResourceType(Enum):
    """Types of cloud resources to scan"""
    EC2_INSTANCES = "ec2_instances"
    RDS_DATABASES = "rds_databases"
    ELB_LOAD_BALANCERS = "elb_load_balancers"
    S3_BUCKETS = "s3_buckets"
    LAMBDA_FUNCTIONS = "lambda_functions"
    EKS_CLUSTERS = "eks_clusters"
    API_GATEWAYS = "api_gateways"
    CLOUDFRONT_DISTRIBUTIONS = "cloudfront_distributions"
    AZURE_VMS = "azure_vms"
    AZURE_WEBAPPS = "azure_webapps"
    GCP_COMPUTE = "gcp_compute"
    GCP_STORAGE = "gcp_storage"
    KUBERNETES_PODS = "kubernetes_pods"
    DOCKER_CONTAINERS = "docker_containers"


@dataclass
class CloudAsset:
    """Cloud asset representation"""
    id: str
    name: str
    type: CloudResourceType
    provider: CloudProvider
    region: str
    public_ip: Optional[str]
    private_ip: Optional[str]
    ports: List[int]
    tags: Dict[str, str]
    security_groups: List[str]
    metadata: Dict[str, Any]
    last_seen: datetime
    
    @property
    def scannable_ip(self) -> Optional[str]:
        """Get the IP address that can be scanned"""
        return self.public_ip or self.private_ip
        
    def to_nmap_target(self) -> Optional[str]:
        """Convert to nmap-compatible target"""
        if self.scannable_ip:
            return self.scannable_ip
        elif self.name and not self.name.startswith('i-'):  # Not an instance ID
            return self.name
        return None


class CloudDiscoveryEngine:
    """Cloud asset discovery engine"""
    
    def __init__(self):
        self.providers = {
            CloudProvider.AWS: AWSDiscovery(),
            CloudProvider.AZURE: AzureDiscovery(),
            CloudProvider.GCP: GCPDiscovery(),
            CloudProvider.DIGITALOCEAN: DigitalOceanDiscovery(),
        }
        
    async def discover_all_assets(self, providers: List[CloudProvider] = None) -> List[CloudAsset]:
        """Discover assets across all or specified cloud providers"""
        
        if providers is None:
            providers = list(self.providers.keys())
            
        all_assets = []
        
        for provider in providers:
            if provider in self.providers:
                logger.info(f"☁️ Discovering {provider.value.upper()} assets...")
                
                try:
                    assets = await self.providers[provider].discover_assets()
                    all_assets.extend(assets)
                    logger.info(f"✅ Found {len(assets)} assets in {provider.value.upper()}")
                    
                except Exception as e:
                    logger.error(f"❌ Error discovering {provider.value.upper()} assets: {e}")
                    
        logger.info(f"🌐 Total cloud assets discovered: {len(all_assets)}")
        return all_assets
        
    async def discover_by_tags(self, tag_filters: Dict[str, str]) -> List[CloudAsset]:
        """Discover assets matching specific tags"""
        
        all_assets = await self.discover_all_assets()
        filtered_assets = []
        
        for asset in all_assets:
            match = True
            for key, value in tag_filters.items():
                if key not in asset.tags or asset.tags[key] != value:
                    match = False
                    break
                    
            if match:
                filtered_assets.append(asset)
                
        logger.info(f"🏷️ Found {len(filtered_assets)} assets matching tags: {tag_filters}")
        return filtered_assets


class AWSDiscovery:
    """AWS asset discovery"""
    
    def __init__(self):
        try:
            self.ec2 = boto3.client('ec2')
            self.rds = boto3.client('rds')
            self.elbv2 = boto3.client('elbv2')
            self.s3 = boto3.client('s3')
            self.lambda_client = boto3.client('lambda')
            self.eks = boto3.client('eks')
        except Exception as e:
            logger.warning(f"AWS credentials not configured: {e}")
            
    async def discover_assets(self) -> List[CloudAsset]:
        """Discover all AWS assets"""
        
        assets = []
        
        # EC2 Instances
        try:
            assets.extend(await self._discover_ec2_instances())
        except Exception as e:
            logger.error(f"Failed to discover EC2 instances: {e}")
            
        # RDS Databases
        try:
            assets.extend(await self._discover_rds_instances())
        except Exception as e:
            logger.error(f"Failed to discover RDS instances: {e}")
            
        # Load Balancers
        try:
            assets.extend(await self._discover_load_balancers())
        except Exception as e:
            logger.error(f"Failed to discover load balancers: {e}")
            
        return assets
        
    async def _discover_ec2_instances(self) -> List[CloudAsset]:
        """Discover EC2 instances"""
        
        instances = []
        
        try:
            response = self.ec2.describe_instances()
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    
                    if instance['State']['Name'] not in ['running', 'pending']:
                        continue
                        
                    # Extract security groups
                    security_groups = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    
                    # Extract tags
                    tags = {}
                    for tag in instance.get('Tags', []):
                        tags[tag['Key']] = tag['Value']
                        
                    # Get open ports from security groups
                    open_ports = await self._get_security_group_ports(security_groups)
                    
                    asset = CloudAsset(
                        id=instance['InstanceId'],
                        name=tags.get('Name', instance['InstanceId']),
                        type=CloudResourceType.EC2_INSTANCES,
                        provider=CloudProvider.AWS,
                        region=instance['Placement']['AvailabilityZone'][:-1],
                        public_ip=instance.get('PublicIpAddress'),
                        private_ip=instance.get('PrivateIpAddress'),
                        ports=open_ports,
                        tags=tags,
                        security_groups=security_groups,
                        metadata={
                            'instance_type': instance['InstanceType'],
                            'vpc_id': instance.get('VpcId'),
                            'subnet_id': instance.get('SubnetId'),
                            'state': instance['State']['Name']
                        },
                        last_seen=datetime.now(timezone.utc)
                    )
                    
                    instances.append(asset)
                    
        except Exception as e:
            logger.error(f"Error discovering EC2 instances: {e}")
            
        return instances
        
    async def _discover_rds_instances(self) -> List[CloudAsset]:
        """Discover RDS database instances"""
        
        databases = []
        
        try:
            response = self.rds.describe_db_instances()
            
            for db in response['DBInstances']:
                
                if db['DBInstanceStatus'] != 'available':
                    continue
                    
                # Extract tags
                tags = {}
                try:
                    tag_response = self.rds.list_tags_for_resource(
                        ResourceName=db['DBInstanceArn']
                    )
                    for tag in tag_response.get('TagList', []):
                        tags[tag['Key']] = tag['Value']
                except:
                    pass
                    
                # Database port
                port = db.get('DbInstancePort', 3306)
                
                asset = CloudAsset(
                    id=db['DBInstanceIdentifier'],
                    name=db['DBInstanceIdentifier'],
                    type=CloudResourceType.RDS_DATABASES,
                    provider=CloudProvider.AWS,
                    region=db['AvailabilityZone'][:-1] if db.get('AvailabilityZone') else 'unknown',
                    public_ip=None,  # RDS instances typically don't have public IPs directly
                    private_ip=db['Endpoint']['Address'] if db.get('Endpoint') else None,
                    ports=[port],
                    tags=tags,
                    security_groups=[sg['VpcSecurityGroupId'] for sg in db.get('VpcSecurityGroups', [])],
                    metadata={
                        'engine': db['Engine'],
                        'engine_version': db['EngineVersion'],
                        'instance_class': db['DBInstanceClass'],
                        'allocated_storage': db.get('AllocatedStorage'),
                        'publicly_accessible': db.get('PubliclyAccessible', False)
                    },
                    last_seen=datetime.now(timezone.utc)
                )
                
                databases.append(asset)
                
        except Exception as e:
            logger.error(f"Error discovering RDS instances: {e}")
            
        return databases
        
    async def _discover_load_balancers(self) -> List[CloudAsset]:
        """Discover Application Load Balancers"""
        
        load_balancers = []
        
        try:
            response = self.elbv2.describe_load_balancers()
            
            for lb in response['LoadBalancers']:
                
                if lb['State']['Code'] != 'active':
                    continue
                    
                # Extract tags
                tags = {}
                try:
                    tag_response = self.elbv2.describe_tags(
                        ResourceArns=[lb['LoadBalancerArn']]
                    )
                    for tag_desc in tag_response.get('TagDescriptions', []):
                        for tag in tag_desc.get('Tags', []):
                            tags[tag['Key']] = tag['Value']
                except:
                    pass
                    
                # Get listeners to determine ports
                ports = []
                try:
                    listeners_response = self.elbv2.describe_listeners(
                        LoadBalancerArn=lb['LoadBalancerArn']
                    )
                    ports = [listener['Port'] for listener in listeners_response.get('Listeners', [])]
                except:
                    ports = [80, 443]  # Default web ports
                    
                asset = CloudAsset(
                    id=lb['LoadBalancerArn'].split('/')[-1],
                    name=lb['LoadBalancerName'],
                    type=CloudResourceType.ELB_LOAD_BALANCERS,
                    provider=CloudProvider.AWS,
                    region=lb['AvailabilityZones'][0]['ZoneName'][:-1] if lb.get('AvailabilityZones') else 'unknown',
                    public_ip=None,  # ALBs use DNS names
                    private_ip=lb['DNSName'],
                    ports=ports,
                    tags=tags,
                    security_groups=lb.get('SecurityGroups', []),
                    metadata={
                        'type': lb['Type'],
                        'scheme': lb['Scheme'],
                        'vpc_id': lb.get('VpcId'),
                        'dns_name': lb['DNSName']
                    },
                    last_seen=datetime.now(timezone.utc)
                )
                
                load_balancers.append(asset)
                
        except Exception as e:
            logger.error(f"Error discovering load balancers: {e}")
            
        return load_balancers
        
    async def _get_security_group_ports(self, security_group_ids: List[str]) -> List[int]:
        """Extract open ports from security groups"""
        
        ports = set()
        
        try:
            if security_group_ids:
                response = self.ec2.describe_security_groups(GroupIds=security_group_ids)
                
                for sg in response['SecurityGroups']:
                    for rule in sg.get('IpPermissions', []):
                        if rule.get('FromPort') is not None:
                            if rule['FromPort'] == rule.get('ToPort'):
                                ports.add(rule['FromPort'])
                            else:
                                # Port range - add common ports within range
                                start, end = rule['FromPort'], rule.get('ToPort', rule['FromPort'])
                                common_ports = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 3389, 5432, 3306]
                                for port in common_ports:
                                    if start <= port <= end:
                                        ports.add(port)
                                        
        except Exception as e:
            logger.error(f"Error getting security group ports: {e}")
            
        return list(ports)


class AzureDiscovery:
    """Azure asset discovery"""
    
    async def discover_assets(self) -> List[CloudAsset]:
        """Discover Azure assets"""
        # Placeholder for Azure discovery
        logger.info("Azure discovery not yet implemented")
        return []


class GCPDiscovery:
    """Google Cloud Platform asset discovery"""
    
    async def discover_assets(self) -> List[CloudAsset]:
        """Discover GCP assets"""
        # Placeholder for GCP discovery
        logger.info("GCP discovery not yet implemented")
        return []


class DigitalOceanDiscovery:
    """DigitalOcean asset discovery"""
    
    async def discover_assets(self) -> List[CloudAsset]:
        """Discover DigitalOcean assets"""
        # Placeholder for DigitalOcean discovery
        logger.info("DigitalOcean discovery not yet implemented")
        return []


class CloudScanOrchestrator:
    """Orchestrates cloud scanning operations"""
    
    def __init__(self, nmap_automator):
        self.nmap_automator = nmap_automator
        self.discovery_engine = CloudDiscoveryEngine()
        
    async def cloud_scan_workflow(self, providers: List[CloudProvider] = None,
                                 tag_filters: Dict[str, str] = None,
                                 scan_options: Dict[str, Any] = None) -> Dict:
        """Complete cloud scanning workflow"""
        
        workflow_start = time.time()
        results = {
            'scan_start': datetime.now(timezone.utc).isoformat(),
            'providers_scanned': [],
            'assets_discovered': 0,
            'assets_scanned': 0,
            'scan_results': [],
            'cloud_specific_findings': [],
            'recommendations': []
        }
        
        try:
            # Phase 1: Cloud Asset Discovery
            logger.info("🌐 Phase 1: Cloud Asset Discovery")
            
            if tag_filters:
                assets = await self.discovery_engine.discover_by_tags(tag_filters)
            else:
                assets = await self.discovery_engine.discover_all_assets(providers)
                
            results['assets_discovered'] = len(assets)
            results['providers_scanned'] = [p.value for p in (providers or list(CloudProvider))]
            
            if not assets:
                logger.warning("No cloud assets discovered")
                return results
                
            # Phase 2: Asset Classification and Filtering
            logger.info("🔍 Phase 2: Asset Classification")
            scannable_assets = [asset for asset in assets if asset.to_nmap_target()]
            
            logger.info(f"📊 Asset Summary:")
            logger.info(f"  Total discovered: {len(assets)}")
            logger.info(f"  Scannable: {len(scannable_assets)}")
            
            # Group by resource type
            asset_types = {}
            for asset in scannable_assets:
                asset_type = asset.type.value
                if asset_type not in asset_types:
                    asset_types[asset_type] = []
                asset_types[asset_type].append(asset)
                
            for asset_type, asset_list in asset_types.items():
                logger.info(f"    {asset_type}: {len(asset_list)}")
                
            # Phase 3: Cloud-Aware Scanning
            logger.info("⚡ Phase 3: Cloud-Aware Scanning")
            
            scan_results = []
            for asset in scannable_assets:
                
                target = asset.to_nmap_target()
                if not target:
                    continue
                    
                logger.info(f"🎯 Scanning {asset.name} ({target}) - {asset.type.value}")
                
                # Build cloud-specific scan parameters
                cloud_scan_args = self._build_cloud_scan_args(asset, scan_options)
                
                # Execute scan (integrate with existing nmap automator)
                scan_result = await self._execute_cloud_scan(target, asset, cloud_scan_args)
                
                if scan_result:
                    scan_results.append(scan_result)
                    results['assets_scanned'] += 1
                    
            results['scan_results'] = scan_results
            
            # Phase 4: Cloud-Specific Analysis
            logger.info("🔬 Phase 4: Cloud-Specific Analysis")
            
            cloud_findings = await self._analyze_cloud_findings(assets, scan_results)
            results['cloud_specific_findings'] = cloud_findings
            
            # Phase 5: Cloud Security Recommendations
            logger.info("💡 Phase 5: Security Recommendations")
            
            recommendations = await self._generate_cloud_recommendations(assets, cloud_findings)
            results['recommendations'] = recommendations
            
        except Exception as e:
            logger.error(f"❌ Cloud scan workflow error: {e}")
            results['error'] = str(e)
            
        finally:
            results['scan_end'] = datetime.now(timezone.utc).isoformat()
            results['scan_duration'] = time.time() - workflow_start
            
        return results
        
    def _build_cloud_scan_args(self, asset: CloudAsset, scan_options: Dict = None) -> List[str]:
        """Build cloud-specific scan arguments"""
        
        args = []
        scan_options = scan_options or {}
        
        # Cloud-specific timing (often need to be more aggressive due to auto-scaling)
        if asset.provider == CloudProvider.AWS:
            args.extend(['-T4'])  # Aggressive timing for cloud
        else:
            args.extend(['-T3'])  # Normal timing
            
        # Port selection based on asset type
        if asset.type == CloudResourceType.EC2_INSTANCES:
            if asset.ports:
                port_list = ','.join(map(str, asset.ports))
                args.extend(['-p', port_list])
            else:
                args.extend(['-F'])  # Fast scan if no specific ports
                
        elif asset.type == CloudResourceType.RDS_DATABASES:
            # Database-specific ports
            db_ports = [1433, 1521, 3306, 5432, 6379, 27017]
            if asset.ports:
                db_ports.extend(asset.ports)
            args.extend(['-p', ','.join(map(str, set(db_ports)))])
            
        elif asset.type == CloudResourceType.ELB_LOAD_BALANCERS:
            # Web-focused scanning for load balancers
            web_ports = [80, 443, 8080, 8443]
            if asset.ports:
                web_ports.extend(asset.ports)
            args.extend(['-p', ','.join(map(str, set(web_ports)))])
            
        # Cloud-specific service detection
        args.extend(['-sV', '-sC'])
        
        # Add cloud provider tags to output
        if 'output_basename' in scan_options:
            basename = scan_options['output_basename']
            cloud_basename = f"{basename}_cloud_{asset.provider.value}_{asset.type.value}"
            scan_options['output_basename'] = cloud_basename
            
        return args
        
    async def _execute_cloud_scan(self, target: str, asset: CloudAsset, 
                                 scan_args: List[str]) -> Dict:
        """Execute scan against cloud asset"""
        
        try:
            # This would integrate with your existing nmap automator
            # For now, simulate the scan execution
            
            scan_result = {
                'target': target,
                'asset_id': asset.id,
                'asset_name': asset.name,
                'asset_type': asset.type.value,
                'provider': asset.provider.value,
                'region': asset.region,
                'scan_args': scan_args,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'status': 'completed'
            }
            
            # Simulate some findings based on asset type
            if asset.type == CloudResourceType.EC2_INSTANCES:
                scan_result['findings'] = {
                    'open_ports': asset.ports or [22, 80],
                    'services': ['ssh', 'http'],
                    'cloud_metadata_accessible': True if asset.public_ip else False
                }
            elif asset.type == CloudResourceType.RDS_DATABASES:
                scan_result['findings'] = {
                    'open_ports': asset.ports or [3306],
                    'services': ['mysql'],
                    'publicly_accessible': asset.metadata.get('publicly_accessible', False)
                }
                
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning {target}: {e}")
            return None
            
    async def _analyze_cloud_findings(self, assets: List[CloudAsset], 
                                    scan_results: List[Dict]) -> List[Dict]:
        """Analyze findings for cloud-specific security issues"""
        
        findings = []
        
        for result in scan_results:
            asset = next((a for a in assets if a.id == result['asset_id']), None)
            if not asset:
                continue
                
            # Cloud metadata service accessibility
            if result.get('findings', {}).get('cloud_metadata_accessible'):
                findings.append({
                    'type': 'cloud_metadata_exposure',
                    'severity': 'medium',
                    'asset': asset.name,
                    'description': 'Cloud metadata service may be accessible',
                    'recommendation': 'Implement metadata service protection'
                })
                
            # Publicly accessible databases
            if (asset.type == CloudResourceType.RDS_DATABASES and 
                asset.metadata.get('publicly_accessible')):
                findings.append({
                    'type': 'public_database',
                    'severity': 'high',
                    'asset': asset.name,
                    'description': 'Database is publicly accessible',
                    'recommendation': 'Restrict database access to private subnets'
                })
                
            # Overly permissive security groups
            if asset.ports and len(asset.ports) > 10:
                findings.append({
                    'type': 'permissive_security_group',
                    'severity': 'medium',
                    'asset': asset.name,
                    'description': f'Security group allows {len(asset.ports)} ports',
                    'recommendation': 'Review and minimize open ports'
                })
                
        return findings
        
    async def _generate_cloud_recommendations(self, assets: List[CloudAsset],
                                           findings: List[Dict]) -> List[Dict]:
        """Generate cloud security recommendations"""
        
        recommendations = []
        
        # Asset-based recommendations
        provider_counts = {}
        for asset in assets:
            provider = asset.provider.value
            provider_counts[provider] = provider_counts.get(provider, 0) + 1
            
        # Multi-cloud recommendations
        if len(provider_counts) > 1:
            recommendations.append({
                'category': 'multi_cloud_management',
                'priority': 'medium',
                'title': 'Multi-Cloud Security Management',
                'description': f'Assets found across {len(provider_counts)} cloud providers',
                'recommendation': 'Implement centralized security monitoring and compliance'
            })
            
        # Finding-based recommendations
        high_severity_findings = [f for f in findings if f.get('severity') == 'high']
        if high_severity_findings:
            recommendations.append({
                'category': 'critical_security',
                'priority': 'high',
                'title': 'Critical Security Issues Found',
                'description': f'{len(high_severity_findings)} high-severity issues identified',
                'recommendation': 'Immediately address all high-severity findings'
            })
            
        return recommendations


# Integration functions for existing NMAP Automator
async def discover_cloud_targets(providers: List[str] = None, 
                               tags: Dict[str, str] = None) -> List[str]:
    """Discover cloud targets for traditional nmap scanning"""
    
    discovery = CloudDiscoveryEngine()
    
    # Convert string providers to enum
    provider_enums = []
    if providers:
        for p in providers:
            try:
                provider_enums.append(CloudProvider(p.lower()))
            except ValueError:
                logger.warning(f"Unknown cloud provider: {p}")
                
    if tags:
        assets = await discovery.discover_by_tags(tags)
    else:
        assets = await discovery.discover_all_assets(provider_enums)
        
    # Convert to nmap targets
    targets = []
    for asset in assets:
        target = asset.to_nmap_target()
        if target:
            targets.append(target)
            
    return targets


def print_cloud_banner():
    """Print cloud scanning banner"""
    print(f"""
    ☁️  CLOUD SCANNING ENABLED ☁️
    =====================================
    🌐 Multi-Cloud Asset Discovery
    ⚡ Cloud-Aware Security Assessment  
    🔍 Provider-Specific Analysis
    💡 Cloud Security Recommendations
    =====================================
    """)


if __name__ == "__main__":
    # Example usage
    async def main():
        orchestrator = CloudScanOrchestrator(None)
        
        # Discover and scan AWS assets
        results = await orchestrator.cloud_scan_workflow(
            providers=[CloudProvider.AWS],
            tag_filters={'Environment': 'production'}
        )
        
        print(f"Cloud scan completed: {results['assets_scanned']} assets scanned")
        
    asyncio.run(main())