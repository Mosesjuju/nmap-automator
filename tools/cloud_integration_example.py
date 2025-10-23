#!/usr/bin/env python3
"""
NMAP Automator v1.3.0 - Cloud-Enhanced Security Platform
Integration of cloud scanning capabilities with existing security platform
"""

# Enhanced imports for cloud integration
from cloud_scanning import (
    CloudScanOrchestrator,
    CloudDiscoveryEngine, 
    CloudProvider,
    discover_cloud_targets,
    print_cloud_banner
)

def add_cloud_arguments(parser):
    """Add cloud scanning arguments to argument parser"""
    
    # Cloud Scanning argument group
    cloudgroup = parser.add_argument_group('☁️ Cloud Infrastructure Scanning')
    
    cloudgroup.add_argument('--cloud-scan', action='store_true',
                           help='🌐 Enable cloud infrastructure scanning')
    
    cloudgroup.add_argument('--cloud-providers', 
                           choices=['aws', 'azure', 'gcp', 'digitalocean', 'all'],
                           nargs='+', default=['all'],
                           help='☁️ Cloud providers to scan (default: all)')
    
    cloudgroup.add_argument('--cloud-regions',
                           help='🌍 Specific cloud regions to scan (comma-separated)')
    
    cloudgroup.add_argument('--cloud-tags',
                           help='🏷️ Filter assets by tags (format: key1=value1,key2=value2)')
    
    cloudgroup.add_argument('--cloud-types',
                           choices=['ec2', 'rds', 'elb', 's3', 'lambda', 'all'],
                           nargs='+', default=['all'],
                           help='🔧 Cloud resource types to include')
    
    cloudgroup.add_argument('--cloud-output',
                           default='cloud_scan_results',
                           help='📁 Cloud scan results directory')
    
    cloudgroup.add_argument('--cloud-only', action='store_true',
                           help='🎯 Only perform cloud discovery (no traditional scanning)')
    
    cloudgroup.add_argument('--cloud-credentials',
                           help='🔑 Path to cloud credentials file')
    
    cloudgroup.add_argument('--export-cloud-targets', 
                           help='📋 Export discovered cloud targets to file')
    
    cloudgroup.add_argument('--cloud-parallel', type=int, default=5,
                           help='⚡ Number of parallel cloud scans (default: 5)')

def enhanced_main_with_cloud():
    """Enhanced main function with cloud scanning integration"""
    
    # ... existing argument parsing code ...
    
    # Add cloud arguments
    add_cloud_arguments(parser)
    
    args = parser.parse_args()
    
    # Handle cloud-specific operations
    if args.cloud_scan or args.cloud_only:
        
        # Display cloud banner
        print_cloud_banner()
        
        # Parse cloud tags if provided
        cloud_tags = {}
        if args.cloud_tags:
            for tag_pair in args.cloud_tags.split(','):
                if '=' in tag_pair:
                    key, value = tag_pair.split('=', 1)
                    cloud_tags[key.strip()] = value.strip()
        
        # Convert provider strings to enums
        providers = []
        if 'all' not in args.cloud_providers:
            for provider in args.cloud_providers:
                try:
                    providers.append(CloudProvider(provider.lower()))
                except ValueError:
                    logger.warning(f"Unknown cloud provider: {provider}")
        
        # Cloud scanning workflow
        if args.cloud_only:
            # Cloud discovery only
            asyncio.run(cloud_discovery_only(providers, cloud_tags, args))
        else:
            # Integrated cloud + traditional scanning
            asyncio.run(integrated_cloud_scanning(providers, cloud_tags, args))
    
    # ... rest of existing main function ...

async def cloud_discovery_only(providers, cloud_tags, args):
    """Cloud discovery only workflow"""
    
    print(f"{Fore.CYAN}🌐 Starting cloud asset discovery...{Style.RESET_ALL}")
    
    discovery_engine = CloudDiscoveryEngine()
    
    if cloud_tags:
        assets = await discovery_engine.discover_by_tags(cloud_tags)
    else:
        assets = await discovery_engine.discover_all_assets(providers)
    
    print(f"\n{Fore.GREEN}☁️ CLOUD DISCOVERY RESULTS{Style.RESET_ALL}")
    print("=" * 50)
    
    # Group assets by provider and type
    by_provider = {}
    for asset in assets:
        provider = asset.provider.value
        if provider not in by_provider:
            by_provider[provider] = {}
        
        asset_type = asset.type.value
        if asset_type not in by_provider[provider]:
            by_provider[provider][asset_type] = []
            
        by_provider[provider][asset_type].append(asset)
    
    # Display results
    for provider, types in by_provider.items():
        print(f"\n{Fore.YELLOW}{provider.upper()}{Style.RESET_ALL}")
        for asset_type, asset_list in types.items():
            print(f"  📦 {asset_type}: {len(asset_list)} assets")
            
            if args.verbose:
                for asset in asset_list[:5]:  # Show first 5
                    ip = asset.scannable_ip or "No IP"
                    print(f"    - {asset.name} ({ip})")
                if len(asset_list) > 5:
                    print(f"    ... and {len(asset_list) - 5} more")
    
    # Export targets if requested
    if args.export_cloud_targets:
        targets = [asset.to_nmap_target() for asset in assets if asset.to_nmap_target()]
        
        with open(args.export_cloud_targets, 'w') as f:
            for target in targets:
                f.write(f"{target}\n")
                
        print(f"\n{Fore.GREEN}📋 Exported {len(targets)} targets to {args.export_cloud_targets}{Style.RESET_ALL}")

async def integrated_cloud_scanning(providers, cloud_tags, args):
    """Integrated cloud and traditional scanning workflow"""
    
    print(f"{Fore.CYAN}🌐 Starting integrated cloud scanning workflow...{Style.RESET_ALL}")
    
    # Initialize cloud orchestrator
    orchestrator = CloudScanOrchestrator(None)  # Would pass actual nmap automator
    
    # Execute cloud workflow
    scan_options = {
        'output_dir': args.cloud_output,
        'parallel_scans': args.cloud_parallel,
        'evasion_profile': getattr(args, 'evasion', None)
    }
    
    results = await orchestrator.cloud_scan_workflow(
        providers=providers,
        tag_filters=cloud_tags if cloud_tags else None,
        scan_options=scan_options
    )
    
    # Display results
    print(f"\n{Fore.GREEN}☁️ CLOUD SCAN COMPLETED{Style.RESET_ALL}")
    print("=" * 50)
    print(f"Assets Discovered: {results['assets_discovered']}")
    print(f"Assets Scanned: {results['assets_scanned']}")
    print(f"Scan Duration: {results['scan_duration']:.2f} seconds")
    
    # Show cloud-specific findings
    if results['cloud_specific_findings']:
        print(f"\n{Fore.RED}🚨 CLOUD SECURITY FINDINGS{Style.RESET_ALL}")
        print("-" * 30)
        
        for finding in results['cloud_specific_findings']:
            severity_color = Fore.RED if finding['severity'] == 'high' else Fore.YELLOW
            print(f"{severity_color}[{finding['severity'].upper()}] {finding['description']}{Style.RESET_ALL}")
            print(f"  Asset: {finding['asset']}")
            print(f"  Recommendation: {finding['recommendation']}")
            print()
    
    # Show recommendations
    if results['recommendations']:
        print(f"\n{Fore.CYAN}💡 CLOUD SECURITY RECOMMENDATIONS{Style.RESET_ALL}")
        print("-" * 40)
        
        for rec in results['recommendations']:
            priority_color = Fore.RED if rec['priority'] == 'high' else Fore.YELLOW
            print(f"{priority_color}[{rec['priority'].upper()}] {rec['title']}{Style.RESET_ALL}")
            print(f"  {rec['description']}")
            print(f"  Action: {rec['recommendation']}")
            print()
    
    # Save results
    results_file = f"{args.cloud_output}/cloud_scan_results_{int(time.time())}.json"
    os.makedirs(args.cloud_output, exist_ok=True)
    
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"{Fore.GREEN}📄 Detailed results saved to: {results_file}{Style.RESET_ALL}")

# Example of how existing functions would be enhanced
def enhanced_build_nmap_command(target, ports=None, scan_type="-sV", extra_args=None, 
                              output_basename=None, xml=False, evasion_profile=None,
                              cloud_asset=None):
    """Enhanced command building with cloud asset context"""
    
    # Start with existing logic
    args = build_nmap_command(target, ports, scan_type, extra_args, 
                             output_basename, xml, evasion_profile)
    
    # Add cloud-specific optimizations
    if cloud_asset:
        
        # Cloud timing optimization
        if cloud_asset.provider == CloudProvider.AWS:
            # AWS instances can handle more aggressive scanning
            if '-T' not in ' '.join(args):
                args.extend(['-T4'])
                
        # Cloud-specific port selection
        if cloud_asset.type == CloudResourceType.RDS_DATABASES:
            # Focus on database ports
            db_ports = [1433, 1521, 3306, 5432, 6379, 27017]
            if cloud_asset.ports:
                db_ports.extend(cloud_asset.ports)
            
            # Replace or add port specification
            for i, arg in enumerate(args):
                if arg == '-p' and i + 1 < len(args):
                    args[i + 1] = ','.join(map(str, set(db_ports)))
                    break
            else:
                args.extend(['-p', ','.join(map(str, set(db_ports)))])
                
        # Add cloud provider tag to output
        if output_basename and cloud_asset:
            cloud_suffix = f"_cloud_{cloud_asset.provider.value}_{cloud_asset.type.value}"
            # Find and modify output file arguments
            for i, arg in enumerate(args):
                if arg in ['-oN', '-oX'] and i + 1 < len(args):
                    base, ext = os.path.splitext(args[i + 1])
                    args[i + 1] = f"{base}{cloud_suffix}{ext}"
    
    return args

if __name__ == '__main__':
    enhanced_main_with_cloud()