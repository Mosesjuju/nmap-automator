#!/bin/bash
# NMAP Automator v1.3.0 Cloud Scanning Quickstart

echo "🚀 NMAP Automator Cloud Platform Quickstart"
echo "==========================================="

# Check if cloud scanning is available
if python3 nmap_automator_cloud.py --help > /dev/null 2>&1; then
    echo "✅ Cloud platform is ready!"
else
    echo "❌ Cloud platform setup incomplete"
    echo "Run: python3 cloud_transformation.py"
    exit 1
fi

echo ""
echo "🌐 Available Commands:"
echo ""
echo "1. Cloud Discovery Only:"
echo "   python3 nmap_automator_cloud.py --cloud-scan --cloud-only --export-cloud-targets targets.txt"
echo ""
echo "2. Multi-Cloud Security Assessment:"
echo "   python3 nmap_automator_cloud.py --cloud-scan --cloud-providers aws,azure --cloud-risk-analysis"
echo ""
echo "3. Integrated Cloud + Traditional Scanning:"
echo "   python3 nmap_automator_cloud.py --cloud-scan --targets 192.168.1.0/24 --evasion stealth"
echo ""
echo "4. Enterprise Security Report:"
echo "   python3 nmap_automator_cloud.py --cloud-scan --executive-report --cloud-compliance pci-dss"
echo ""

echo "📋 Next Steps:"
echo "1. Configure cloud credentials in cloud_credentials.conf"
echo "2. Test cloud discovery: python3 nmap_automator_cloud.py --cloud-scan --cloud-only --dry-run"
echo "3. Run your first cloud security assessment!"
