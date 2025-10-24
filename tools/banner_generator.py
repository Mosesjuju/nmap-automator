#!/usr/bin/env python3
"""
Banner Generator for NMAP Automator
Provides ASCII banners for various tools and operations
"""

def nmap_banner():
    """Classic NMAP banner"""
    return """
    ███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
    ████╗  ██║████╗ ████║██╔══██╗██╔══██╗
    ██╔██╗ ██║██╔████╔██║███████║██████╔╝
    ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
    ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
    ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
    
    NMAP AUTOMATOR v1.2.1
    Network Exploration & Security Auditing
    """

def securescout_banner():
    """SecureScout banner"""
    return """
    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
    ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  
    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  
    ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗
    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
    
    ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
    ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
    ███████╗██║     ██║   ██║██║   ██║   ██║   
    ╚════██║██║     ██║   ██║██║   ██║   ██║   
    ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   
    
    SECURESCOUT - Advanced Network Security Scanner
    Professional Penetration Testing & Vulnerability Assessment
    """

def nikto_banner():
    """Nikto scanner banner"""
    return """
    ███╗   ██╗██╗██╗  ██╗████████╗ ██████╗ 
    ████╗  ██║██║██║ ██╔╝╚══██╔══╝██╔═══██╗
    ██╔██╗ ██║██║█████╔╝    ██║   ██║   ██║
    ██║╚██╗██║██║██╔═██╗    ██║   ██║   ██║
    ██║ ╚████║██║██║  ██╗   ██║   ╚██████╔╝
    ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ 
    
    NIKTO - Web Server Scanner
    Comprehensive Web Application Security Testing
    """

def gobuster_banner():
    """Gobuster banner"""
    return """
     ██████╗  ██████╗ ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ 
    ██╔════╝ ██╔═══██╗██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
    ██║  ███╗██║   ██║██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝
    ██║   ██║██║   ██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗
    ╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║
     ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    
    GOBUSTER - Directory/File & DNS Busting Tool
    Fast Directory and Subdomain Discovery
    """

def masscan_banner():
    """Masscan banner"""
    return """
    ███╗   ███╗ █████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ████╗ ████║██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██╔████╔██║███████║███████╗███████╗██║     ███████║██╔██╗ ██║
    ██║╚██╔╝██║██╔══██║╚════██║╚════██║██║     ██╔══██║██║╚██╗██║
    ██║ ╚═╝ ██║██║  ██║███████║███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    
    MASSCAN - High-Speed Port Scanner
    Internet-scale Port Scanning at 10 million packets per second
    """

def vulnerability_scanner_banner():
    """Vulnerability scanner banner"""
    return """
    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
    ██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║
    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║
     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║
      ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    
    VULNERABILITY SCANNER - Advanced Security Assessment
    Comprehensive Vulnerability Detection & Analysis
    """

def tool_chain_banner():
    """Tool chain banner"""
    return """
    ████████╗ ██████╗  ██████╗ ██╗         ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
    ╚══██╔══╝██╔═══██╗██╔═══██╗██║        ██╔════╝██║  ██║██╔══██╗██║████╗  ██║
       ██║   ██║   ██║██║   ██║██║        ██║     ███████║███████║██║██╔██╗ ██║
       ██║   ██║   ██║██║   ██║██║        ██║     ██╔══██║██╔══██║██║██║╚██╗██║
       ██║   ╚██████╔╝╚██████╔╝███████╗   ╚██████╗██║  ██║██║  ██║██║██║ ╚████║
       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
    
    TOOL CHAIN - Integrated Security Tool Suite
    Automated Security Tool Orchestration & Management
    """

def performance_banner():
    """Performance monitoring banner"""
    return """
    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ███╗   ██╗ ██████╗███████╗
    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗████╗  ██║██╔════╝██╔════╝
    ██████╔╝█████╗  ██████╔╝█████╗  ██║   ██║██████╔╝██╔████╔██║███████║██╔██╗ ██║██║     █████╗  
    ██╔═══╝ ██╔══╝  ██╔══██╗██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║██║╚██╗██║██║     ██╔══╝  
    ██║     ███████╗██║  ██║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║██║ ╚████║╚██████╗███████╗
    ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝
    
    PERFORMANCE MONITOR - Real-Time System Analytics
    Advanced Performance Tracking & Resource Monitoring
    """

def get_banner(tool_name: str) -> str:
    """Get banner for specified tool"""
    banners = {
        'nmap': nmap_banner,
        'securescout': securescout_banner,
        'nikto': nikto_banner,
        'gobuster': gobuster_banner,
        'masscan': masscan_banner,
        'vulnerability': vulnerability_scanner_banner,
        'toolchain': tool_chain_banner,
        'performance': performance_banner
    }
    
    return banners.get(tool_name.lower(), nmap_banner)()

def display_banner(tool_name: str, color_code: str = "\033[92m"):
    """Display colored banner"""
    reset_color = "\033[0m"
    print(f"{color_code}{get_banner(tool_name)}{reset_color}")

if __name__ == "__main__":
    # Demo all banners
    tools = ['nmap', 'securescout', 'nikto', 'gobuster', 'masscan', 'vulnerability', 'toolchain', 'performance']
    for tool in tools:
        display_banner(tool)
        print("\n" + "="*80 + "\n")