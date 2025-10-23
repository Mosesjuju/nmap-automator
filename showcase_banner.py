#!/usr/bin/env python3
"""
Show off the complete Nmap Automator banner with full color display
"""
from colorama import Fore, Style, init

init(autoreset=True)

__version__ = "1.1.0"


def show_banner():
    banner = f"""
{Fore.CYAN}
                    ███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
                    ████╗  ██║████╗ ████║██╔══██╗██╔══██╗
                    ██╔██╗ ██║██╔████╔██║███████║██████╔╝
                    ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
                    ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
                    ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
{Style.RESET_ALL}
{Fore.RED}                        ═══════════════════════════════════════
                              A U T O M A T O R  v{__version__}
                        ═══════════════════════════════════════
{Style.RESET_ALL}
{Fore.GREEN}              [*] Network Mapper Automation & Orchestration Tool
              [*] Developed by: Moses Juju (@Mosesjuju)
              [*] "The quieter you become, the more you can hear"
{Style.RESET_ALL}
{Fore.CYAN}    ╔═══════════════════════════════════════════════════════════════════╗
    ║  {Fore.WHITE}Multi-target scanning{Fore.CYAN}  |  {Fore.WHITE}Scheduled automation{Fore.CYAN}  |  {Fore.WHITE}Vuln analysis{Fore.CYAN}  ║
    ╚═══════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)


if __name__ == "__main__":
    print(f"\n{Fore.CYAN}{'='*75}")
    print(f"               NMAP AUTOMATOR - ASCII BANNER SHOWCASE")
    print(f"{'='*75}{Style.RESET_ALL}\n")

    show_banner()

    # Removed Banner Features section and any yellow-colored lines per request
