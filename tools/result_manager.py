#!/usr/bin/env python3
"""
Result Manager for NMAP Automator
Handles result preview, save/discard prompts, and file management
"""

import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

class ResultManager:
    """Manages scan results with preview and save functionality"""
    
    def __init__(self, base_results_dir: str = "results"):
        self.base_results_dir = Path(base_results_dir)
        self.tool_directories = {
            'nmap': 'nmap_scans',
            'nikto': 'nikto_scans', 
            'gobuster': 'gobuster_scans',
            'masscan': 'masscan_scans',
            'vulnerability': 'vulnerability_scans',
            'toolchain': 'tool_chain_results',
            'performance': 'performance_logs'
        }
        self._ensure_directories()
        
    def _ensure_directories(self):
        """Ensure all result directories exist"""
        for tool, directory in self.tool_directories.items():
            dir_path = self.base_results_dir / directory
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def preview_result(self, result_content: str, result_type: str = "scan") -> None:
        """Preview result content before saving"""
        print(f"\n{'='*80}")
        print(f"🔍 RESULT PREVIEW - {result_type.upper()}")
        print(f"{'='*80}")
        
        # Show first 50 lines of content for preview
        lines = result_content.split('\n')
        preview_lines = min(50, len(lines))
        
        for i, line in enumerate(lines[:preview_lines]):
            print(f"{i+1:3d}: {line}")
        
        if len(lines) > preview_lines:
            print(f"\n... and {len(lines) - preview_lines} more lines")
        
        print(f"\n{'='*80}")
        print(f"📊 Result Summary:")
        print(f"   Total Lines: {len(lines)}")
        print(f"   Content Size: {len(result_content)} bytes")
        print(f"   Preview Showing: {preview_lines}/{len(lines)} lines")
        print(f"{'='*80}")
    
    def get_save_decision(self) -> bool:
        """Get user decision to save or discard results"""
        while True:
            print(f"\n💾 Save Options:")
            print(f"   [S] Save results")
            print(f"   [D] Discard results")
            print(f"   [P] Preview again")
            
            choice = input("Choose an option [S/D/P]: ").strip().upper()
            
            if choice in ['S', 'SAVE']:
                return True
            elif choice in ['D', 'DISCARD']:
                return False
            elif choice in ['P', 'PREVIEW']:
                return None  # Signal to preview again
            else:
                print("❌ Invalid choice. Please enter S, D, or P.")
    
    def get_file_details(self, tool_name: str, target: str) -> Dict[str, str]:
        """Get filename and file type from user"""
        # Generate default filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"{target}_{timestamp}"
        
        print(f"\n📝 File Details:")
        print(f"   Tool: {tool_name}")
        print(f"   Target: {target}")
        print(f"   Default filename: {default_filename}")
        
        # Get custom filename
        custom_name = input(f"\n📄 Enter filename (press Enter for default): ").strip()
        filename = custom_name if custom_name else default_filename
        
        # Get file type
        print(f"\n📋 Available file types:")
        print(f"   [1] .txt (Plain text)")
        print(f"   [2] .xml (XML format)")
        print(f"   [3] .json (JSON format)")
        print(f"   [4] .html (HTML report)")
        print(f"   [5] .csv (CSV format)")
        
        file_extensions = {
            '1': '.txt',
            '2': '.xml', 
            '3': '.json',
            '4': '.html',
            '5': '.csv'
        }
        
        while True:
            choice = input("Select file type [1-5]: ").strip()
            if choice in file_extensions:
                extension = file_extensions[choice]
                break
            else:
                print("❌ Invalid choice. Please select 1-5.")
        
        return {
            'filename': filename,
            'extension': extension,
            'full_filename': f"{filename}{extension}"
        }
    
    def save_result(self, content: str, tool_name: str, target: str, 
                   filename: Optional[str] = None, extension: Optional[str] = None) -> str:
        """Save result to appropriate directory"""
        
        # Get tool directory
        tool_dir = self.tool_directories.get(tool_name.lower(), 'nmap_scans')
        save_path = self.base_results_dir / tool_dir
        
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{target}_{timestamp}"
        
        if not extension:
            extension = '.txt'
        
        # Ensure extension starts with dot
        if not extension.startswith('.'):
            extension = f".{extension}"
        
        full_filename = f"{filename}{extension}"
        file_path = save_path / full_filename
        
        # Save file
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"✅ Result saved successfully:")
            print(f"   📁 Directory: {tool_dir}/")
            print(f"   📄 Filename: {full_filename}")
            print(f"   📍 Full path: {file_path}")
            
            return str(file_path)
            
        except Exception as e:
            print(f"❌ Error saving file: {e}")
            return ""
    
    def process_result(self, content: str, tool_name: str, target: str, 
                      auto_save: bool = False) -> Optional[str]:
        """Complete result processing workflow"""
        
        if not auto_save:
            # Preview the result
            self.preview_result(content, f"{tool_name} scan")
            
            # Get save decision
            while True:
                decision = self.get_save_decision()
                
                if decision is None:  # Preview again
                    self.preview_result(content, f"{tool_name} scan")
                    continue
                elif decision:  # Save
                    break
                else:  # Discard
                    print("🗑️  Results discarded.")
                    return None
            
            # Get file details
            file_details = self.get_file_details(tool_name, target)
            
            # Save result
            return self.save_result(
                content, 
                tool_name, 
                target,
                file_details['filename'],
                file_details['extension']
            )
        else:
            # Auto-save with default settings
            return self.save_result(content, tool_name, target)
    
    def list_results(self, tool_name: Optional[str] = None) -> Dict[str, List[str]]:
        """List all saved results"""
        results = {}
        
        if tool_name:
            # List results for specific tool
            tool_dirs = [self.tool_directories.get(tool_name.lower(), 'nmap_scans')]
        else:
            # List all results
            tool_dirs = self.tool_directories.values()
        
        for tool_dir in tool_dirs:
            dir_path = self.base_results_dir / tool_dir
            if dir_path.exists():
                files = [f.name for f in dir_path.iterdir() if f.is_file()]
                results[tool_dir] = sorted(files)
        
        return results
    
    def get_result_stats(self) -> Dict[str, Any]:
        """Get statistics about saved results"""
        stats = {
            'total_files': 0,
            'total_size_mb': 0,
            'by_tool': {}
        }
        
        for tool, tool_dir in self.tool_directories.items():
            dir_path = self.base_results_dir / tool_dir
            if dir_path.exists():
                files = list(dir_path.iterdir())
                file_count = len([f for f in files if f.is_file()])
                total_size = sum(f.stat().st_size for f in files if f.is_file())
                
                stats['by_tool'][tool] = {
                    'files': file_count,
                    'size_mb': round(total_size / 1024 / 1024, 2)
                }
                
                stats['total_files'] += file_count
                stats['total_size_mb'] += stats['by_tool'][tool]['size_mb']
        
        stats['total_size_mb'] = round(stats['total_size_mb'], 2)
        return stats


def main():
    """Demo function for result manager"""
    print("📁 NMAP Automator Result Manager Demo")
    print("=" * 50)
    
    manager = ResultManager()
    
    # Demo result content
    demo_content = """
# NMAP Scan Results
Target: example.com
Scan Date: 2025-10-23

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2
80/tcp   open  http    Apache 2.4.41
443/tcp  open  https   Apache 2.4.41

# Vulnerability Assessment
- No critical vulnerabilities found
- SSL/TLS configuration appears secure
- SSH version is up to date

# Recommendations
1. Enable fail2ban for SSH protection
2. Implement web application firewall
3. Regular security updates recommended
"""
    
    # Process result with preview
    result_path = manager.process_result(
        demo_content, 
        "nmap", 
        "example.com"
    )
    
    if result_path:
        print(f"\n📊 Demo completed - File saved to: {result_path}")
    
    # Show statistics
    stats = manager.get_result_stats()
    print(f"\n📈 Result Statistics:")
    print(f"   Total Files: {stats['total_files']}")
    print(f"   Total Size: {stats['total_size_mb']} MB")


if __name__ == "__main__":
    main()