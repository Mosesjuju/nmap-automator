#!/usr/bin/env python3
"""
Tool Chaining Framework for NMAP Automator v1.1.1
Provides dynamic security tool integration and execution pipeline
"""

import json
import os
import subprocess
import threading
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
from queue import Queue
import shutil

logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    """Tool execution status enum"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class TriggerType(Enum):
    """Tool trigger types"""
    PORT = "port"
    SERVICE = "service"
    NETWORK = "network_range"
    DOMAIN = "domain"
    CMS = "cms"
    PARAM = "param"


@dataclass
class ToolResult:
    """Container for tool execution results"""
    tool_name: str
    category: str
    status: ToolStatus
    start_time: float
    end_time: Optional[float]
    command: str
    stdout: str
    stderr: str
    exit_code: int
    output_file: Optional[str] = None
    parsed_results: Optional[Dict] = None
    

@dataclass
class ToolConfig:
    """Tool configuration container"""
    name: str
    category: str
    enabled: bool
    path: str
    description: str
    triggers: List[str]
    args: str
    timeout: int
    priority: int
    output_format: Optional[str] = None
    

class ToolRegistry:
    """Registry for managing available security tools"""
    
    def __init__(self, config_path: str = "tools.config.json"):
        self.config_path = config_path
        self.tools: Dict[str, ToolConfig] = {}
        self.categories: Dict[str, List[str]] = {}
        self.load_configuration()
        
    def load_configuration(self):
        """Load tool configuration from JSON file"""
        try:
            if not os.path.exists(self.config_path):
                # Fall back to example config
                example_path = "tools.config.example.json"
                if os.path.exists(example_path):
                    self.config_path = example_path
                else:
                    logger.warning(f"No tool configuration found at {self.config_path}")
                    return
                    
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                
            # Skip global settings, process tool categories
            for category, tools in config.items():
                if category == "tool_chaining":
                    continue
                    
                self.categories[category] = []
                
                for tool_name, tool_config in tools.items():
                    if not isinstance(tool_config, dict):
                        continue
                        
                    # Create ToolConfig object
                    tool = ToolConfig(
                        name=tool_name,
                        category=category,
                        enabled=tool_config.get('enabled', False),
                        path=tool_config.get('path', tool_name),
                        description=tool_config.get('description', ''),
                        triggers=tool_config.get('triggers', []),
                        args=tool_config.get('args', ''),
                        timeout=tool_config.get('timeout', 300),
                        priority=tool_config.get('priority', 99),
                        output_format=tool_config.get('output_format')
                    )
                    
                    self.tools[tool_name] = tool
                    self.categories[category].append(tool_name)
                    
            logger.info(f"Loaded {len(self.tools)} tools in {len(self.categories)} categories")
            
        except Exception as e:
            logger.error(f"Failed to load tool configuration: {e}")
            
    def get_tool(self, name: str) -> Optional[ToolConfig]:
        """Get tool configuration by name"""
        return self.tools.get(name)
        
    def get_tools_by_category(self, category: str) -> List[ToolConfig]:
        """Get all tools in a category"""
        tool_names = self.categories.get(category, [])
        return [self.tools[name] for name in tool_names if name in self.tools]
        
    def get_enabled_tools(self) -> List[ToolConfig]:
        """Get all enabled tools"""
        return [tool for tool in self.tools.values() if tool.enabled]
        
    def find_tools_by_trigger(self, trigger: str) -> List[ToolConfig]:
        """Find tools that match a specific trigger"""
        matching_tools = []
        for tool in self.tools.values():
            if tool.enabled and trigger in tool.triggers:
                matching_tools.append(tool)
        return sorted(matching_tools, key=lambda x: x.priority)
        
    def validate_tool_availability(self) -> Dict[str, bool]:
        """Check which tools are actually available on the system"""
        availability = {}
        for tool_name, tool_config in self.tools.items():
            availability[tool_name] = shutil.which(tool_config.path) is not None
        return availability


class ToolExecutor:
    """Handles tool execution and result management"""
    
    def __init__(self, output_dir: str = "tool_results"):
        self.output_dir = output_dir
        self.results: List[ToolResult] = []
        self.running_tools: Dict[str, subprocess.Popen] = {}
        self.ensure_output_dir()
        
    def ensure_output_dir(self):
        """Create output directory if it doesn't exist"""
        os.makedirs(self.output_dir, exist_ok=True)
        
    def execute_tool(self, tool: ToolConfig, target: str, context: Dict = None) -> ToolResult:
        """Execute a single tool against a target"""
        start_time = time.time()
        
        # Build command
        command = self._build_command(tool, target, context)
        
        # Create result object
        result = ToolResult(
            tool_name=tool.name,
            category=tool.category,
            status=ToolStatus.PENDING,
            start_time=start_time,
            end_time=None,
            command=command,
            stdout="",
            stderr="",
            exit_code=-1
        )
        
        try:
            logger.info(f"Executing {tool.name}: {command}")
            result.status = ToolStatus.RUNNING
            
            # Execute with timeout
            process = subprocess.Popen(
                command.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.running_tools[tool.name] = process
            
            try:
                stdout, stderr = process.communicate(timeout=tool.timeout)
                result.stdout = stdout
                result.stderr = stderr
                result.exit_code = process.returncode
                result.status = ToolStatus.COMPLETED if process.returncode == 0 else ToolStatus.FAILED
                
            except subprocess.TimeoutExpired:
                process.kill()
                result.status = ToolStatus.FAILED
                result.stderr = f"Tool timed out after {tool.timeout} seconds"
                logger.warning(f"{tool.name} timed out")
                
        except Exception as e:
            result.status = ToolStatus.FAILED
            result.stderr = str(e)
            logger.error(f"Failed to execute {tool.name}: {e}")
            
        finally:
            result.end_time = time.time()
            if tool.name in self.running_tools:
                del self.running_tools[tool.name]
                
        # Save output to file
        if result.stdout:
            output_file = os.path.join(
                self.output_dir,
                f"{tool.name}_{target.replace('/', '_')}_{int(start_time)}.txt"
            )
            try:
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                result.output_file = output_file
            except Exception as e:
                logger.error(f"Failed to save output for {tool.name}: {e}")
                
        self.results.append(result)
        return result
        
    def _build_command(self, tool: ToolConfig, target: str, context: Dict = None) -> str:
        """Build command line for tool execution"""
        command = f"{tool.path} {tool.args}"
        
        # Replace placeholders
        command = command.replace("{target}", target)
        
        if context:
            for key, value in context.items():
                command = command.replace(f"{{{key}}}", str(value))
                
        return command.strip()
        
    def get_results(self) -> List[ToolResult]:
        """Get all execution results"""
        return self.results
        
    def get_results_by_status(self, status: ToolStatus) -> List[ToolResult]:
        """Get results filtered by status"""
        return [r for r in self.results if r.status == status]
        

class ToolChain:
    """Main tool chaining orchestrator"""
    
    def __init__(self, config_path: str = "tools.config.json"):
        self.registry = ToolRegistry(config_path)
        self.executor = ToolExecutor()
        self.selected_tools: List[str] = []
        
    def analyze_scan_results(self, nmap_results: Dict) -> List[str]:
        """Analyze nmap results and determine which tools to run"""
        triggers = set()
        
        # Extract triggers from scan results
        if 'open_ports' in nmap_results:
            for port, service in nmap_results['open_ports']:
                triggers.add(f"port:{port}")
                if service:
                    triggers.add(f"service:{service}")
                    
        # Add network-based triggers
        if 'target_type' in nmap_results:
            if nmap_results['target_type'] == 'network':
                triggers.add("network_range")
            elif nmap_results['target_type'] == 'domain':
                triggers.add("domain")
                
        logger.info(f"Identified triggers: {triggers}")
        return list(triggers)
        
    def get_recommended_tools(self, triggers: List[str]) -> List[ToolConfig]:
        """Get recommended tools based on triggers"""
        recommended = set()
        
        for trigger in triggers:
            matching_tools = self.registry.find_tools_by_trigger(trigger)
            recommended.update(matching_tools)
            
        return sorted(list(recommended), key=lambda x: (x.category, x.priority))
        
    def execute_tool_chain(self, target: str, triggers: List[str], 
                          selected_tools: List[str] = None) -> List[ToolResult]:
        """Execute tool chain against target"""
        if selected_tools:
            tools_to_run = [self.registry.get_tool(name) for name in selected_tools]
            tools_to_run = [t for t in tools_to_run if t is not None]
        else:
            tools_to_run = self.get_recommended_tools(triggers)
            
        logger.info(f"Executing {len(tools_to_run)} tools against {target}")
        
        results = []
        for tool in tools_to_run:
            if tool.enabled:
                result = self.executor.execute_tool(tool, target)
                results.append(result)
                logger.info(f"{tool.name}: {result.status.value}")
                
        return results
        
    def get_available_tools_summary(self) -> Dict[str, Any]:
        """Get summary of all available tools"""
        availability = self.registry.validate_tool_availability()
        
        summary = {
            'categories': {},
            'total_tools': len(self.registry.tools),
            'enabled_tools': len(self.registry.get_enabled_tools()),
            'available_tools': sum(availability.values())
        }
        
        for category, tool_names in self.registry.categories.items():
            summary['categories'][category] = {
                'tools': [],
                'count': len(tool_names)
            }
            
            for tool_name in tool_names:
                tool = self.registry.get_tool(tool_name)
                if tool:
                    summary['categories'][category]['tools'].append({
                        'name': tool_name,
                        'description': tool.description,
                        'enabled': tool.enabled,
                        'available': availability.get(tool_name, False),
                        'priority': tool.priority
                    })
                    
        return summary


# CLI Helper Functions for integration with main script
def print_tool_chain_banner():
    """Print tool chaining banner"""
    from colorama import Fore, Style
    banner = f"""
{Fore.CYAN}    ╔═══════════════════════════════════════════════════════════════════╗
    ║                     🔗 TOOL CHAINING SYSTEM 🔗                    ║
    ║              Automated Security Tool Integration v1.1.1           ║  
    ╚═══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def show_available_tools(tool_chain: ToolChain):
    """Display available tools in a nice format"""
    from colorama import Fore, Style
    
    print_tool_chain_banner()
    summary = tool_chain.get_available_tools_summary()
    
    print(f"{Fore.GREEN}📊 Tool Chain Summary:{Style.RESET_ALL}")
    print(f"   Total Tools: {summary['total_tools']}")
    print(f"   Enabled: {summary['enabled_tools']}")
    print(f"   Available: {summary['available_tools']}")
    print()
    
    for category, info in summary['categories'].items():
        print(f"{Fore.YELLOW}📂 {category.upper().replace('_', ' ')}{Style.RESET_ALL}")
        for tool in info['tools']:
            status_icon = "✅" if tool['available'] else "❌"
            enabled_icon = "🔘" if tool['enabled'] else "⚪"
            print(f"   {status_icon} {enabled_icon} {tool['name']:<12} - {tool['description']}")
        print()


if __name__ == "__main__":
    # Test the tool chain system
    tool_chain = ToolChain()
    show_available_tools(tool_chain)