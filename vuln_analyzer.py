#!/usr/bin/env python3
import openai
import os
import json
import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class VulnerabilityAnalyzer:
    def __init__(self, api_key: str = None, grok_api_key: str = None, use_grok: bool = False):
        """Initialize the vulnerability analyzer with API key."""
        self.use_grok = use_grok or grok_api_key is not None
        
        if self.use_grok:
            self.api_key = grok_api_key or os.getenv('GROK_API_KEY')
            if not self.api_key:
                raise ValueError("Grok API key must be provided either directly or via GROK_API_KEY environment variable")
            # Configure for Grok (xAI)
            openai.api_key = self.api_key
            openai.api_base = "https://api.x.ai/v1"
        else:
            self.api_key = api_key or os.getenv('OPENAI_API_KEY')
            if not self.api_key:
                raise ValueError("OpenAI API key must be provided either directly or via OPENAI_API_KEY environment variable")
            openai.api_key = self.api_key

    def analyze_vulnerabilities(self, xml_file_or_cves, script_outputs: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Analyze vulnerabilities from XML file or CVE list using AI to assess severity and suggest Metasploit modules.
        
        Args:
            xml_file_or_cves: Either path to XML file or List of CVE IDs found
            script_outputs: Dict of script_id -> output for vulnerability-related NSE scripts (optional)
        
        Returns:
            Dictionary containing analysis results including severity scores and Metasploit suggestions
        """
        try:
            # Handle different input types
            if isinstance(xml_file_or_cves, str) and xml_file_or_cves.endswith('.xml'):
                # Parse XML file
                cves, script_outputs = self._parse_xml_vulnerabilities(xml_file_or_cves)
            else:
                # Use provided CVE list
                cves = xml_file_or_cves if isinstance(xml_file_or_cves, list) else [xml_file_or_cves]
                script_outputs = script_outputs or {}
            
            if not cves and not script_outputs:
                return {
                    "message": "No vulnerabilities found in scan results",
                    "vulnerabilities": [],
                    "metasploit_suggestions": []
                }
            
            # Prepare the prompt for AI
            prompt = self._build_analysis_prompt(cves, script_outputs)
            
            # Use HTTP requests for Grok since OpenAI library has compatibility issues
            if self.use_grok:
                import requests
                url = "https://api.x.ai/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                data = {
                    "model": "grok-3",
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity expert analyzing vulnerability scan results. Provide detailed severity assessments and specific Metasploit module recommendations where applicable. Format your response as JSON with 'vulnerabilities' and 'metasploit_suggestions' arrays."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 1500
                }
                
                response_obj = requests.post(url, headers=headers, json=data, timeout=30)
                if response_obj.status_code != 200:
                    raise Exception(f"Grok API error: {response_obj.text}")
                
                response = response_obj.json()
                analysis_text = response['choices'][0]['message']['content']
            else:
                # Call OpenAI API
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert analyzing vulnerability scan results. Provide detailed severity assessments and specific Metasploit module recommendations where applicable. Format your response as JSON with 'vulnerabilities' and 'metasploit_suggestions' arrays."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=1500
                )
                analysis_text = response.choices[0].message['content']

            
            # Parse and structure the response
            analysis = self._parse_ai_response(analysis_text)
            
            # Save analysis to file if we have an XML file
            if isinstance(xml_file_or_cves, str) and xml_file_or_cves.endswith('.xml'):
                self._save_analysis_to_file(xml_file_or_cves, analysis)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error during vulnerability analysis: {e}")
            return {
                "error": str(e),
                "vulnerabilities": [],
                "metasploit_suggestions": []
            }

    def _parse_xml_vulnerabilities(self, xml_file: str) -> tuple:
        """Parse vulnerabilities from Nmap XML output."""
        cves = []
        script_outputs = {}
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Find all CVEs and script outputs
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    for script in port.findall('.//script'):
                        script_id = script.get('id', '')
                        script_output = script.get('output', '')
                        
                        # Store script output
                        if script_output:
                            script_outputs[script_id] = script_output
                        
                        # Look for CVEs in script output
                        if 'CVE' in script_output:
                            # Extract CVE IDs from script output
                            import re
                            cve_matches = re.findall(r'CVE-\d{4}-\d+', script_output)
                            cves.extend(cve_matches)
                        
                        # Also check script tables for CVE elements
                        for table in script.findall('.//table'):
                            if 'CVE' in table.get('key', ''):
                                cves.append(table.get('key'))
        
        except Exception as e:
            logger.error(f"Error parsing XML file {xml_file}: {e}")
        
        return list(set(cves)), script_outputs

    def _save_analysis_to_file(self, xml_file: str, analysis: Dict[str, Any]):
        """Save analysis results to a file next to the XML file."""
        try:
            analysis_file = xml_file.replace('.xml', '_analysis.json')
            with open(analysis_file, 'w') as f:
                json.dump(analysis, f, indent=2)
            logger.info(f"AI analysis saved to {analysis_file}")
        except Exception as e:
            logger.error(f"Error saving analysis to file: {e}")

    def _build_analysis_prompt(self, cves: List[str], script_outputs: Dict[str, str]) -> str:
        """Build a prompt for GPT analysis."""
        prompt_parts = [
            "Analyze these security findings and provide:\n",
            "1. Severity score (Critical/High/Medium/Low) for each vulnerability\n",
            "2. Exploitability assessment\n",
            "3. Specific Metasploit modules that could be used (if applicable)\n\n",
            "Findings:\n"
        ]
        
        if cves:
            prompt_parts.append("CVEs found:\n")
            prompt_parts.extend(f"- {cve}\n" for cve in cves)
        
        if script_outputs:
            prompt_parts.append("\nNmap Script Outputs:\n")
            for script_id, output in script_outputs.items():
                prompt_parts.append(f"\n{script_id}:\n{output}\n")
        
        return "".join(prompt_parts)

    def _parse_ai_response(self, response: str) -> Dict[str, Any]:
        """Parse and structure AI response into a usable format."""
        try:
            # Try to parse as JSON first
            try:
                json_response = json.loads(response)
                if isinstance(json_response, dict):
                    return json_response
            except json.JSONDecodeError:
                pass
            
            # Fallback to text parsing
            vulnerabilities = []
            metasploit_suggestions = []
            
            # Simple text parsing for structured responses
            sections = response.split('\n\n')
            
            for section in sections:
                if any(keyword in section.lower() for keyword in ['cve', 'vulnerability', 'severity']):
                    vuln = self._parse_vulnerability_section(section)
                    if vuln:
                        vulnerabilities.append(vuln)
                elif any(keyword in section.lower() for keyword in ['metasploit', 'module', 'exploit']):
                    msf = self._parse_metasploit_section(section)
                    if msf:
                        metasploit_suggestions.append(msf)
            
            return {
                "vulnerabilities": vulnerabilities,
                "metasploit_suggestions": metasploit_suggestions,
                "raw_analysis": response
            }
            
        except Exception as e:
            logger.error(f"Error parsing AI response: {e}")
            return {
                "error": f"Failed to parse analysis: {e}",
                "raw_analysis": response
            }

    def _parse_vulnerability_section(self, section: str) -> Dict[str, str]:
        """Parse a vulnerability analysis section."""
        lines = section.split('\n')
        result = {
            "description": lines[0],
            "severity": "Unknown",
            "exploitability": "Unknown"
        }
        
        for line in lines[1:]:
            if 'Severity:' in line:
                result["severity"] = line.split('Severity:')[1].strip()
            elif 'Exploitability:' in line:
                result["exploitability"] = line.split('Exploitability:')[1].strip()
        
        return result

    def _parse_metasploit_section(self, section: str) -> Dict[str, str]:
        """Parse a Metasploit suggestion section."""
        lines = section.split('\n')
        result = {
            "module": "",
            "description": "",
            "usage_notes": ""
        }
        
        for line in lines:
            if 'Module:' in line:
                result["module"] = line.split('Module:')[1].strip()
            elif 'Description:' in line:
                result["description"] = line.split('Description:')[1].strip()
            elif 'Usage:' in line:
                result["usage_notes"] = line.split('Usage:')[1].strip()
        
        return result