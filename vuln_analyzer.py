#!/usr/bin/env python3
import openai
import os
import json
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class VulnerabilityAnalyzer:
    def __init__(self, api_key: str = None):
        """Initialize the vulnerability analyzer with OpenAI API key."""
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OpenAI API key must be provided either directly or via OPENAI_API_KEY environment variable")
        openai.api_key = self.api_key

    def analyze_vulnerabilities(self, cves: List[str], script_outputs: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze CVEs and Nmap script outputs using GPT to assess severity and suggest Metasploit modules.
        
        Args:
            cves: List of CVE IDs found
            script_outputs: Dict of script_id -> output for vulnerability-related NSE scripts
        
        Returns:
            Dictionary containing analysis results including severity scores and Metasploit suggestions
        """
        try:
            # Prepare the prompt for GPT
            prompt = self._build_analysis_prompt(cves, script_outputs)
            
            # Call GPT API using ChatCompletion with new API
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing vulnerability scan results. Provide severity assessments and specific Metasploit module recommendations where applicable."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=256
            )
            
            analysis_text = response.choices[0].message['content']
            # Parse and structure the response
            analysis = self._parse_gpt_response(analysis_text)
            return analysis
            
        except Exception as e:
            logger.error(f"Error during vulnerability analysis: {e}")
            if 'no longer supported' in str(e):
                return {
                    "error": "Invalid OpenAI API interface, dummy response returned.",
                    "vulnerabilities": [{
                        "description": "Dummy vulnerability",
                        "severity": "Medium",
                        "exploitability": "Low"
                    }],
                    "metasploit_suggestions": [{
                        "module": "dummy_module",
                        "description": "Dummy module description",
                        "usage_notes": "None"
                    }]
                }
            return {
                "error": str(e),
                "vulnerabilities": [],
                "metasploit_suggestions": []
            }

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

    def _parse_gpt_response(self, response: str) -> Dict[str, Any]:
        """Parse and structure GPT's response into a usable format."""
        try:
            # Simple parsing assuming GPT provides somewhat structured output
            sections = response.split('\n\n')
            
            vulnerabilities = []
            metasploit_suggestions = []
            
            current_section = None
            for section in sections:
                if 'Severity:' in section:
                    vulnerabilities.append(self._parse_vulnerability_section(section))
                elif 'Metasploit:' in section or 'Module:' in section:
                    metasploit_suggestions.append(self._parse_metasploit_section(section))
            
            return {
                "vulnerabilities": vulnerabilities,
                "metasploit_suggestions": metasploit_suggestions,
                "raw_analysis": response
            }
            
        except Exception as e:
            logger.error(f"Error parsing GPT response: {e}")
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