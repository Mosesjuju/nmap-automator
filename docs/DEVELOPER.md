# Developer Guide

## Overview

This project is a feature-rich CLI wrapper for Nmap that includes scheduling, vulnerability analysis with OpenAI integration, and Nikto chaining for web scans. It is designed to automate scan orchestration and output generation in various formats.

## Design Decisions

- **CLI Argument Grouping:** Commands are organized into logical groups for targets, scanning techniques, output options, etc.
- **Concurrency:** Worker threads (using Python's threading and Queue) are used to run scans concurrently.
- **XML Parsing:** The tool parses Nmap's XML output for detection of open ports, services, and vulnerabilities, which can trigger escalation scans.
- **AI Integration:** OpenAI API is used for vulnerability analysis by processing scan findings.
- **Nikto Chaining:** Automatically runs Nikto scans on targets with common web ports open (80/443) to obtain additional data.

## Assumptions

- Nmap and Nikto are installed and available in the system PATH.
- Users have valid API keys for OpenAI integration when required.
- Outputs are stored in a designated directory (default: `nmap_results`).

## Future Improvements

- **Enhanced Testing:** Extend unit and integration tests to cover more functionalities.
- **Error Handling:** Improve error handling and logging throughout the application.
- **Asynchronous Processing:** Consider refactoring parts of the code to use asyncio for improved performance.
- **Configuration Files:** Introduce a configuration file for more flexible runtime options.

