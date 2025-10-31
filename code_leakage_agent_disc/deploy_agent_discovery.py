#!/usr/bin/env python3
"""
Deployment script for Agent Discovery Tool
Sets up the environment and installs dependencies.
"""

import os
import subprocess
import sys
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("ERROR: Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"[OK] Python version: {sys.version.split()[0]}")

def install_dependencies():
    """Install required Python packages"""
    print("Installing dependencies...")
    
    requirements = [
        "gitpython>=3.1.40",
        "rich>=13.0.0",
        "urllib3>=2.0.0",
        "requests>=2.31.0",
        "pydantic>=2.0.0",
        "jinja2>=3.1.0"
    ]
    
    for package in requirements:
        try:
            print(f"Installing {package}...")
            subprocess.run([sys.executable, "-m", "pip", "install", package], 
                         check=True, capture_output=True)
            print(f"[OK] {package} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to install {package}: {e}")
            return False
    
    return True

def create_directories():
    """Create necessary directories"""
    print("Creating directories...")
    
    directories = [
        "reports",
        "logs", 
        "temp",
        "configs"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"[OK] Created directory: {directory}")

def create_config_file():
    """Create default configuration file"""
    print("Creating configuration file...")
    
    config_content = """[discovery]
scan_all_files = true
max_file_size = 10485760
exclude_patterns = ["test_*", "*_test.py", "venv/*", "node_modules/*", "__pycache__/*"]

[risk_analysis]
enable_llm_analysis = false
risk_thresholds = { low = 0.3, medium = 0.7, high = 1.0 }

[output]
default_format = "json"
include_raw_data = true
include_risk_analysis = true
timestamp_format = "%Y-%m-%d %H:%M:%S"

[logging]
level = "INFO"
log_to_file = true
log_to_console = true
"""
    
    config_file = Path("configs/agent_discovery.toml")
    if not config_file.exists():
        config_file.write_text(config_content)
        print("[OK] Created configuration file: configs/agent_discovery.toml")
    else:
        print("[OK] Configuration file already exists")

def create_sample_scripts():
    """Create sample batch and PowerShell scripts"""
    print("Creating sample scripts...")
    
    # Batch script
    batch_content = """@echo off
REM Agent Discovery Tool - Windows Batch Script
REM Usage: scan_agents.bat <repo_url> <token> [format] [output_file]

if "%~2"=="" (
    echo Usage: scan_agents.bat ^<repo_url^> ^<token^> [format] [output_file]
    echo Example: scan_agents.bat https://github.com/user/repo ghp_1234567890abcdef1234567890abcdef1234 json
    exit /b 1
)

set REPO_URL=%~1
set TOKEN=%~2
set FORMAT=%~3
set OUTPUT=%~4

if "%FORMAT%"=="" set FORMAT=json

if "%OUTPUT%"=="" (
    python scripts_for_scans\\agent_discovery.py --repo-url "%REPO_URL%" --token "%TOKEN%" --format %FORMAT%
) else (
    python scripts_for_scans\\agent_discovery.py --repo-url "%REPO_URL%" --token "%TOKEN%" --format %FORMAT% --output "%OUTPUT%"
)
"""
    
    batch_file = Path("scan_agents.bat")
    if not batch_file.exists():
        batch_file.write_text(batch_content)
        print("[OK] Created batch script: scan_agents.bat")
    else:
        print("[OK] Batch script already exists")
    
    # PowerShell script
    ps_content = """# Agent Discovery Tool - PowerShell Script
# Usage: .\\scan_agents.ps1 -RepoUrl <url> -Token <token> [-Format <format>] [-Output <file>]

param(
    [Parameter(Mandatory=$true)][string]$RepoUrl,
    [Parameter(Mandatory=$true)][string]$Token,
    [string]$Format = "json",
    [string]$Output = "",
    [switch]$Verbose
)

Write-Host "Starting Agent Discovery..." -ForegroundColor Blue
Write-Host "Repository: $RepoUrl" -ForegroundColor Gray
Write-Host "Format: $Format" -ForegroundColor Gray

if ($Output) {
    Write-Host "Output file: $Output" -ForegroundColor Gray
    python scripts_for_scans\\agent_discovery.py --repo-url "$RepoUrl" --token "$Token" --format $Format --output "$Output"
} else {
    python scripts_for_scans\\agent_discovery.py --repo-url "$RepoUrl" --token "$Token" --format $Format
}

if ($LASTEXITCODE -eq 0) {
    Write-Host "Agent discovery completed successfully!" -ForegroundColor Green
} else {
    Write-Host "Agent discovery failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}
"""
    
    ps_file = Path("scan_agents.ps1")
    if not ps_file.exists():
        ps_file.write_text(ps_content)
        print("[OK] Created PowerShell script: scan_agents.ps1")
    else:
        print("[OK] PowerShell script already exists")

def create_readme():
    """Create README file"""
    print("Creating README file...")
    
    readme_content = """# Agent Discovery Tool

A powerful tool for discovering AI agents from GitHub repositories and analyzing their risk levels.

## Features

- **Agent Discovery**: Automatically discovers AI agents from GitHub repositories
- **Framework Detection**: Identifies Custom and LangChain agents
- **Risk Analysis**: Assesses agent risk levels based on role and tools
- **Multiple Output Formats**: JSON, CSV, and HTML reports
- **Tool Detection**: Automatically detects tools used by agents

## Quick Start

### 1. Setup

```bash
# Install dependencies
python scripts_for_scans/deploy_agent_discovery.py

# Or manually install
pip install -r requirements.txt
```

### 2. Basic Usage

```bash
# Using Python script directly
python scripts_for_scans/agent_discovery.py --repo-url "https://github.com/user/repo" --token "ghp_your_token_here"

# Using batch script (Windows)
scan_agents.bat "https://github.com/user/repo" "ghp_your_token_here" json

# Using PowerShell script
.\\scan_agents.ps1 -RepoUrl "https://github.com/user/repo" -Token "ghp_your_token_here" -Format json
```

### 3. Output Formats

- **JSON**: Detailed agent information with metadata
- **CSV**: Tabular format for analysis
- **HTML**: Rich formatted reports (coming soon)

## Configuration

Edit `configs/agent_discovery.toml` to customize:
- File scanning patterns
- Risk analysis thresholds
- Output preferences
- Logging settings

## Requirements

- Python 3.8+
- GitHub Personal Access Token
- Internet connection for repository cloning

## Examples

### Discover agents from a repository
```bash
python scripts_for_scans/agent_discovery.py \\
  --repo-url "https://github.com/microsoft/vscode" \\
  --token "ghp_your_token_here" \\
  --format json \\
  --output "reports/vscode_agents.json"
```

### Generate CSV report
```bash
python scripts_for_scans/agent_discovery.py \\
  --repo-url "https://github.com/openai/openai-python" \\
  --token "ghp_your_token_here" \\
  --format csv \\
  --output "reports/openai_agents.csv"
```

## Output Structure

### JSON Output
```json
{
  "scan_metadata": {
    "timestamp": "2024-01-01T00:00:00Z",
    "repository": "https://github.com/user/repo",
    "total_agents": 5,
    "scan_duration": "2.5s"
  },
  "agents": [
    {
      "id": "sha256_hash",
      "file_path": "src/agent.py",
      "role": "Code Assistant",
      "system_prompt": "You are a helpful...",
      "framework": "Custom",
      "risk_level": "medium",
      "risk_reason": "Has filesystem access tools",
      "tools": [
        {
          "name": "file_read",
          "description": "Tool for filesystem operations",
          "risk_level": "high"
        }
      ]
    }
  ]
}
```

### CSV Output
```csv
agent_id,file_path,role,framework,risk_level,risk_reason,tools_count
abc123,src/agent.py,Code Assistant,Custom,medium,"Has filesystem access",3
```

## Troubleshooting

### Common Issues

1. **Token Error**: Ensure your GitHub token is valid and has repository access
2. **Clone Error**: Check repository URL and network connectivity
3. **Permission Error**: Ensure write permissions for reports directory

### Logs

Check `logs/agent_discovery.log` for detailed error information.

## License

MIT License - See LICENSE file for details.
"""
    
    readme_file = Path("README.md")
    if not readme_file.exists():
        readme_file.write_text(readme_content)
        print("[OK] Created README file: README.md")
    else:
        print("[OK] README file already exists")

def main():
    """Main deployment function"""
    print("=" * 60)
    print("Agent Discovery Tool - Deployment Script")
    print("=" * 60)
    
    # Check Python version
    check_python_version()
    
    # Create directories
    create_directories()
    
    # Install dependencies
    if not install_dependencies():
        print("[ERROR] Dependency installation failed")
        sys.exit(1)
    
    # Create configuration file
    create_config_file()
    
    # Create sample scripts
    create_sample_scripts()
    
    # Create README
    create_readme()
    
    print("\n" + "=" * 60)
    print("[SUCCESS] Deployment completed successfully!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Set your GitHub token: $env:GITHUB_TOKEN='ghp_your_token_here'")
    print("2. Run a test scan: python agent_discovery.py --repo-url 'https://github.com/user/repo' --token 'ghp_your_token_here'")
    print("3. Check the reports/ directory for output files")
    print("\nFor more information, see README.md")

if __name__ == "__main__":
    main()
