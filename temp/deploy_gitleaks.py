#!/usr/bin/env python3
"""
Production deployment script for GitLeaks scanning.
This script sets up GitLeaks in a production environment without Docker dependency.
"""

import os
import sys
import json
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, Any, Optional

def create_production_structure():
    """Create the production directory structure."""
    base_dir = Path.cwd()
    
    # Create directory structure
    dirs = [
        "tools",
        "configs", 
        "reports",
        "logs",
        "temp"
    ]
    
    for dir_name in dirs:
        dir_path = base_dir / dir_name
        dir_path.mkdir(exist_ok=True)
        print(f"Created directory: {dir_path}")

def download_gitleaks_binary():
    """Download and setup GitLeaks binary."""
    tools_dir = Path.cwd() / "tools"
    gitleaks_exe = tools_dir / "gitleaks.exe"
    
    if gitleaks_exe.exists():
        print(f"GitLeaks already exists: {gitleaks_exe}")
        return str(gitleaks_exe)
    
    print("Downloading GitLeaks binary...")
    
    try:
        # Get latest release info
        with urllib.request.urlopen("https://api.github.com/repos/gitleaks/gitleaks/releases/latest") as response:
            release_data = json.loads(response.read().decode())
        
        # Find Windows binary (prefer x64 over ARM)
        windows_asset = None
        for asset in release_data["assets"]:
            if "windows" in asset["name"].lower() and asset["name"].endswith(".zip"):
                # Prefer x64 over ARM
                if "x64" in asset["name"].lower() or "amd64" in asset["name"].lower():
                    windows_asset = asset
                    break
                elif windows_asset is None:  # Fallback to any Windows binary
                    windows_asset = asset
        
        if not windows_asset:
            raise RuntimeError("Could not find Windows binary in latest release")
        
        download_url = windows_asset["browser_download_url"]
        zip_path = tools_dir / "gitleaks.zip"
        
        print(f"Downloading {windows_asset['name']}...")
        
        # Download the zip file
        with urllib.request.urlopen(download_url) as response:
            with open(zip_path, 'wb') as f:
                f.write(response.read())
        
        # Extract the zip file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(tools_dir)
        
        # Find the extracted exe file
        for file in tools_dir.iterdir():
            if file.name.startswith("gitleaks") and file.suffix == ".exe":
                file.rename(gitleaks_exe)
                break
        
        # Clean up
        zip_path.unlink(missing_ok=True)
        
        if gitleaks_exe.exists():
            print(f"GitLeaks downloaded successfully: {gitleaks_exe}")
            return str(gitleaks_exe)
        else:
            raise RuntimeError("Failed to extract GitLeaks executable")
            
    except Exception as e:
        print(f"Failed to download GitLeaks: {e}")
        raise

def create_gitleaks_config():
    """Create a production GitLeaks configuration file."""
    config_dir = Path.cwd() / "configs"
    config_file = config_dir / "gitleaks.toml"
    
    # Production-ready GitLeaks configuration
    config_content = '''# GitLeaks Production Configuration
# This configuration is optimized for production scanning

[gitleaks]
    # Scan all files, not just git-tracked ones
    scanAllFiles = true
    
    # Redact secrets in output
    redact = true
    
    # Verbose logging
    verbose = true
    
    # Exit code 0 even if leaks are found (useful for CI/CD)
    # exitCode = 0
    
    # Maximum file size to scan (in bytes)
    maxFileSize = 1048576  # 1MB

# Custom rules for your organization
# Add your custom rules here as needed

# Exclude common false positives
[[rules.exclude]]
    description = "Exclude test files"
    path = ".*test.*|.*spec.*|.*mock.*"

[[rules.exclude]]
    description = "Exclude documentation"
    path = ".*readme.*|.*doc.*|.*example.*"
'''
    
    with open(config_file, 'w', encoding='utf-8') as f:
        f.write(config_content)
    
    print(f"Created GitLeaks config: {config_file}")
    return str(config_file)

def create_batch_scan_script():
    """Create a batch script for easy scanning."""
    batch_content = '''@echo off
REM GitLeaks Production Scan Script
REM Usage: scan_repo.bat <repo_url> [output_dir]

set REPO_URL=%1
set OUTPUT_DIR=%2

if "%REPO_URL%"=="" (
    echo Usage: scan_repo.bat ^<repo_url^> [output_dir]
    echo Example: scan_repo.bat https://github.com/owner/repo
    exit /b 1
)

if "%OUTPUT_DIR%"=="" set OUTPUT_DIR=reports

echo Starting GitLeaks scan for: %REPO_URL%
echo Output directory: %OUTPUT_DIR%

python gitleaks_scan.py --repo-url "%REPO_URL%" --output-dir "%OUTPUT_DIR%"

echo Scan completed. Check %OUTPUT_DIR% for results.
'''
    
    batch_file = Path.cwd() / "scan_repo.bat"
    with open(batch_file, 'w', encoding='utf-8') as f:
        f.write(batch_content)
    
    print(f"Created batch script: {batch_file}")

def create_powershell_script():
    """Create a PowerShell script for advanced scanning."""
    ps_content = '''# GitLeaks Production Scan Script (PowerShell)
# Usage: .\scan_repo.ps1 -RepoUrl "https://github.com/owner/repo" -OutputDir "reports"

param(
    [Parameter(Mandatory=$true)]
    [string]$RepoUrl,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "reports",
    
    [Parameter(Mandatory=$false)]
    [switch]$ScanHistory,
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "configs\gitleaks.toml"
)

Write-Host "Starting GitLeaks scan for: $RepoUrl" -ForegroundColor Yellow
Write-Host "Output directory: $OutputDir" -ForegroundColor Cyan

# Create output directory if it doesn't exist
if (!(Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir
}

# Run the scan
$scanArgs = @(
    "python", "gitleaks_scan.py",
    "--repo-url", $RepoUrl,
    "--output-dir", $OutputDir
)

if ($ScanHistory) {
    $scanArgs += "--scan-history"
}

if (Test-Path $ConfigFile) {
    $scanArgs += "--config", $ConfigFile
}

& $scanArgs[0] $scanArgs[1..($scanArgs.Length-1)]

Write-Host "Scan completed. Check $OutputDir for results." -ForegroundColor Green
'''
    
    ps_file = Path.cwd() / "scan_repo.ps1"
    with open(ps_file, 'w', encoding='utf-8') as f:
        f.write(ps_content)
    
    print(f"Created PowerShell script: {ps_file}")

def create_requirements_file():
    """Create requirements.txt for production deployment."""
    requirements = '''# GitLeaks Production Requirements
gitpython>=3.1.0
rich>=13.0.0
urllib3>=1.26.0
'''
    
    req_file = Path.cwd() / "requirements.txt"
    with open(req_file, 'w', encoding='utf-8') as f:
        f.write(requirements)
    
    print(f"Created requirements file: {req_file}")

def create_readme():
    """Create a comprehensive README for production deployment."""
    readme_content = '''# GitLeaks Production Deployment

This directory contains a production-ready GitLeaks scanning solution that works without Docker dependencies.

## Directory Structure
```
scripts_for_scans/
├── gitleaks_scan.py          # Main scanning script
├── deploy_gitleaks.py        # Deployment script
├── scan_repo.bat            # Windows batch script
├── scan_repo.ps1            # PowerShell script
├── requirements.txt         # Python dependencies
├── tools/                   # GitLeaks binary (auto-downloaded)
├── configs/                 # Configuration files
├── reports/                 # Scan results
├── logs/                    # Log files
└── temp/                    # Temporary files
```

## Quick Start

1. **Deploy the solution:**
   ```cmd
   python deploy_gitleaks.py
   ```

2. **Install Python dependencies:**
   ```cmd
   pip install -r requirements.txt
   ```

3. **Scan a repository:**
   ```cmd
   scan_repo.bat https://github.com/owner/repo
   ```

## Advanced Usage

### PowerShell Script
```powershell
.\scan_repo.ps1 -RepoUrl "https://github.com/owner/repo" -OutputDir "reports" -ScanHistory
```

### Python Script Direct
```python
from gitleaks_scan import run_gitleaks_scan

result = run_gitleaks_scan(
    repo_url="https://github.com/owner/repo",
    redact=True,
    scan_history=False
)
```

## Configuration

Edit `configs/gitleaks.toml` to customize scanning rules and exclusions.

## Production Considerations

1. **Security**: The script automatically downloads GitLeaks from GitHub releases
2. **Performance**: Uses shallow clones by default for faster scanning
3. **Logging**: All operations are logged with timestamps
4. **Error Handling**: Comprehensive error handling and recovery
5. **Cleanup**: Automatic cleanup of temporary files

## CI/CD Integration

### GitHub Actions
```yaml
- name: Run GitLeaks Scan
  run: |
    python scripts_for_scans/gitleaks_scan.py --repo-url ${{ github.repositoryUrl }}
```

### Azure DevOps
```yaml
- script: |
    python scripts_for_scans/gitleaks_scan.py --repo-url $(Build.Repository.Uri)
  displayName: 'Run GitLeaks Scan'
```

## Troubleshooting

1. **GitLeaks not found**: The script will auto-download it
2. **Network issues**: Check internet connectivity for GitHub API access
3. **Permission errors**: Ensure write permissions for tools/ and reports/ directories
4. **Memory issues**: For large repositories, consider using `--no-git` flag

## Support

For issues and questions, check the GitLeaks documentation:
https://github.com/gitleaks/gitleaks
'''
    
    readme_file = Path.cwd() / "README.md"
    with open(readme_file, 'w', encoding='utf-8') as f:
        f.write(readme_content)
    
    print(f"Created README: {readme_file}")

def main():
    """Main deployment function."""
    print("=== GitLeaks Production Deployment ===")
    print("Setting up GitLeaks scanning solution...")
    
    try:
        # Create directory structure
        create_production_structure()
        
        # Download GitLeaks binary
        gitleaks_path = download_gitleaks_binary()
        
        # Create configuration
        config_path = create_gitleaks_config()
        
        # Create helper scripts
        create_batch_scan_script()
        create_powershell_script()
        
        # Create requirements file
        create_requirements_file()
        
        # Create documentation
        create_readme()
        
        print("\n=== Deployment Complete ===")
        print("GitLeaks production setup completed successfully!")
        print(f"GitLeaks binary: {gitleaks_path}")
        print(f"Configuration: {config_path}")
        print("\nNext steps:")
        print("1. Install Python dependencies: pip install -r requirements.txt")
        print("2. Test the setup: scan_repo.bat https://github.com/owner/repo")
        print("3. Check the README.md for detailed usage instructions")
        
    except Exception as e:
        print(f"Deployment failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
