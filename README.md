# EDR Validation / Smoke Test Suite

A comprehensive, cross-platform testing tool for validating Endpoint Detection and Response (EDR) systems. This tool generates safe, non-destructive signals that modern EDR solutions (Bitdefender, Microsoft Defender, CrowdStrike, etc.) should detect and log.

## 🎯 Purpose

This tool is designed for:
- **SOC Validation**: Verify that your EDR system is properly detecting and logging security events
- **QA Testing**: Regression testing for EDR deployments and configuration changes
- **Demos**: Demonstrate EDR capabilities to stakeholders
- **Threat Hunting**: Generate test data for threat hunting exercises and SIEM tuning

## ✨ Features

- **Cross-Platform Support**: macOS, Windows, and Linux (Ubuntu 20.04+)
- **MITRE ATT&CK Mapped**: All tests are mapped to MITRE ATT&CK framework techniques
- **Safe & Non-Destructive**: User-level actions only, no exploits or privilege escalation
- **Structured Reporting**: Generates JSON reports with correlation IDs for EDR log searches
- **Automated Setup**: Platform-specific scripts handle Node.js installation automatically
- **Comprehensive Coverage**: 12 different attack techniques tested

## 📋 Prerequisites

- **Node.js 18+** (automatically installed by platform scripts if missing)
- **Platform-specific requirements**:
  - **Linux**: `curl` or `wget`, `sudo` privileges for package installation
  - **macOS**: Administrator privileges for Homebrew installation (if needed)
  - **Windows**: Git Bash, WSL, Cygwin, or MSYS2 environment

## 🚀 Quick Start

### One-Command Installation

Users can download and run with one command:

```bash
curl -fsSL https://github.com/espressolabs-com/EDR-tester/releases/download/v1.0.0/edr-tester.sh \
  -o /tmp/edr-tester.sh \
  && chmod +x /tmp/edr-tester.sh \
  && /tmp/edr-tester.sh
```

Or download and execute:

```bash
wget https://github.com/espressolabs-com/EDR-tester/releases/download/v1.0.0/edr-tester.sh -O /tmp/edr-tester.sh
chmod +x /tmp/edr-tester.sh
/tmp/edr-tester.sh
```

### Linux

```bash
chmod +x run-linux.sh
./run-linux.sh
```

### macOS

```bash
chmod +x run-macos.sh
./run-macos.sh
```

### Windows (Git Bash/WSL/Cygwin)

```bash
chmod +x run-windows.sh
./run-windows.sh
```

### Manual Execution

If Node.js is already installed:

```bash
node basic_tests.js
```

## 📖 Detailed Usage

### Platform Scripts

All platform scripts support the following options:

```bash
# Show help
./run-linux.sh --help

# Skip dependency installation (assumes Node.js is installed)
./run-linux.sh --skip-install

# Show version
./run-linux.sh --version
```

### Linux-Specific Notes

The Linux script (`run-linux.sh`) supports:
- **Ubuntu 20.04+**
- **Debian 10+**
- **CentOS/RHEL 7+**
- **Fedora 30+**
- Other distributions with `apt`, `yum`, or `dnf` package managers

Installation methods (in order of preference):
1. NodeSource repository (recommended for Node.js 18+)
2. System package manager (fallback)

### macOS-Specific Notes

The macOS script (`run-macos.sh`):
- Automatically installs Homebrew if missing
- Uses Homebrew to install Node.js
- Supports both Intel and Apple Silicon Macs

### Windows-Specific Notes

The Windows script (`run-windows.sh`) works in:
- **Git Bash** (Git for Windows)
- **WSL** (Windows Subsystem for Linux) - uses Linux installation method
- **Cygwin**
- **MSYS2**

Installation methods:
- **WSL**: Uses Linux package manager (apt/yum/dnf)
- **Git Bash/Cygwin**: Attempts Chocolatey or manual installer download
- **Native Windows**: Requires manual Node.js installation from nodejs.org

## 🧪 Test Coverage

The suite tests 12 different attack techniques, all mapped to MITRE ATT&CK:

| Test | MITRE ID | Tactic | Technique |
|------|----------|--------|-----------|
| EICAR signature test | T1204.002 | Execution | Malicious File |
| Process execution | T1059 | Execution | Command and Scripting Interpreter |
| LOLBin usage | T1218 | Defense Evasion | Signed Binary Proxy Execution |
| Persistence attempt | T1547.001 | Persistence | Registry Run Keys / Startup Folder |
| Credential access attempt | T1555 | Credential Access | Credentials from Password Stores |
| Outbound network connection | T1071.001 | Command and Control | Web Protocols |
| Filesystem discovery | T1083 | Discovery | File and Directory Discovery |
| Process tree behavior | T1057 | Discovery | Process Discovery |
| Encoded command execution | T1027 | Defense Evasion | Obfuscated/Encoded Commands |
| Ransomware-like behavior | T1486 | Impact | Data Encrypted for Impact |
| DNS exfiltration pattern | T1048 | Exfiltration | Exfiltration Over Alternative Protocol |
| File timestomping | T1070.006 | Defense Evasion | Timestomp |

### Test Details

#### 1. EICAR Signature Test
Creates a file containing the standard EICAR test string, which should trigger signature-based detection.

#### 2. Process Execution
Executes shell commands (`whoami`) to test process execution monitoring.

#### 3. LOLBin Usage
Tests usage of Living-off-the-Land Binaries (PowerShell on Windows, `ls`/`ps` on Unix systems).

#### 4. Persistence Attempt
Attempts user-level persistence:
- **Windows**: Registry Run key (HKCU)
- **macOS**: LaunchAgent plist
- **Linux**: XDG autostart entry

#### 5. Credential Access
Safely attempts to access credential stores:
- **Windows**: Lists Windows Credential Manager entries
- **macOS**: Attempts Keychain access
- **Linux**: Reads `/etc/passwd`

#### 6. Network Beacon
Makes an HTTPS connection to `example.com` to test network telemetry.

#### 7. Filesystem Discovery
Reads system directories (`C:\Windows` on Windows, `/etc` on Unix) to test discovery detection.

#### 8. Process Tree
Creates parent-child process relationships to test process tree correlation.

#### 9. Encoded Commands
Executes base64-encoded commands to test obfuscation detection.

#### 10. Ransomware-Like Behavior
Creates and renames files with `.encrypted` extension to simulate ransomware patterns.

#### 11. DNS Exfiltration
Performs DNS lookup with hex-encoded subdomain to test DNS exfiltration detection.

#### 12. File Timestomping
Modifies file timestamps to a past date (2020-01-01) to test anti-forensics detection.

## 📊 Output and Reports

### Console Output

The tool provides real-time console output with:
- Timestamped log entries
- Test execution status
- MITRE ATT&CK IDs
- Correlation IDs for EDR log searches

Example output:
```
[2024-01-15T10:30:00.000Z] Starting EDR validation on darwin | Host=MacBook-Pro | User=admin
[2024-01-15T10:30:01.000Z] Running EICAR test
[2024-01-15T10:30:02.000Z] Testing process execution
...
--------------------------------------------------
EDR VALIDATION SUMMARY
Platform   : darwin
Host       : MacBook-Pro
User       : admin
Duration   : 5.23s
--------------------------------------------------
EXECUTED | EICAR signature test | /tmp/eicar_test.txt | MITRE=T1204.002 | CID=EDR-TEST-1705312200000-abc123
...
```

### JSON Report

A structured JSON report is saved to the system temp directory with:
- **Metadata**: Platform, hostname, user, execution time
- **Test Results**: All test outcomes with MITRE mappings
- **Summary**: Statistics on executed vs failed tests
- **EDR Search Queries**: Pre-formatted queries for Bitdefender EDR (extensible to other platforms)

Report location: `{TMP_DIR}/edr-report-{timestamp}.json`

Example report structure:
```json
{
  "meta": {
    "tool": "EDR Validation Suite",
    "version": "1.1.0",
    "platform": "darwin",
    "hostname": "MacBook-Pro",
    "user": "admin",
    "startTime": "2024-01-15T10:30:00.000Z",
    "endTime": "2024-01-15T10:30:05.230Z",
    "durationMs": 5230
  },
  "tests": [
    {
      "test": "EICAR signature test",
      "status": "executed",
      "details": "/tmp/eicar_test.txt",
      "time": "2024-01-15T10:30:01.000Z",
      "mitre_id": "T1204.002",
      "mitre_tactic": "Execution",
      "mitre_technique": "Malicious File",
      "correlation_id": "EDR-TEST-1705312200000-abc123"
    }
  ],
  "summary": {
    "total": 12,
    "executed": 12,
    "errors": 0
  },
  "bitdefender": {
    "expectedAlerts": [
      {
        "test": "EICAR signature test",
        "correlationId": "EDR-TEST-1705312200000-abc123",
        "mitreId": "T1204.002",
        "searchQuery": "\"EDR-TEST-1705312200000-abc123\" OR \"T1204.002\""
      }
    ]
  }
}
```

### Using Correlation IDs

Each test generates a unique correlation ID (CID) that can be used to search EDR logs:

1. **Extract CID from console output or JSON report**
2. **Search EDR platform** using the correlation ID or MITRE ID
3. **Verify detection** - the EDR should have logged events matching the test

Example Bitdefender search query:
```
"EDR-TEST-1705312200000-abc123" OR "T1204.002"
```

## 🔒 Security and Disclaimers

### Safety Guarantees

- ✅ **No exploits**: No privilege escalation attempts
- ✅ **No kernel activity**: User-level actions only
- ✅ **No driver manipulation**: No low-level system modifications
- ✅ **Non-destructive**: All test files are created in temp directories
- ✅ **Safe domains**: Network tests use `example.com` (reserved test domain)

### What This Tool Does NOT Do

- ❌ No actual malware execution
- ❌ No privilege escalation
- ❌ No system modification beyond temp files
- ❌ No network attacks or exploitation
- ❌ No credential theft (only safe read attempts)

### Intended Use

This tool is designed for:
- SOC validation and testing
- EDR QA and regression testing
- Security demonstrations
- Threat hunting exercises

**NOT intended for**:
- Penetration testing (use dedicated pentest tools)
- Actual security assessments (use professional security tools)
- Bypassing security controls (this tool is designed to be detected)

## 🐛 Troubleshooting

### Node.js Installation Issues

**Linux**:
- Ensure `curl` or `wget` is installed: `sudo apt-get install curl`
- Check sudo access: `sudo -v`
- Try manual installation: `curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -`

**macOS**:
- Ensure Xcode Command Line Tools: `xcode-select --install`
- Check Homebrew: `brew --version`
- Manual Homebrew install: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`

**Windows**:
- For WSL: Use Linux troubleshooting steps
- For Git Bash: Install Node.js manually from [nodejs.org](https://nodejs.org/)
- For Chocolatey: Run PowerShell as Administrator

### Test Execution Errors

**Permission Errors**:
- Ensure you have write access to temp directory
- Check file system permissions: `ls -la $(node -e "console.log(require('os').tmpdir())")`

**Network Errors**:
- Network tests may fail in isolated environments (expected)
- Check firewall/proxy settings
- Verify internet connectivity: `ping example.com`

**Platform-Specific Issues**:

- **macOS**: LaunchAgent creation may require user directory access
- **Windows**: Registry operations require user-level registry access
- **Linux**: XDG autostart requires `.config` directory access

### Report Not Generated

- Check temp directory permissions
- Verify disk space: `df -h` (Linux/macOS)
- Check Node.js version: `node -v` (must be 18+)

## 📝 Example Workflow

1. **Run the test suite**:
   ```bash
   ./run-linux.sh
   ```

2. **Note the correlation IDs** from console output or JSON report

3. **Search EDR platform** using correlation IDs:
   ```
   Search: "EDR-TEST-1705312200000-abc123"
   ```

4. **Verify detections**:
   - Check that EDR logged events for each test
   - Verify MITRE ATT&CK mappings are correct
   - Confirm timestamps match test execution

5. **Review coverage**:
   - Ensure all 12 techniques were detected
   - Check for any false positives or missed detections
   - Document findings in security reports

## 🔧 Advanced Usage

### Custom Execution

Run individual test functions by modifying `basic_tests.js`:

```javascript
// Comment out unwanted tests in the run() function
async function run() {
  await eicarTest();
  await processExecutionTest();
  // await lolbinTest(); // Skip this test
  // ... other tests
}
```

### Integration with CI/CD

Example GitHub Actions workflow:

```yaml
name: EDR Validation
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '18'
      - run: node basic_tests.js
      - run: |
          REPORT=$(ls /tmp/edr-report-*.json | tail -1)
          cat $REPORT
```

### Parsing Reports

Example Python script to parse JSON reports:

```python
import json
import glob
import os

def parse_edr_report(report_path):
    with open(report_path) as f:
        report = json.load(f)
    
    print(f"Platform: {report['meta']['platform']}")
    print(f"Tests Executed: {report['summary']['executed']}")
    print(f"Tests Failed: {report['summary']['errors']}")
    
    for test in report['tests']:
        print(f"{test['status']}: {test['test']} ({test['mitre_id']})")

# Find latest report
reports = glob.glob(os.path.join(os.path.expanduser('~'), '.tmp', 'edr-report-*.json'))
if reports:
    latest = max(reports, key=os.path.getctime)
    parse_edr_report(latest)
```

## 📚 MITRE ATT&CK Framework

This tool maps all tests to the MITRE ATT&CK framework, enabling:

- **Standardized Threat Taxonomy**: Use industry-standard technique IDs
- **EDR Log Correlation**: Search EDR logs using MITRE IDs
- **Coverage Analysis**: Verify EDR coverage across ATT&CK tactics
- **Threat Hunting**: Use MITRE IDs in threat hunting queries

Learn more: [MITRE ATT&CK Framework](https://attack.mitre.org/)

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Additional test scenarios
- Support for more EDR platforms (search query generation)
- Enhanced reporting formats (CSV, HTML)
- Test result validation against EDR APIs
- Performance benchmarking

## 📄 License

This tool is provided as-is for security testing and validation purposes.

## 🙏 Acknowledgments

- MITRE ATT&CK framework for threat taxonomy
- EICAR test string standard
- Node.js community for cross-platform runtime

## 📞 Support

For issues, questions, or contributions:
- Check troubleshooting section above
- Review test execution logs
- Verify Node.js and platform requirements

---

**Version**: 1.1.0  
**Last Updated**: 2024  
**Platforms**: macOS, Windows, Linux (Ubuntu 20.04+)

