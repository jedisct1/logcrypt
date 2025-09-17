# LogCrypt

A command-line tool for prefix-preserving encryption of IP addresses and URIs in logs and data files. Enables privacy-compliant data analysis while maintaining network and URI hierarchies.

## Quick Start

```bash
# Install
cargo build --release

# Generate a secure key
KEY=$(./target/release/logcrypt generate-key)

# Encrypt an IP address
./target/release/logcrypt encrypt-ip 192.168.1.1 --key $KEY

# Parse and redact a log file
./target/release/logcrypt parse-logs access.log --operation redact -o redacted.log
```

## Features

### IP Address Encryption with Prefix Preservation

- Prefix-preserving encryption: IPs in the same subnet remain in the same encrypted subnet, enabling network topology analysis without exposing real IPs
- Format-preserving: Encrypted IPs are syntactically valid IP addresses
- Full IPv4 and IPv6 support: Complete protocol coverage
- Deterministic: Same input always produces the same encrypted output, enabling correlation analysis

### URI/URL Encryption with Hierarchy Preservation

- Hierarchy-preserving encryption: Maintains URI path structure, preserving the relationship between parent and child paths
- Full URL and path-only support: Handles both complete URLs (https://example.com/api/v1/users) and relative paths (/api/v1/users)
- Component preservation: Encrypts while maintaining query parameters, fragments, ports, and credentials
- Multi-scheme support: Works with http, https, ftp, ssh, and other URI schemes

### Log File Processing

- Auto-detection: Automatically identifies Apache, Nginx, JSON, Syslog formats
- Batch processing: Handle entire log files efficiently
- Structure preservation: Maintains original log format
- Multiple operations: Encrypt, decrypt, or redact sensitive data

### Additional Features

- Batch processing: Process multiple IPs/URIs from files
- JSON output: Integration-friendly output format
- Environment variables: Store keys securely
- Dry-run mode: Preview changes before applying

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/logcrypt.git
cd logcrypt

# Build with Cargo
cargo build --release

# Binary will be at target/release/logcrypt
```

### Add to PATH (Optional)

```bash
# Copy to local bin
cp target/release/logcrypt ~/.local/bin/

# Or system-wide (requires sudo)
sudo cp target/release/logcrypt /usr/local/bin/
```

## Key Management

### Generating Keys

LogCrypt requires 256-bit (32-byte) keys with different halves for security:

```bash
# Generate a cryptographically secure key (always ensures different halves)
logcrypt generate-key

# Save to environment variable
export LOGCRYPT_KEY=$(logcrypt generate-key)
```

Important: The two 16-byte halves of the key must be different for security reasons. LogCrypt automatically generates keys with this property and validates all keys before use.

### Using Environment Variables

Avoid exposing keys in command history by using environment variables:

```bash
# Set key once
export LOGCRYPT_KEY="your-64-hex-character-key"

# Use commands without --key flag
logcrypt encrypt-ip 192.168.1.1
logcrypt encrypt-uri "https://example.com/api"
logcrypt parse-logs access.log --operation encrypt -o encrypted.log
```

## Command Reference

### Generate Key

```bash
logcrypt generate-key [OPTIONS]

Options:
  --ensure-different-halves  Ensure key halves differ (recommended)
  -o, --output <FORMAT>      Output format [plain|json]
```

### Encrypt/Decrypt IP

```bash
logcrypt encrypt-ip <IP> [OPTIONS]
logcrypt decrypt-ip <IP> [OPTIONS]

Options:
  -k, --key <KEY>        Encryption key (or use LOGCRYPT_KEY env var)
  -o, --output <FORMAT>  Output format [plain|json]
```

### Encrypt/Decrypt URI

```bash
logcrypt encrypt-uri <URI> [OPTIONS]
logcrypt decrypt-uri <URI> [OPTIONS]

Options:
  -k, --key <KEY>        Encryption key (or use LOGCRYPT_KEY env var)
  -o, --output <FORMAT>  Output format [plain|json]
```

### Parse Logs

```bash
logcrypt parse-logs <INPUT> [OPTIONS]

Options:
  -p, --operation <OP>   Operation to perform [encrypt|decrypt|redact]
  -k, --key <KEY>        Encryption key (required for encrypt/decrypt)
  -o, --output <FILE>    Output file (default: stdout)
  --format <FORMAT>      Force log format [apache|clf|json|syslog]
  --dry-run             Preview changes without applying them
```

### Batch Processing

```bash
logcrypt batch [OPTIONS]

Options:
  -i, --input <FILE>     Input file with one item per line
  -o, --output <FILE>    Output file (JSON format)
  -p, --operation <OP>   Operation [encrypt-ip|decrypt-ip|encrypt-uri|decrypt-uri]
  -k, --key <KEY>        Encryption key
```

## Examples

### Basic IP Encryption

```bash
# Set your key
export LOGCRYPT_KEY=$(logcrypt generate-key)

# Encrypt an IP
logcrypt encrypt-ip 192.168.1.100
# Output: 45.67.89.123 (example)

# Decrypt it back
logcrypt decrypt-ip 45.67.89.123
# Output: 192.168.1.100

# Notice prefix preservation - IPs in the same subnet
# map to IPs in the same encrypted subnet, preserving network topology
logcrypt encrypt-ip 192.168.1.101  # -> 45.67.89.124 (same subnet as above)
logcrypt encrypt-ip 192.168.1.102  # -> 45.67.89.125 (same subnet as above)
logcrypt encrypt-ip 192.168.2.1    # -> 45.67.90.1   (different subnet)
```

### Log File Processing

```bash
# Redact all IPs and URLs (no key needed)
logcrypt parse-logs access.log --operation redact -o redacted.log

# Example output:
# [REDACTED_IP] - - [01/Jan/2024:12:00:00] "GET [REDACTED_URI] HTTP/1.1" 200

# Encrypt sensitive data (reversible with key)
logcrypt parse-logs access.log --operation encrypt --key $LOGCRYPT_KEY -o encrypted.log

# Decrypt to restore original
logcrypt parse-logs encrypted.log --operation decrypt --key $LOGCRYPT_KEY -o original.log

# Preview changes without modifying
logcrypt parse-logs access.log --operation redact --dry-run
```

### Batch Processing

```bash
# Create input file
cat > ips.txt << EOF
192.168.1.1
10.0.0.1
172.16.0.1
2001:db8::1
EOF

# Batch encrypt
logcrypt batch -i ips.txt -o encrypted.json -p encrypt-ip --key $LOGCRYPT_KEY

# Output (encrypted.json):
{
  "results": [
    {"input": "192.168.1.1", "output": "45.67.89.123", "success": true},
    {"input": "10.0.0.1", "output": "98.76.54.32", "success": true},
    ...
  ],
  "total": 4,
  "errors": 0
}
```

### Working with URIs - Hierarchy Preservation

```bash
# URI hierarchy is preserved during encryption
# Parent-child relationships remain intact
logcrypt encrypt-uri "https://api.example.com/v1/users"
# -> https://encrypted.example.com/xyz/abc

logcrypt encrypt-uri "https://api.example.com/v1/users/123"
# -> https://encrypted.example.com/xyz/abc/def (child of above)

logcrypt encrypt-uri "/api/internal/metrics"  # Path-only URI
# -> /encrypted/xyz/metrics

logcrypt encrypt-uri "/api/internal/metrics/detailed"
# -> /encrypted/xyz/metrics/detailed (child of above)
```

## Security Considerations

### Key Security

- Never commit keys to version control
- Use environment variables to avoid command history exposure
- Rotate keys regularly for production systems
- Use different keys for different environments
- Store keys securely using a key management system

### Encryption Properties

- Deterministic: Same input → same output (enables correlation and pattern analysis)
- Prefix-preserving: Network topology and URI hierarchies remain analyzable
- Format-preserving: Encrypted data maintains syntactically valid format
- Privacy-preserving: Original values cannot be recovered without the key
- Analysis-friendly: Enables statistical analysis, anomaly detection, and pattern recognition on encrypted data

### Best Practices

```bash
# Good: Using environment variable
export LOGCRYPT_KEY=$(logcrypt generate-key)
logcrypt encrypt-ip 192.168.1.1

# Bad: Key visible in command history
logcrypt encrypt-ip 192.168.1.1 --key abc123...

# Good: Separate keys for different data
export LOGCRYPT_KEY_PROD=$(logcrypt generate-key)
export LOGCRYPT_KEY_DEV=$(logcrypt generate-key)
```

## Use Cases

### Privacy-Compliant Log Analysis

Analyze logs while complying with GDPR, CCPA, and other privacy regulations:

```bash
# Encrypt IPs and URIs while preserving their relationships
# Enables network analysis and user behavior analytics without exposing real data
logcrypt parse-logs production.log --operation encrypt --key $KEY -o analytics-ready.log
```

### Network Topology Analysis

Share network data with security teams or third parties without exposing infrastructure:

```bash
# Preserved subnet relationships enable:
# - Network segmentation analysis
# - Intrusion detection pattern matching
# - Traffic flow analysis
logcrypt batch -i network-ips.txt -o analysis.json -p encrypt-ip --key $KEY
```

### API Usage Analytics

Analyze API usage patterns while protecting endpoint details:

```bash
# URI hierarchy preservation allows:
# - API endpoint popularity analysis
# - User flow tracking
# - Performance monitoring by endpoint groups
logcrypt parse-logs api-access.log --operation encrypt --key $KEY -o encrypted-api.log
```

### Security Research and Threat Intelligence

Share anonymized data with security researchers:

```bash
# Researchers can analyze:
# - Attack patterns across subnets
# - Lateral movement patterns (preserved IP relationships)
# - Campaign targeting (preserved URI hierarchies)
logcrypt parse-logs security-events.log --operation encrypt --key $KEY -o research-data.log
```

### Multi-Tenant Data Analysis

Enable cross-tenant analytics while maintaining tenant isolation:

```bash
# Different encryption keys per tenant preserve:
# - Tenant-specific network patterns
# - API usage patterns per tenant
# - Compliance with data segregation requirements
logcrypt parse-logs tenant-A.log --operation encrypt --key $TENANT_A_KEY -o tenant-A-encrypted.log
```

## Troubleshooting

### Common Issues

"No key provided" error

```bash
# Solution: Set environment variable or use --key flag
export LOGCRYPT_KEY=$(logcrypt generate-key)
```

"Invalid hex key" error

```bash
# Keys must be exactly 64 hex characters (32 bytes)
# Generate a valid key:
logcrypt generate-key
```

"The two halves of the key must be different" error

```bash
# Your key has identical 16-byte halves (security issue)
# Solution: Generate a new secure key:
logcrypt generate-key
# This automatically ensures the halves are different
```

Format detection issues

```bash
# Force a specific format if auto-detection fails
logcrypt parse-logs custom.log --format apache --operation redact
```

## How Prefix-Preserving Encryption Works

### Traditional Encryption vs LogCrypt

Traditional Encryption:

```
Original:       192.168.1.1    192.168.1.2    192.168.2.1
Encrypted:         a7f9c4e3       2b8d1a9f       5e3c7b2a
```

All relationships lost - useless for analysis

LogCrypt (Prefix-Preserving):

```
Original:       192.168.1.1    192.168.1.2    192.168.2.1
Encrypted:       45.67.89.1     45.67.89.2     45.67.90.1
```

Subnet relationships preserved - analysis ready!

### Key Benefits

1. Maintains Analytical Value: Statistical analysis, pattern recognition, and anomaly detection work on encrypted data
2. Preserves Hierarchies: Network topology and API endpoint structures remain intact
3. Enables Correlation: Trace requests across systems while protecting sensitive identifiers
4. Privacy by Design: Original values cannot be recovered without the encryption key

## Architecture

### Building Blocks

- IPCrypt-PFX: Advanced format-preserving encryption that maintains IP prefix relationships
- URICrypt: Hierarchy-preserving encryption that maintains URI path relationships

### Privacy-Preserving Analysis

Unlike traditional encryption that breaks all relationships, LogCrypt's prefix-preserving approach enables:

1. Network Analysis: Identify traffic patterns, bottlenecks, and security issues without seeing real IPs
2. User Journey Mapping: Track API usage flows and user behavior patterns while protecting endpoint details
3. Anomaly Detection: Detect unusual patterns based on preserved network and URI hierarchies
4. Compliance: Meet privacy requirements while maintaining data utility for business operations
