# cert-monitor-lambda

A certificate transparency monitoring tool that runs in AWS Lambda and writes matching log entries to S3. This tool helps monitor newly issued SSL/TLS certificates for specified domains and patterns, allowing you to stay informed about certificate changes and potential security issues.

## Overview

cert-monitor-lambda periodically checks Certificate Transparency (CT) logs for new certificates matching specified domains or patterns. When a match is found, it stores the certificate information in an S3 bucket for further analysis.

## Setup

- Set up an S3 bucket to store the configuration file and certificate data.
- Set the environment variable `CERT_MONITOR_BUCKET` to the name of your S3 bucket.
- Deploy the compiled Lambda function code to AWS Lambda.
- Give the lambda permission to read and write to your s3 bucket
- Set up a CloudWatch Events rule to trigger the Lambda function periodically (e.g., every minute).
- (Optional) setup s3 object triggers to notify you when a new certificate is detected

## Config file

The configuration file needs to be placed in the S3 bucket with the key "cert-monitor.toml". Here's an example of the config file:

```toml
# list of domains (including sub domains) to monitor
domains = [
  "google.com",
  "facebook.com",
]

# define regex patterns with Go regex syntax
patterns = [
  "^www.*",
]

# should the monitor also check at pre certificates
include_pre_certs = false
```

### Configuration options:

- `domains`: A list of domain names to monitor. The monitor will match certificates for these domains and their subdomains.
- `patterns`: A list of regex patterns to match against certificate domain names. Use Go regex syntax.
- `include_pre_certs`: Set to `true` to include precertificates in the monitoring process.

## json-to-cert Tool

The `json-to-cert` tool is included in the `cmd/json-to-cert` directory. This utility helps convert the JSON-formatted certificate data stored in S3 to various formats for easier analysis.

Usage:
```
json-to-cert [-format=<format>] <cert.json>
```

Supported formats:
- `text`: Human-readable text format (default)
- `json`: Formatted JSON output
- `pem`: PEM-encoded certificate

Example:
```
./json-to-cert -format=pem certificate.json
```
