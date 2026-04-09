# Writing a StreamTrace Parser

This guide walks you through adding a new parser to StreamTrace.
Time estimate: 30-60 minutes for a typical log format.

---

## Quick Start

1. Copy the template
2. Rename the struct
3. Set your parser ID and content types
4. Implement the `can_parse` heuristic
5. Implement the `parse` method
6. Register your parser
7. Add tests
8. Submit a PR

---

## Step 1: Copy the Template

```bash
cp crates/st-parser/src/template.rs crates/st-parser/src/your_format.rs
```

Then open the new file and do three find/replace operations:

| Find | Replace with | Example |
|------|-------------|---------|
| `TemplateParser` | `YourFormatParser` | `CloudTrailParser` |
| `"template"` | `"your_format"` | `"cloudtrail"` |
| `"template."` | `"your_format."` | `"cloudtrail."` |

---

## Step 2: Add Your Module to the Crate

Edit `crates/st-parser/src/lib.rs`:

```rust
pub mod your_format;
pub use your_format::YourFormatParser;
```

---

## Step 3: Register Your Parser

Edit `crates/st-parser/src/registry.rs`:

1. Add the import:
```rust
use crate::your_format::YourFormatParser;
```

2. Add to the `with_defaults()` method:
```rust
pub fn with_defaults() -> Self {
    let mut registry = Self::new();
    // ... existing parsers ...
    registry.register(Arc::new(YourFormatParser::new()));
    registry
}
```

**Registration order matters.** The registry checks parsers in order during auto-detection. Register more specific parsers before generic ones. If your parser handles `application/json`, make sure its `can_parse` heuristic is specific enough to avoid stealing events from `json_generic`.

---

## The EventParser Trait

Every parser implements four methods:

```rust
pub trait EventParser: Send + Sync {
    /// Unique, stable identifier (e.g., "cloudtrail", "k8s_audit").
    fn id(&self) -> &str;

    /// MIME content types this parser handles.
    fn supported_content_types(&self) -> &[&str];

    /// Cheap heuristic: can this parser likely handle this content?
    fn can_parse(&self, content: &[u8], content_type: &str) -> bool;

    /// Parse raw bytes into zero or more normalized events.
    fn parse(&self, content: &[u8], content_type: &str)
        -> Result<Vec<ParsedEvent>, StError>;
}
```

### `id()`

Return a short, stable, lowercase string. Use underscores for multi-word names. This ID is stored with events and used by API callers to force a specific parser, so do not change it after release.

Good: `"cloudtrail"`, `"k8s_audit"`, `"nginx_access"`
Bad: `"my-parser-v2"`, `"AWSCloudTrailParser"`

### `supported_content_types()`

Return the MIME types your format uses. For JSON-based formats, this is typically `&["application/json"]`. If your format has a vendor-specific MIME type, include both:

```rust
&["application/vnd.amazonaws.cloudtrail+json", "application/json"]
```

### `can_parse()`

This is called during auto-detection and must be **fast**. Do not parse the full input. Instead:

- Check for a distinctive content type first (instant match).
- If the content type is shared (e.g., `application/json`), peek at the first few hundred bytes for a signature field.

```rust
fn can_parse(&self, content: &[u8], content_type: &str) -> bool {
    // Instant match on vendor content type.
    if content_type == "application/vnd.amazonaws.cloudtrail+json" {
        return true;
    }
    // For shared types, look for a distinctive field.
    if content_type == "application/json" {
        let peek = &content[..content.len().min(512)];
        if let Ok(s) = std::str::from_utf8(peek) {
            return s.contains("\"Records\"") && s.contains("\"eventSource\"");
        }
    }
    false
}
```

### `parse()`

This is where the real work happens. The template provides a working structure you can adapt:

1. Validate input (non-empty, valid encoding).
2. Deserialize into your format's structure.
3. Handle single vs. batch payloads.
4. Map each source event to a `ParsedEvent`.
5. Return errors for malformed input (fail closed).

---

## Mapping to the Forensic Model

### `event_type`

Use dotted notation: `"<parser_id>.<action>"`.

| Format | Example |
|--------|---------|
| CloudTrail | `"cloudtrail.ConsoleLogin"`, `"cloudtrail.CreateBucket"` |
| Kubernetes | `"k8s_audit.create"`, `"k8s_audit.delete"` |
| Nginx | `"nginx.access"`, `"nginx.error"` |

### `severity`

Map from the source's severity or level field. If the source has no severity, derive it from the action:

| Source signal | StreamTrace severity |
|--------------|---------------------|
| Emergency, Alert, Critical | `Severity::Critical` |
| Error, failure events | `Severity::High` |
| Warning, destructive actions | `Severity::Medium` |
| Notice, auth events | `Severity::Low` |
| Info, debug, routine | `Severity::Info` |

### `occurred_at`

Use the **authoritative timestamp** from the source system. This is when the event actually happened, not when it was logged or received. The template includes `parse_timestamp()` and `parse_timestamp_str()` helpers that handle:

- RFC 3339 / ISO 8601 (with and without timezone)
- ISO 8601 without timezone (assumed UTC)
- Unix epoch seconds (integer or string)
- Unix epoch milliseconds (integer or string)

### `actor`

Who initiated the action.

| Format | Actor source |
|--------|-------------|
| CloudTrail | `userIdentity.arn` or `userIdentity.userName` |
| Kubernetes | `user.username` |
| Nginx | Usually not present (use IP instead) |

### `subject`

What was acted upon.

| Format | Subject source |
|--------|---------------|
| CloudTrail | Target account or resource |
| Kubernetes | Resource name + namespace |

### `object`

The specific resource involved.

| Format | Object source |
|--------|--------------|
| CloudTrail | S3 bucket, EC2 instance, IAM role |
| Kubernetes | Pod, deployment, configmap |
| Nginx | Request URI |

### `network`

IP addresses, ports, protocols.

| Format | Network source |
|--------|---------------|
| CloudTrail | `sourceIPAddress` |
| Kubernetes | `sourceIPs` array |
| Nginx | `$remote_addr`, `$server_port` |

### `device`

Host or device context.

| Format | Device source |
|--------|--------------|
| CloudTrail | `userAgent` (not a device, but useful context in `custom_fields`) |
| Kubernetes | Node name |
| Nginx | `$hostname` |

### `correlation_hints`

Keys that should link this event to others across sources. Add every identifier that might appear in another log source:

```rust
// User identity -- links to auth logs, application logs, etc.
correlation_hints.push(CorrelationKey {
    key_type: CorrelationKeyType::Identity,
    key_value: user_id.clone(),
});

// Source IP -- links to firewall logs, access logs, etc.
correlation_hints.push(CorrelationKey {
    key_type: CorrelationKeyType::Ip,
    key_value: source_ip.clone(),
});

// Session -- links to session logs across services.
correlation_hints.push(CorrelationKey {
    key_type: CorrelationKeyType::Session,
    key_value: session_id.clone(),
});

// Custom key for your domain (e.g., AWS request ID).
correlation_hints.push(CorrelationKey {
    key_type: CorrelationKeyType::Custom("request_id".to_string()),
    key_value: request_id.clone(),
});
```

---

## Common Patterns

### Parsing ISO 8601 timestamps

The template includes `parse_timestamp()` which handles the common cases. Use it directly:

```rust
let occurred_at = obj
    .get("eventTime")
    .and_then(parse_timestamp)
    .ok_or_else(|| StError::ParseError("missing eventTime".to_string()))?;
```

### Handling Unix epoch timestamps

The same `parse_timestamp()` function handles numeric values:

```rust
// Works with both seconds and milliseconds.
let ts = serde_json::json!(1775908800);
let dt = parse_timestamp(&ts); // Some(2026-04-09T12:00:00Z)
```

### Extracting IPs from various formats

```rust
// Simple string field.
let ip = obj.get("sourceIPAddress").and_then(|v| v.as_str());

// Array of IPs (e.g., Kubernetes sourceIPs).
let ips: Vec<String> = obj
    .get("sourceIPs")
    .and_then(|v| v.as_array())
    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
    .unwrap_or_default();
```

### Mapping severity levels

```rust
fn map_level(level: &str) -> Severity {
    match level.to_lowercase().as_str() {
        "emergency" | "alert" | "critical" | "fatal" => Severity::Critical,
        "error" | "err" => Severity::High,
        "warning" | "warn" => Severity::Medium,
        "notice" | "info" | "informational" => Severity::Low,
        "debug" | "trace" => Severity::Info,
        _ => Severity::Info,
    }
}
```

### Handling nested JSON structures

```rust
// Safely navigate nested objects.
let bucket_name = obj
    .get("requestParameters")
    .and_then(|v| v.as_object())
    .and_then(|params| params.get("bucketName"))
    .and_then(|v| v.as_str());
```

### Batch event payloads (arrays)

The template already handles this pattern. CloudTrail wraps events in a `Records` array:

```rust
let records = root
    .get("Records")
    .and_then(|v| v.as_array())
    .ok_or_else(|| StError::ParseError("missing Records array".to_string()))?;

let mut events = Vec::with_capacity(records.len());
for record in records {
    let obj = record.as_object().ok_or_else(|| /* ... */)?;
    events.push(parse_single_event(obj)?);
}
```

### Line-delimited formats (non-JSON)

For text-based formats like Nginx access logs, iterate line by line:

```rust
fn parse(&self, content: &[u8], _content_type: &str) -> Result<Vec<ParsedEvent>, StError> {
    let text = std::str::from_utf8(content)
        .map_err(|e| StError::ParseError(format!("invalid UTF-8: {}", e)))?;

    let mut events = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        events.push(parse_line(line)?);
    }

    if events.is_empty() {
        return Err(StError::ParseError("no valid lines found".to_string()));
    }
    Ok(events)
}
```

---

## Testing Your Parser

### Required tests

Every parser should have tests for:

1. **Single event** -- Verify all fields are extracted correctly.
2. **Batch payload** -- If your format supports arrays or wrapped records.
3. **Missing optional fields** -- Parser should not panic.
4. **Severity mapping** -- Each severity level maps correctly.
5. **Timestamp parsing** -- All timestamp formats your source emits.
6. **Error cases** -- Empty input, invalid encoding, missing required fields, malformed structure.
7. **`can_parse` heuristic** -- Accepts your format, rejects others.

### Running tests

```bash
# Run all parser tests.
cargo test -p st-parser

# Run only your parser's tests.
cargo test -p st-parser -- your_format::tests

# Run with output visible.
cargo test -p st-parser -- your_format::tests --nocapture
```

### Property-based testing (recommended for production parsers)

Add fuzz tests to ensure your parser never panics on arbitrary input:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_never_panics(input in any::<Vec<u8>>()) {
        let parser = YourFormatParser::new();
        let _ = parser.parse(&input, "application/json");
    }
}
```

---

## Registering Your Parser

After your parser compiles and tests pass:

1. Edit `crates/st-parser/src/registry.rs`.
2. Add an import for your parser.
3. Add `registry.register(Arc::new(YourFormatParser::new()));` in `with_defaults()`.
4. Update the registry test `with_defaults_includes_all_parsers` to include your parser ID.

---

## Checklist Before Submitting

- [ ] File copied from template and renamed
- [ ] Module added to `lib.rs` (`pub mod` + `pub use`)
- [ ] Parser registered in `registry.rs` `with_defaults()`
- [ ] `id()` returns a unique, stable, lowercase identifier
- [ ] `can_parse()` has a specific heuristic (does not steal other formats)
- [ ] `parse()` handles empty input, invalid encoding, malformed structure
- [ ] `parse()` handles both single and batch payloads (if applicable)
- [ ] All fields mapped: event_type, severity, occurred_at, actor, network, etc.
- [ ] Correlation hints added for linkable identifiers
- [ ] Unused canonical fields set to `None` (not omitted)
- [ ] Custom fields preserve source-specific data
- [ ] Unit tests for positive cases, error cases, and heuristic
- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo test -p st-parser` passes

---

## Real-World Examples (Skeletons)

These show the key decisions for common formats. Copy the template and use these as a reference for your `parse_single_event` implementation.

### AWS CloudTrail

```rust
fn id(&self) -> &str { "cloudtrail" }

fn can_parse(&self, content: &[u8], content_type: &str) -> bool {
    // CloudTrail JSON always has a top-level "Records" array
    // with objects containing "eventSource" and "eventName".
    let peek = &content[..content.len().min(512)];
    if let Ok(s) = std::str::from_utf8(peek) {
        return s.contains("\"Records\"") && s.contains("\"eventSource\"");
    }
    false
}

// In parse_single_event:
// - timestamp: obj["eventTime"] (ISO 8601)
// - event_type: format!("cloudtrail.{}", obj["eventName"])
// - actor: obj["userIdentity"]["arn"] or ["userName"]
// - network.src_ip: obj["sourceIPAddress"]
// - object: derive from obj["requestParameters"] based on eventSource
// - correlation: user ARN, source IP, request ID (obj["requestID"])
```

### Kubernetes Audit Log

```rust
fn id(&self) -> &str { "k8s_audit" }

fn can_parse(&self, content: &[u8], content_type: &str) -> bool {
    let peek = &content[..content.len().min(512)];
    if let Ok(s) = std::str::from_utf8(peek) {
        return s.contains("\"apiVersion\"") && s.contains("audit.k8s.io");
    }
    false
}

// In parse_single_event:
// - timestamp: obj["requestReceivedTimestamp"] (RFC 3339)
// - event_type: format!("k8s_audit.{}", obj["verb"])
// - actor: obj["user"]["username"]
// - subject: obj["objectRef"]["name"] + obj["objectRef"]["namespace"]
// - object: obj["objectRef"]["resource"]
// - network.src_ip: obj["sourceIPs"][0]
// - correlation: username, source IP, audit ID
```

### Nginx Access Log

```rust
fn id(&self) -> &str { "nginx_access" }

fn can_parse(&self, content: &[u8], content_type: &str) -> bool {
    // Heuristic: line matches combined log format pattern.
    // Look for IP, dash, dash, timestamp in brackets.
    let peek = &content[..content.len().min(256)];
    if let Ok(s) = std::str::from_utf8(peek) {
        // Rough pattern: starts with IP, has [timestamp], has "HTTP/"
        return s.contains("HTTP/") && s.contains('[') && s.contains(']');
    }
    false
}

// This is a line-delimited text format, not JSON.
// Use the line-by-line parsing pattern described above.
//
// In parse_line:
// - Split by spaces, respecting quoted strings.
// - timestamp: field in [brackets], parse with "%d/%b/%Y:%H:%M:%S %z"
// - event_type: "nginx.access"
// - network.src_ip: first field (client IP)
// - object: request URI (e.g., "/api/v1/users")
// - custom_fields: status code, bytes, user agent, referer
// - severity: derive from HTTP status (5xx -> High, 4xx -> Medium, etc.)
```
