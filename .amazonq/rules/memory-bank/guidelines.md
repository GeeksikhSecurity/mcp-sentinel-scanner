# MCP Sentinel Scanner - Development Guidelines

## Code Quality Standards

### Formatting and Style
- **Line Length**: 100 characters maximum (Black formatter configuration)
- **Import Organization**: isort with black profile for consistent import sorting
- **Code Formatting**: Black formatter with Python 3.9+ target version
- **Type Hints**: Full typing support with mypy strict mode validation
- **Docstrings**: Comprehensive docstrings for all public functions and classes

### File Organization Patterns
- **Module Structure**: Clear separation between adapters, analyzers, filters, and reporters
- **Configuration Files**: JSON-based configuration with environment-specific variants
- **Test Organization**: Separate unit/, integration/, and external/ test directories
- **Documentation**: Comprehensive README.md with architecture diagrams and deployment guides

### Naming Conventions
- **Classes**: PascalCase (e.g., `FalsePositiveFilter`, `StreamableHTTPServerTransport`)
- **Functions/Methods**: snake_case (e.g., `calculate_entropy`, `handle_request`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `MCP_SESSION_ID_HEADER`, `LATEST_PROTOCOL_VERSION`)
- **Private Methods**: Leading underscore (e.g., `_event_store`, `_lock`)
- **Test Functions**: Descriptive test names with `test_` prefix

## Architectural Patterns

### Adapter Pattern Implementation
```python
# External tool integration without tight coupling
class SemgrepAdapter:
    def normalize_output(self, raw_output: Dict) -> List[Finding]
    
class TruffleHogAdapter:
    def process_secrets(self, results: List) -> List[SecretFinding]
```

### Filter Chain Pattern
```python
# Sequential filtering with composable filters
class FilterChain:
    def apply_filters(self, findings: List[Finding]) -> List[Finding]:
        for filter_instance in self.filters:
            findings = filter_instance.filter(findings)
        return findings
```

### Strategy Pattern for Output Formats
```python
# Pluggable output format selection
class ReporterFactory:
    def create_reporter(self, format_type: str) -> BaseReporter:
        return self.reporters[format_type]()
```

### Context Manager Usage
```python
# Proper resource management with async context managers
async with streamablehttp_client(url) as (read_stream, write_stream, get_session_id):
    async with ClientSession(read_stream, write_stream) as session:
        result = await session.initialize()
```

## Testing Standards

### Test Structure and Organization
- **Fixture-Based Setup**: Extensive use of pytest fixtures for test data and server setup
- **Async Testing**: `@pytest.mark.anyio` for async test functions
- **Test Isolation**: Each test creates its own server instance and cleans up resources
- **Parameterized Tests**: Use `@pytest.mark.parametrize` for testing multiple scenarios

### Test Naming and Documentation
```python
def test_session_id_pattern():
    """Test that SESSION_ID_PATTERN correctly validates session IDs."""
    
async def test_streamablehttp_client_basic_connection(basic_server: None, basic_server_url: str):
    """Test basic client connection with initialization."""
```

### Mock and Fixture Patterns
```python
@pytest.fixture
def recording_middleware():
    """Fixture that provides a recording middleware instance."""
    middleware = RecordingMiddleware(name="recording_middleware")
    yield middleware

# Process-based server testing for isolation
@pytest.fixture
def basic_server(basic_server_port: int) -> Generator[None, None, None]:
    proc = multiprocessing.Process(target=run_server, kwargs={"port": basic_server_port}, daemon=True)
    proc.start()
    # Wait for server startup and cleanup
    yield
    proc.kill()
    proc.join(timeout=2)
```

## Error Handling Patterns

### Exception Hierarchy
```python
class McpError(Error):
    def __init__(self, code: number, message: str, data?: unknown):
        super().__init__(f"MCP error {code}: {message}")

class ToolError(Exception):
    """Specific error for tool execution failures"""
```

### Validation and Error Propagation
```python
# Input validation with descriptive error messages
if not SESSION_ID_PATTERN.match(session_id):
    raise ValueError("Session ID must only contain visible ASCII characters")

# Graceful error handling with proper cleanup
try:
    await transport.handleRequest(req, res)
except Exception as error:
    console.error('Error handling request:', error)
    if (!res.headersSent) res.writeHead(500).end()
```

## Async Programming Patterns

### Resource Management
```python
# Proper async context manager implementation
async def __aenter__(self):
    await self.initialize()
    return self

async def __aexit__(self, exc_type, exc_val, exc_tb):
    await self.cleanup()
```

### Concurrent Processing
```python
# Task group pattern for concurrent operations
async with anyio.create_task_group() as tg:
    tg.start_soon(process_file, file_path)
    tg.start_soon(analyze_patterns, patterns)
```

### Event-Driven Architecture
```python
# Callback-based event handling
async def message_handler(
    message: RequestResponder | ServerNotification | Exception,
) -> None:
    if isinstance(message, ServerNotification):
        await self.handle_notification(message)
```

## Security and Validation Patterns

### Input Validation
```python
# Comprehensive input validation with regex patterns
SESSION_ID_PATTERN = re.compile(r'^[\x21-\x7E]+$')  # Visible ASCII only

def validate_session_id(session_id: str) -> bool:
    return SESSION_ID_PATTERN.fullmatch(session_id) is not None
```

### Security Headers and CORS
```typescript
// Protocol version validation
if (protocolVersion && !SUPPORTED_PROTOCOL_VERSIONS.includes(protocolVersion)) {
    throw new Error(`Unsupported protocol version: ${protocolVersion}`)
}

// DNS rebinding protection
if (enableDnsRebindingProtection && allowedHosts) {
    const hostHeader = req.headers.host
    if (!allowedHosts.includes(hostHeader)) {
        throw new Error(`Invalid Host header: ${hostHeader}`)
    }
}
```

### Entropy-Based Detection
```python
def calculate_entropy(self, text: str) -> float:
    """Calculate Shannon entropy for credential validation"""
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy
```

## Configuration Management

### Environment-Specific Configuration
```json
// configs/default_config.json
{
  "exclude": ["node_modules", "*.d.ts", "dist", ".git"],
  "severity_threshold": "HIGH",
  "parallel_workers": 4
}
```

### Secret Management
```python
# Secure secret handling with optional fallbacks
ap_encryption_key = config.getSecret("apEncryptionKey")?.apply(secretValue => {
    return secretValue || child_process.execSync("openssl rand -hex 16").toString().trim()
})
```

## Performance Optimization Patterns

### Parallel Processing
```python
# Multi-worker parallel processing
class Scanner:
    def __init__(self, parallel_workers: int = 4):
        self.workers = parallel_workers
    
    async def scan_files(self, files: List[str]) -> List[Finding]:
        # Process files in parallel batches
        return await self.process_parallel(files)
```

### Memory Management
```python
# Efficient resource utilization with generators
def process_large_files(self) -> Generator[Finding, None, None]:
    for file_path in self.file_paths:
        yield from self.analyze_file(file_path)
```

### Caching Strategies
```python
# Result caching for incremental scans
@lru_cache(maxsize=1000)
def analyze_pattern(self, pattern: str, content: str) -> List[Match]:
    return self.pattern_matcher.find_matches(pattern, content)
```

## Documentation Standards

### Code Documentation
- **Comprehensive Docstrings**: All public APIs documented with parameters, return values, and examples
- **Type Annotations**: Full type hints for all function signatures
- **Inline Comments**: Explain complex logic and business rules
- **Architecture Documentation**: High-level system design and data flow diagrams

### API Documentation
```python
def filter_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter a list of vulnerability findings to remove false positives.
    
    Args:
        findings: List of vulnerability findings with code_snippet, context, file_path
        
    Returns:
        Filtered list of findings with confidence scores added
        
    Example:
        >>> filter_instance = FalsePositiveFilter()
        >>> filtered = filter_instance.filter_findings(raw_findings)
    """
```

## Integration Patterns

### External Tool Integration
```python
# Standardized adapter interface for external tools
class BaseAdapter:
    def execute(self, target_path: str) -> RawResults
    def normalize(self, raw_results: RawResults) -> List[Finding]
    def validate_tool_availability(self) -> bool
```

### CI/CD Integration
```yaml
# GitHub Actions integration pattern
- name: Security Scan
  run: |
    docker run --rm -v ${{ github.workspace }}:/scan \
      ghcr.io/mcp-security/mcp-sentinel-scanner:latest \
      /scan --format sarif -o results.sarif
```

These guidelines ensure consistent, maintainable, and secure code across the MCP Sentinel Scanner project while following established Python and TypeScript best practices.