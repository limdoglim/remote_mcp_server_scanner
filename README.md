# MCP URL Classifier

A high-performance Python CLI tool that classifies URLs into Model Context Protocol (MCP) related categories using a sophisticated 7-stage detection pipeline.

## Features

- **Multi-category Classification**: Classifies URLs into `mcp_server`, `mcp_intro`, `mcp_registry`, or `unknown`
- **7-Stage Detection Pipeline**: Comprehensive analysis using multiple detection methods
- **High Concurrency**: Configurable async processing (default 32, max 128 concurrent requests)
- **Multiple Output Formats**: CSV (Google Sheets compatible) and JSON output
- **LLM Integration**: Optional Ollama API integration for intelligent content analysis
- **Robust Error Handling**: Comprehensive error codes with retry policies
- **SSL Flexibility**: Disabled SSL verification with security warnings (research tool)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd mcp_scanner
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
# On Windows
.\.venv\Scripts\activate
# On Linux/Mac
source .venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Copy and configure environment variables:
```bash
cp .env.example .env
# Edit .env with your settings
```

## Usage

### Basic Examples

```bash
# Classify a single URL
python -m src.cli --url https://example.com

# Classify multiple URLs from command line
python -m src.cli --list "https://a.com,https://b.com,https://c.com"

# Classify URLs from a file
python -m src.cli --file urls.txt --output results.csv

# High concurrency with JSON output
python -m src.cli --file urls.txt --concurrency 64 --json --timeout 10
```

### Command Line Options

- `--url, -u`: Single URL to classify
- `--list, -l`: Comma-separated list of URLs
- `--file, -f`: File containing URLs (one per line)
- `--output, -o`: Output CSV file (default: results.csv)
- `--json`: Also save results as JSON
- `--concurrency, -c`: Number of concurrent requests (default: 32, max: 128)
- `--timeout, -t`: Request timeout in seconds (default: 5)
- `--debug`: Enable debug logging
- `--no-llm`: Disable LLM classification
- `--proxy`: HTTP proxy URL

### Input File Format

Create a text file with one URL per line:

```
https://github.com/modelcontextprotocol/servers
https://modelcontextprotocol.io/
https://docs.example.com/mcp/
# Comments are ignored
https://registry.mcp.example.com/
```

## Detection Pipeline

The tool uses a sophisticated 7-stage detection pipeline:

### Stage 1: Pre-flight Checks
- DNS resolution
- Port connectivity testing
- Basic reachability validation

### Stage 2: TLS Layer Analysis
- HTTP/HTTPS connectivity
- Header analysis
- SSL/TLS certificate inspection
- Automatic HTTP fallback for HTTPS failures

### Stage 3: Signature Scan
- Well-known MCP endpoints (`/.well-known/mcp/metadata.json`)
- MCP-specific HTTP headers
- DNS TXT record analysis
- URL pattern matching

### Stage 4: Context Parsing
- HTML content analysis
- Meta tag extraction
- TLS certificate MCP references
- Content pattern recognition

### Stage 5: LLM Classification (Optional)
- Ollama API integration
- Intelligent content analysis
- Context-aware categorization
- Confidence scoring

### Stage 6: Decision Aggregation
- Multi-signal scoring
- Weighted decision making
- Confidence calculation
- Category determination

### Stage 7: Result Persistence
- CSV output generation
- JSON detail export
- Error code tracking
- Performance metrics

## Output Format

### CSV Output (Google Sheets Compatible)

```csv
url,label,confidence,error_code,retry_count,elapsed_ms,notes
https://mcp.example.com,mcp_server,0.96,0000,1,245,"/metadata.json OK"
https://docs.example.com/mcp,mcp_intro,0.78,0401,2,832,"meta tag + LLM"
https://foo.bar,unknown,0.01,0101,3,115,"NXDOMAIN"
```

### JSON Output (Detailed)

The JSON output contains complete pipeline results including:
- All pipeline stage results
- Detailed error information
- Confidence breakdowns
- Reasoning chains
- Performance metrics

## Error Codes

| Code | Category | Description | Retry Policy |
|------|----------|-------------|--------------|
| 0000 | Success | No errors | N/A |
| 01xx | DNS | DNS resolution issues | 3 retries with backoff |
| 02xx | TCP | Connection issues | 3 retries |
| 03xx | TLS | SSL/TLS problems | 1 retry, then HTTP fallback |
| 04xx | HTTP | HTTP errors | 2-3 retries based on status |
| 05xx | Content | Content processing issues | No retry |
| 06xx | LLM | LLM analysis issues | 1 retry with reduced content |
| 09xx | General | Unknown errors | No retry |

## Environment Configuration

Create a `.env` file based on `.env.example`:

```env
# Ollama API configuration
OLLAMA_BASE_URL=http://localhost:11434

# Proxy settings (optional)
PROXY=http://proxy.local:8080

# MCP Specification repository
MCP_SPEC_REPO=https://github.com/modelcontextprotocol/registry.git

# Logging and performance
LOG_LEVEL=INFO
MAX_RETRY=3
REQUEST_TIMEOUT=5
DEFAULT_CONCURRENCY=32
MAX_CONCURRENCY=128

# SSL settings
STRICT_SSL=false
```

## LLM Integration (Ollama)

To enable LLM-based classification:

1. Install Ollama: https://ollama.ai/
2. Pull a model: `ollama pull llama2`
3. Start Ollama: `ollama serve`
4. Configure `OLLAMA_BASE_URL` in `.env`

The LLM provides intelligent content analysis and improves classification accuracy, especially for documentation and introduction pages.

## Performance Tuning

### Concurrency Settings
- Start with default concurrency (32)
- Increase for faster processing of large URL lists
- Monitor system resources and target server load
- Respect rate limits and server resources

### Timeout Configuration
- Default timeout: 5 seconds
- Increase for slow servers
- Decrease for faster processing of large lists
- Balance between accuracy and speed

### Memory Usage
- Each concurrent request uses ~1-2MB memory
- Large content downloads are limited to 1MB
- JSON output can be memory-intensive for large datasets

## Testing

Run the test suite:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src tests/

# Run specific test modules
pytest tests/test_signature.py
pytest tests/test_errors.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Security Considerations

⚠️ **Important**: This tool disables SSL certificate verification globally for research purposes. This poses security risks and should not be used in production environments where SSL verification is critical.

- All SSL bypass operations are logged
- Use in controlled environments only
- Consider enabling `STRICT_SSL=true` for production use
- Implement rate limiting to be respectful to target servers

## License

MIT License - see LICENSE file for details.

## Troubleshooting

### Common Issues

1. **"DNS resolution failed"**
   - Check internet connectivity
   - Verify URL format
   - Check DNS configuration

2. **"LLM unavailable"**
   - Ensure Ollama is installed and running
   - Check `OLLAMA_BASE_URL` configuration
   - Verify model is downloaded (`ollama pull llama2`)

3. **"Too many concurrent requests"**
   - Reduce `--concurrency` value
   - Check system resource limits
   - Monitor target server responses

4. **"Classification taking too long"**
   - Reduce `--timeout` value
   - Disable LLM with `--no-llm`
   - Use smaller URL batches

### Getting Help

- Check the debug output with `--debug`
- Review error codes in the output
- Check system resources and network connectivity
- Verify environment configuration

## Changelog

### Version 1.0.0
- Initial release
- 7-stage detection pipeline
- CSV/JSON output formats
- Ollama LLM integration
- Comprehensive error handling
- High-concurrency processing
