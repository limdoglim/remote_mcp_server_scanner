<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# MCP URL Classifier Project Instructions

This is a Python CLI tool that classifies URLs into Model Context Protocol (MCP) related categories:
- mcp_server: Actual MCP server implementations
- mcp_intro: Documentation and introduction pages about MCP
- mcp_registry: MCP server registries and directories
- unknown: URLs that don't fit the above categories

## Key Implementation Guidelines

1. **Async/Await Pattern**: Use asyncio for all I/O operations including HTTP requests, DNS lookups, and file operations
2. **SSL Verification**: Globally disabled (verify=False) but always log security warnings
3. **Error Handling**: Implement comprehensive error codes (ERR_DNS_*, ERR_TCP_*, ERR_TLS_*, etc.) with retry policies
4. **Detection Pipeline**: Follow the 7-stage pipeline: pre_flight → tls_layer → signature_scan → context_parse → llm_classify → decision.aggregate → persist
5. **Concurrency**: Support configurable concurrency levels (default 32, max 128)
6. **Output Formats**: Support both CSV (default) and JSON output with detailed metrics

## Security Considerations
- Always log SSL verification bypass warnings
- Implement rate limiting and respect server resources
- Handle timeouts gracefully with exponential backoff

## Testing Requirements
- Mock servers for various error scenarios
- Target 90%+ detection accuracy
- 95%+ error mapping accuracy
