#!/usr/bin/env python3
"""
MCP Server for LoxiLB CICD Testing

This server provides mock MCP (Model Context Protocol) endpoints
for testing loxilb fullproxy load balancing with HTTPS termination.

Usage:
    python3 mcp-server.py [server_name] [port]

Example:
    python3 mcp-server.py server1 8080
"""

from fastmcp import FastMCP
import sys
import json
from datetime import datetime
import argparse

# Parse command-line arguments
parser = argparse.ArgumentParser(description='MCP Server for LoxiLB CICD Testing')
parser.add_argument('server_name', nargs='?', default='server', help='Server name')
parser.add_argument('port', nargs='?', type=int, default=8080, help='Port number')
parser.add_argument('--ssl-certfile', type=str, help='SSL certificate file path')
parser.add_argument('--ssl-keyfile', type=str, help='SSL key file path')
args = parser.parse_args()

server_name = args.server_name
port = args.port
ssl_certfile = args.ssl_certfile
ssl_keyfile = args.ssl_keyfile

# Create FastMCP server instance
mcp = FastMCP(f"MCP {server_name}")


@mcp.tool
def health() -> str:
    """Health check endpoint - returns OK if server is running."""
    return "OK"


@mcp.tool
def echo(message: str) -> str:
    """Echo the message with server identification.
    
    Args:
        message: The message to echo back
        
    Returns:
        Server name and the echoed message
    """
    return f"{server_name}:{message}"


@mcp.tool
def get_models() -> list[str]:
    """Return available models from this MCP server.
    
    Returns:
        List of available model names
    """
    return [
        f"{server_name}-gpt-4",
        f"{server_name}-gpt-3.5-turbo",
        f"{server_name}-claude-3"
    ]


@mcp.tool
def chat_completion(prompt: str, model: str = "default") -> dict:
    """Mock chat completion endpoint.
    
    Args:
        prompt: The chat prompt/message
        model: Model name to use (default: "default")
        
    Returns:
        Dictionary with server info, model, response, and timestamp
    """
    return {
        "server": server_name,
        "model": model,
        "prompt": prompt,
        "response": f"Response from {server_name} using {model}: {prompt}",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tokens": len(prompt.split())
    }


@mcp.tool
def get_server_info() -> dict:
    """Get information about this MCP server.
    
    Returns:
        Dictionary with server name, port, and capabilities
    """
    return {
        "name": server_name,
        "port": port,
        "protocol": "http",
        "capabilities": ["chat", "completion", "models"],
        "version": "1.0.0"
    }


@mcp.resource("config://info")
def get_config() -> dict:
    """Get server configuration.
    
    Returns:
        Configuration dictionary
    """
    return {
        "server": server_name,
        "transport": "http",
        "port": port
    }


@mcp.resource("status://health")
def get_status() -> str:
    """Get server status.
    
    Returns:
        Status string
    """
    return f"{server_name} is running"


if __name__ == "__main__":
    # Run MCP server on HTTP or HTTPS transport
    if ssl_certfile and ssl_keyfile:
        print(f"Starting MCP Server: {server_name} on HTTPS port {port}")
        print(f"SSL Certificate: {ssl_certfile}")
        print(f"SSL Key: {ssl_keyfile}")
        
        # For HTTPS, create ASGI app and run with uvicorn SSL
        import uvicorn
        
        # Create the ASGI application
        app = mcp.http_app(path="/mcp")
        
        # Run with uvicorn SSL
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=port,
            ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile,
            log_level="info"
        )
    else:
        print(f"Starting MCP Server: {server_name} on HTTP port {port}")
        mcp.run(transport="http", host="0.0.0.0", port=port, path="/mcp")
