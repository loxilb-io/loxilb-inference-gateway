#!/usr/bin/env python3
"""
MCP Client for LoxiLB CICD Testing

This client tests MCP server endpoints through loxilb load balancer
with HTTPS termination and HTTP backend.

Usage:
    python3 mcp-client.py <server_url> [test_type] [--ca-cert <path>] [--prompt <text>] [--message <text>]

Example:
    python3 mcp-client.py https://10.10.10.254:2020/mcp
    python3 mcp-client.py https://10.10.10.254:2020/mcp health
    python3 mcp-client.py https://10.10.10.254:2020/mcp full
    python3 mcp-client.py https://10.10.10.254:2020/mcp chat --prompt "Hello from test"
    python3 mcp-client.py https://10.10.10.254:2020/mcp echo --message "Test message"
    python3 mcp-client.py https://192.168.100.20:8443/mcp health --ca-cert /app/minica.pem
"""

import asyncio
import sys
import json
import ssl
import os
import httpx
from fastmcp.client import Client
from fastmcp.client.transports import StreamableHttpTransport


async def test_health(client: Client) -> bool:
    """Test health check endpoint."""
    try:
        result = await client.call_tool("health")
        print(f"Health: {result.data}")
        return result.data == "OK"
    except Exception as e:
        print(f"Health check failed: {e}")
        return False


async def test_echo(client: Client, message: str = "test-message") -> bool:
    """Test echo endpoint."""
    try:
        result = await client.call_tool("echo", {"message": message})
        print(f"Echo: {result.data}")
        return message in str(result.data)
    except Exception as e:
        print(f"Echo test failed: {e}")
        return False


async def test_models(client: Client) -> bool:
    """Test get models endpoint."""
    try:
        result = await client.call_tool("get_models")
        print(f"Models: {result.data}")
        return isinstance(result.data, list) and len(result.data) > 0
    except Exception as e:
        print(f"Get models test failed: {e}")
        return False


async def test_chat_completion(client: Client, prompt: str = "Hello MCP", model: str = "test-model") -> bool:
    """Test chat completion endpoint."""
    try:
        result = await client.call_tool("chat_completion", {
            "prompt": prompt,
            "model": model
        })
        print(f"Chat: {json.dumps(result.data, indent=2)}")
        return isinstance(result.data, dict) and "response" in result.data
    except Exception as e:
        print(f"Chat completion test failed: {e}")
        return False


async def test_server_info(client: Client) -> bool:
    """Test server info endpoint."""
    try:
        result = await client.call_tool("get_server_info")
        print(f"Server Info: {json.dumps(result.data, indent=2)}")
        return isinstance(result.data, dict) and "name" in result.data
    except Exception as e:
        print(f"Server info test failed: {e}")
        return False


async def test_resources(client: Client) -> bool:
    """Test resource endpoints."""
    try:
        # List available resources
        resources = await client.list_resources()
        print(f"Available Resources: {len(resources)}")
        
        # Read config resource
        result = await client.read_resource("config://info")
        print(f"Config: {result[0].text}")
        
        return True
    except Exception as e:
        print(f"Resource test failed: {e}")
        return False


async def run_all_tests(server_url: str, ca_cert_path: str = None, custom_prompt: str = None, custom_message: str = None):
    """Run all MCP client tests."""
    print(f"Testing MCP server at: {server_url}\n")
    
    # Configure httpx client with SSL verification
    if server_url.startswith("https://"):
        if ca_cert_path and os.path.exists(ca_cert_path):
            print(f"Using CA certificate: {ca_cert_path}")
            # Create factory that returns httpx client with CA certificate
            factory = lambda **kwargs: httpx.AsyncClient(verify=ca_cert_path, **kwargs)
            transport = StreamableHttpTransport(server_url, httpx_client_factory=factory)
        else:
            # Disable verification for self-signed certs if no CA provided
            print("Warning: SSL verification disabled (no CA certificate)")
            factory = lambda **kwargs: httpx.AsyncClient(verify=False, **kwargs)
            transport = StreamableHttpTransport(server_url, httpx_client_factory=factory)
    else:
        transport = StreamableHttpTransport(server_url)
    
    results = {
        "health": False,
        "echo": False,
        "models": False,
        "chat": False,
        "server_info": False,
        "resources": False
    }
    
    try:
        async with Client(transport=transport) as client:
            print("=== Testing Health Check ===")
            results["health"] = await test_health(client)
            print()
            
            print("=== Testing Echo ===")
            if custom_message:
                results["echo"] = await test_echo(client, custom_message)
            else:
                results["echo"] = await test_echo(client)
            print()
            
            print("=== Testing Get Models ===")
            results["models"] = await test_models(client)
            print()
            
            print("=== Testing Chat Completion ===")
            if custom_prompt:
                results["chat"] = await test_chat_completion(client, custom_prompt)
            else:
                results["chat"] = await test_chat_completion(client)
            print()
            
            print("=== Testing Server Info ===")
            results["server_info"] = await test_server_info(client)
            print()
            
            print("=== Testing Resources ===")
            results["resources"] = await test_resources(client)
            print()
            
    except Exception as e:
        print(f"Client connection failed: {e}")
        return False
    
    # Print summary
    print("=== Test Summary ===")
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    for test_name, result in results.items():
        status = "✓" if result else "✗"
        print(f"  {status} {test_name}")
    
    return all(results.values())


async def run_single_test(server_url: str, test_type: str, ca_cert_path: str = None, custom_prompt: str = None, custom_message: str = None):
    """Run a single test."""
    # Configure httpx client with SSL verification
    if server_url.startswith("https://"):
        if ca_cert_path and os.path.exists(ca_cert_path):
            # Create factory that returns httpx client with CA certificate
            factory = lambda **kwargs: httpx.AsyncClient(verify=ca_cert_path, **kwargs)
            transport = StreamableHttpTransport(server_url, httpx_client_factory=factory)
        else:
            # Disable verification for self-signed certs if no CA provided
            factory = lambda **kwargs: httpx.AsyncClient(verify=False, **kwargs)
            transport = StreamableHttpTransport(server_url, httpx_client_factory=factory)
    else:
        transport = StreamableHttpTransport(server_url)
    
    try:
        async with Client(transport=transport) as client:
            if test_type == "health":
                success = await test_health(client)
            elif test_type == "echo":
                if custom_message:
                    success = await test_echo(client, custom_message)
                else:
                    success = await test_echo(client)
            elif test_type == "models":
                success = await test_models(client)
            elif test_type == "chat":
                if custom_prompt:
                    success = await test_chat_completion(client, custom_prompt)
                else:
                    success = await test_chat_completion(client)
            elif test_type == "info":
                success = await test_server_info(client)
            elif test_type == "resources":
                success = await test_resources(client)
            else:
                print(f"Unknown test type: {test_type}")
                return False
            
            return success
    except Exception as e:
        print(f"Test failed: {e}")
        return False


async def main():
    if len(sys.argv) < 2:
        print("Usage: mcp-client.py <server_url> [test_type] [--ca-cert <path>] [--prompt <text>] [--message <text>]")
        print("  test_type: health|echo|models|chat|info|resources|full (default: health)")
        print("  --ca-cert: Path to CA certificate for SSL verification")
        print("  --prompt: Custom prompt for chat test")
        print("  --message: Custom message for echo test")
        sys.exit(1)
    
    server_url = sys.argv[1]
    test_type = "health"
    ca_cert_path = None
    custom_prompt = None
    custom_message = None
    
    # Parse arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--ca-cert" and i + 1 < len(sys.argv):
            ca_cert_path = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--prompt" and i + 1 < len(sys.argv):
            custom_prompt = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--message" and i + 1 < len(sys.argv):
            custom_message = sys.argv[i + 1]
            i += 2
        else:
            test_type = sys.argv[i]
            i += 1
    
    if test_type == "full":
        success = await run_all_tests(server_url, ca_cert_path, custom_prompt, custom_message)
    else:
        success = await run_single_test(server_url, test_type, ca_cert_path, custom_prompt, custom_message)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
