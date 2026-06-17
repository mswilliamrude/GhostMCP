"""Tests for MCPServer class — registration, dispatch, and error handling."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.mcp import MCPServer


class TestMCPServerRegistration:
    """Tests for tool registration."""

    def test_register_tool(self):
        server = MCPServer("test", "A test server")

        @server.tool(
            name="my_tool",
            description="Does something",
            parameters={"arg1": {"type": "string"}},
        )
        async def my_tool(arg1: str):
            return f"got {arg1}"

        assert "my_tool" in server._tools
        assert "my_tool" in server._handlers
        assert server._tools["my_tool"]["name"] == "my_tool"
        assert server._tools["my_tool"]["description"] == "Does something"

    def test_register_multiple_tools(self):
        server = MCPServer("test")

        @server.tool(name="tool_a", description="A", parameters={})
        async def tool_a():
            return "a"

        @server.tool(name="tool_b", description="B", parameters={})
        async def tool_b():
            return "b"

        assert len(server._tools) == 2
        assert "tool_a" in server._tools
        assert "tool_b" in server._tools

    def test_tool_schema_structure(self):
        server = MCPServer("test")

        @server.tool(
            name="example",
            description="Example tool",
            parameters={"query": {"type": "string", "description": "Search query"}},
        )
        async def example(query: str):
            return query

        schema = server._tools["example"]
        assert schema["inputSchema"]["type"] == "object"
        assert "query" in schema["inputSchema"]["properties"]

    def test_server_name_and_description(self):
        server = MCPServer("GhostMCP", "OSINT toolkit")
        assert server.name == "GhostMCP"
        assert server.description == "OSINT toolkit"


class TestMCPHandleRequest:
    """Tests for handle_request dispatch."""

    @pytest.fixture
    def server(self):
        s = MCPServer("test-server", "Test")

        @s.tool(name="echo", description="Echo back", parameters={"text": {"type": "string"}})
        async def echo(text: str):
            return text

        @s.tool(name="add", description="Add numbers", parameters={"a": {"type": "integer"}, "b": {"type": "integer"}})
        async def add(a: int, b: int):
            return a + b

        @s.tool(name="fail", description="Always fails", parameters={})
        async def fail():
            raise RuntimeError("intentional failure")

        return s

    @pytest.mark.asyncio
    async def test_initialize(self, server):
        resp = await server.handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}
        })
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        result = resp["result"]
        assert result["protocolVersion"] == "2024-11-05"
        assert "tools" in result["capabilities"]
        assert result["serverInfo"]["name"] == "test-server"

    @pytest.mark.asyncio
    async def test_tools_list(self, server):
        resp = await server.handle_request({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
        })
        tools = resp["result"]["tools"]
        assert len(tools) == 3
        names = [t["name"] for t in tools]
        assert "echo" in names
        assert "add" in names
        assert "fail" in names

    @pytest.mark.asyncio
    async def test_tools_call_success(self, server):
        resp = await server.handle_request({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "hello"}}
        })
        assert resp["id"] == 3
        content = resp["result"]["content"]
        assert content[0]["type"] == "text"
        assert content[0]["text"] == "hello"

    @pytest.mark.asyncio
    async def test_tools_call_with_computation(self, server):
        resp = await server.handle_request({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "add", "arguments": {"a": 3, "b": 5}}
        })
        assert resp["result"]["content"][0]["text"] == "8"

    @pytest.mark.asyncio
    async def test_tools_call_unknown_tool(self, server):
        resp = await server.handle_request({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "nonexistent", "arguments": {}}
        })
        assert "error" in resp
        assert resp["error"]["code"] == -32601
        assert "nonexistent" in resp["error"]["message"]

    @pytest.mark.asyncio
    async def test_tools_call_handler_exception(self, server):
        resp = await server.handle_request({
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": {"name": "fail", "arguments": {}}
        })
        # Errors in handlers return isError=True, not JSON-RPC error
        result = resp["result"]
        assert result["isError"] is True
        assert "intentional failure" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_unknown_method(self, server):
        resp = await server.handle_request({
            "jsonrpc": "2.0", "id": 7, "method": "unknown/method", "params": {}
        })
        assert "error" in resp
        assert resp["error"]["code"] == -32601

    @pytest.mark.asyncio
    async def test_notification_initialized(self, server):
        resp = await server.handle_request({
            "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}
        })
        # Notifications return empty dict (no response)
        assert resp == {}

    @pytest.mark.asyncio
    async def test_response_format(self, server):
        resp = await server.handle_request({
            "jsonrpc": "2.0", "id": 99, "method": "initialize", "params": {}
        })
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 99
        assert "result" in resp


class TestMCPStaticHelpers:
    """Tests for _response and _error static methods."""

    def test_response_format(self):
        resp = MCPServer._response(42, {"data": "value"})
        assert resp == {"jsonrpc": "2.0", "id": 42, "result": {"data": "value"}}

    def test_error_format(self):
        resp = MCPServer._error(1, -32601, "Not found")
        assert resp == {
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32601, "message": "Not found"}
        }

    def test_response_with_none_id(self):
        resp = MCPServer._response(None, {})
        assert resp["id"] is None
