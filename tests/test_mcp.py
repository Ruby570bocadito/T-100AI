import pytest

from t100ai.mcp.registry import ToolRegistry
from t100ai.mcp.tool import MCPTool


def test_tool_registry_creation():
    reg = ToolRegistry()
    assert reg is not None
    assert hasattr(reg, "tools")


def test_tool_registry_discover_tools():
    reg = ToolRegistry()
    assert hasattr(reg, "discover_tools")


@pytest.mark.asyncio
async def test_tool_registration():
    reg = ToolRegistry()
    tool = MCPTool(
        name="test_tool",
        description="A test tool",
        category="test",
        skill="test",
        risk_level=0,
        command="echo test",
    )
    reg.register(tool)
    assert "test_tool" in reg.tools
    assert reg.get_tool("test_tool") is not None


def test_tool_search():
    reg = ToolRegistry()
    tool = MCPTool(
        name="nmap_custom",
        description="Custom nmap scan",
        category="recon",
        skill="recon",
        risk_level=0,
        command="nmap -sV",
    )
    reg.register(tool)
    results = reg.search("nmap")
    assert len(results) >= 1
    assert any("nmap" in t.name.lower() for t in results)


def test_tool_list_tools():
    reg = ToolRegistry()
    tool = MCPTool(
        name="list_test",
        description="List test tool",
        category="test",
        skill="test",
        risk_level=0,
        command="echo list",
    )
    reg.register(tool)
    tools = reg.list_tools()
    assert isinstance(tools, list)
    assert any(t.name == "list_test" for t in tools)


def test_tool_list_by_category():
    reg = ToolRegistry()
    tool = MCPTool(
        name="cat_test",
        description="Category test tool",
        category="test/sub",
        skill="test",
        risk_level=0,
        command="echo cat",
    )
    reg.register(tool)
    tools = reg.list_tools(category="test/sub")
    assert isinstance(tools, list)
    assert any(t.name == "cat_test" for t in tools)
