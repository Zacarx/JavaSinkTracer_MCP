#!/usr/bin/env python3
"""
JavaSinkTracer MCP Server
将JavaSinkTracer的功能封装为MCP工具，让AI可以调用分析Java代码漏洞
"""

import json
import sys
import os
import asyncio
from typing import Any, Sequence
from mcp.server import Server
from mcp.types import Tool, TextContent, ImageContent, EmbeddedResource
import mcp.server.stdio

from JavaSinkTracer import JavaSinkTracer
from JavaCodeExtract import extract_method_definition


# 创建MCP服务器实例
app = Server("javasinktracer")

# 全局变量存储分析器实例
analyzer_cache = {}


@app.list_tools()
async def list_tools() -> list[Tool]:
    """
    列出所有可用的工具
    """
    return [
        Tool(
            name="build_callgraph",
            description="构建Java项目的函数调用关系图(Call Graph)。分析项目中所有类和方法的调用关系。",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Java项目的本地根目录路径"
                    },
                    "rules_path": {
                        "type": "string",
                        "description": "规则配置文件路径，默认为Rules/rules.json",
                        "default": "Rules/rules.json"
                    }
                },
                "required": ["project_path"]
            }
        ),
        Tool(
            name="find_vulnerabilities",
            description="扫描Java项目，寻找从Sink到Source的污点传播链路，识别潜在安全漏洞。",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Java项目的本地根目录路径"
                    },
                    "rules_path": {
                        "type": "string",
                        "description": "规则配置文件路径，默认为Rules/rules.json",
                        "default": "Rules/rules.json"
                    },
                    "sink_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "要扫描的漏洞类型列表，如['RCE', 'SQLI']。不指定则扫描所有类型"
                    }
                },
                "required": ["project_path"]
            }
        ),
        Tool(
            name="analyze_vulnerability_chain",
            description="详细分析特定的漏洞调用链，提取每个函数的源代码。",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Java项目的本地根目录路径"
                    },
                    "call_chain": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "调用链，格式为['ClassName:methodName', ...]"
                    }
                },
                "required": ["project_path", "call_chain"]
            }
        ),
        Tool(
            name="extract_method_code",
            description="从Java项目中提取指定类的方法源代码。",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Java项目的本地根目录路径"
                    },
                    "class_name": {
                        "type": "string",
                        "description": "类名"
                    },
                    "method_name": {
                        "type": "string",
                        "description": "方法名"
                    }
                },
                "required": ["project_path", "class_name", "method_name"]
            }
        ),
        Tool(
            name="list_sink_rules",
            description="列出所有配置的Sink规则（漏洞危险函数）。",
            inputSchema={
                "type": "object",
                "properties": {
                    "rules_path": {
                        "type": "string",
                        "description": "规则配置文件路径，默认为Rules/rules.json",
                        "default": "Rules/rules.json"
                    },
                    "sink_type": {
                        "type": "string",
                        "description": "指定要查看的漏洞类型，不指定则返回所有类型"
                    }
                }
            }
        ),
        Tool(
            name="get_project_statistics",
            description="获取Java项目的统计信息，包括类数量、方法数量、调用关系数量等。",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Java项目的本地根目录路径"
                    },
                    "rules_path": {
                        "type": "string",
                        "description": "规则配置文件路径，默认为Rules/rules.json",
                        "default": "Rules/rules.json"
                    }
                },
                "required": ["project_path"]
            }
        )
    ]


def get_analyzer(project_path: str, rules_path: str = "Rules/rules.json") -> JavaSinkTracer:
    """
    获取或创建分析器实例（带缓存）
    """
    # 🚀 规范化路径，避免因路径差异导致缓存失效
    normalized_project_path = os.path.abspath(project_path).replace('\\', '/')
    normalized_rules_path = os.path.abspath(rules_path).replace('\\', '/')

    cache_key = f"{normalized_project_path}:{normalized_rules_path}"

    if cache_key not in analyzer_cache:
        print(f"[+] 缓存未命中，构建新的分析器: {cache_key}")
        analyzer = JavaSinkTracer(project_path, rules_path)
        analyzer.build_ast()
        analyzer_cache[cache_key] = analyzer
    else:
        print(f"[+] 缓存命中，复用现有分析器: {cache_key}")

    return analyzer_cache[cache_key]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """
    处理工具调用
    """
    try:
        if name == "build_callgraph":
            project_path = arguments["project_path"]
            rules_path = arguments.get("rules_path", "Rules/rules.json")

            analyzer = JavaSinkTracer(project_path, rules_path)
            analyzer.build_ast()

            # 缓存分析器
            cache_key = f"{project_path}:{rules_path}"
            analyzer_cache[cache_key] = analyzer

            result = {
                "success": True,
                "message": "调用关系图构建完成",
                "statistics": {
                    "total_classes": len(analyzer.class_methods),
                    "total_call_edges": len(analyzer.call_graph),
                    "total_methods": sum(len(info.get("methods", {})) for info in analyzer.class_methods.values()),
                    "total_files": analyzer.stats['total_files'],
                    "parsed_files": analyzer.stats['parsed_files'],
                    "skipped_files": analyzer.stats['skipped_files'],
                    "error_files": analyzer.stats['error_files']
                }
            }

            return [TextContent(
                type="text",
                text=json.dumps(result, indent=2, ensure_ascii=False)
            )]

        elif name == "find_vulnerabilities":
            project_path = arguments["project_path"]
            rules_path = arguments.get("rules_path", "Rules/rules.json")
            sink_types = arguments.get("sink_types")

            analyzer = get_analyzer(project_path, rules_path)

            # 如果指定了特定的sink类型，过滤规则
            if sink_types:
                original_rules = analyzer.rules["sink_rules"]
                analyzer.rules["sink_rules"] = [
                    rule for rule in original_rules
                    if rule["sink_name"] in sink_types
                ]

            # 🚀 使用轻量级查找，不立即提取代码
            vulnerabilities = analyzer.find_taint_paths_lightweight()

            # 恢复原规则
            if sink_types:
                analyzer.rules = analyzer._load_rules(rules_path)

            result = {
                "success": True,
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
                "note": "使用轻量级模式，代码提取已延迟。使用 analyze_vulnerability_chain 获取详细代码"
            }

            return [TextContent(
                type="text",
                text=json.dumps(result, indent=2, ensure_ascii=False)
            )]

        elif name == "analyze_vulnerability_chain":
            project_path = arguments["project_path"]
            call_chain = arguments["call_chain"]

            chain_details = []
            for func_sig in call_chain:
                class_name, method_name = func_sig.split(":", 1)
                file_path, code = extract_method_definition(project_path, class_name, method_name)

                chain_details.append({
                    "function": func_sig,
                    "file_path": file_path or "未找到",
                    "code": code or "未找到源代码"
                })

            result = {
                "success": True,
                "chain": chain_details
            }

            return [TextContent(
                type="text",
                text=json.dumps(result, indent=2, ensure_ascii=False)
            )]

        elif name == "extract_method_code":
            project_path = arguments["project_path"]
            class_name = arguments["class_name"]
            method_name = arguments["method_name"]

            file_path, code = extract_method_definition(project_path, class_name, method_name)

            result = {
                "success": True if code else False,
                "class_name": class_name,
                "method_name": method_name,
                "file_path": file_path or "未找到",
                "code": code or "未找到方法源代码"
            }

            return [TextContent(
                type="text",
                text=json.dumps(result, indent=2, ensure_ascii=False)
            )]

        elif name == "list_sink_rules":
            rules_path = arguments.get("rules_path", "Rules/rules.json")
            sink_type = arguments.get("sink_type")

            with open(rules_path, "r", encoding="utf-8") as f:
                rules = json.load(f)

            sink_rules = rules.get("sink_rules", [])

            if sink_type:
                sink_rules = [rule for rule in sink_rules if rule["sink_name"] == sink_type]

            result = {
                "success": True,
                "total_rules": len(sink_rules),
                "rules": sink_rules
            }

            return [TextContent(
                type="text",
                text=json.dumps(result, indent=2, ensure_ascii=False)
            )]

        elif name == "get_project_statistics":
            project_path = arguments["project_path"]
            rules_path = arguments.get("rules_path", "Rules/rules.json")

            analyzer = get_analyzer(project_path, rules_path)

            # 统计入口点数量
            entry_points = 0
            for class_info in analyzer.class_methods.values():
                for method_info in class_info.get("methods", {}).values():
                    if method_info.get("has_mapping_annotation", False):
                        entry_points += 1

            result = {
                "success": True,
                "statistics": {
                    "total_classes": len(analyzer.class_methods),
                    "total_methods": sum(len(info.get("methods", {})) for info in analyzer.class_methods.values()),
                    "total_call_edges": sum(len(callees) for callees in analyzer.call_graph.values()),
                    "entry_points": entry_points,
                    "total_files": analyzer.stats['total_files'],
                    "parsed_files": analyzer.stats['parsed_files'],
                    "skipped_files": analyzer.stats['skipped_files'],
                    "error_files": analyzer.stats['error_files'],
                    "classes_with_methods": list(analyzer.class_methods.keys())[:20]  # 显示前20个类
                }
            }

            return [TextContent(
                type="text",
                text=json.dumps(result, indent=2, ensure_ascii=False)
            )]

        else:
            return [TextContent(
                type="text",
                text=json.dumps({"error": f"未知工具: {name}"}, ensure_ascii=False)
            )]

    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": str(e),
                "detail": error_detail
            }, indent=2, ensure_ascii=False)
        )]


async def main():
    """
    主函数：启动MCP服务器
    """
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
