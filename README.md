# JavaSinkTracer_MCP

基于函数级污点分析的 Java 源代码漏洞审计工具，通过 Model Context Protocol (MCP) 为 AI 助手提供安全分析能力。

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置 Claude Desktop

编辑配置文件并添加 MCP 服务器配置：

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "javasinktracer": {
      "command": "python",
      "args": [
        "/path/to/JavaSinkTracer/mcp_server.py"
      ],
      "description": "Java源代码漏洞审计工具 - 基于函数级污点分析"
    }
  }
}
```

**注意**：将 `/path/to/JavaSinkTracer` 替换为实际的项目路径。

### 3. 重启 Claude Desktop

配置完成后重启 Claude Desktop，MCP 工具将自动加载。

## 核心功能

### 漏洞扫描
从危险函数（Sink）反向追踪到外部入口（Source），自动发现潜在的安全漏洞链路。

### 调用图分析
构建完整的 Java 项目函数调用关系图，支持跨文件、跨类的调用追踪。

### 智能分析
基于函数级污点分析，有效规避变量级追踪在复杂场景（线程、反射、回调）下的断链问题。

### 代码提取
自动提取漏洞链路上每个函数的完整源代码，便于人工或 AI 深入分析。

## 可用工具

| 工具名称 | 功能说明 |
|---------|---------|
| `build_callgraph` | 构建项目调用关系图 |
| `find_vulnerabilities` | 扫描安全漏洞 |
| `analyze_vulnerability_chain` | 分析漏洞调用链源代码 |
| `extract_method_code` | 提取指定方法源代码 |
| `list_sink_rules` | 查看漏洞规则配置 |
| `get_project_statistics` | 获取项目统计信息 |

## 使用示例

### 示例 1：全面漏洞扫描

```
请帮我扫描 /path/to/java-project 项目的安全漏洞
```

AI 会自动：
1. 构建调用关系图
2. 扫描所有类型的漏洞
3. 分析并报告发现的问题

### 示例 2：针对性检测

```
检查项目中是否存在 SQL 注入和命令执行漏洞
```

AI 会扫描特定类型的漏洞（SQLI、RCE）。

### 示例 3：深入分析

```
这个漏洞链路是真实漏洞吗？请分析调用链的源代码
```

AI 会提取完整的调用链代码并进行分析。

## 支持的漏洞类型

- **RCE** - 远程代码执行 (CWE-78)
- **SQLI** - SQL 注入 (CWE-89)
- **XXE** - XML 外部实体注入 (CWE-611)
- **SSRF** - 服务端请求伪造 (CWE-918)
- **PATH_TRAVERSAL** - 路径穿越 (CWE-22)
- **DESERIALIZE** - 反序列化漏洞 (CWE-502)
- **XPATH_INJECTION** - XPath 注入 (CWE-643)
- **TEMPLATE_INJECTION** - 模板注入 (CWE-94)
- **JNDI_INJECTION** - JNDI 注入 (CWE-74)
- **REFLECTION_INJECTION** - 反射注入 (CWE-470)
- **LOG_INJECTION** - 日志注入 (CWE-117)
- **CRYPTO_WEAKNESS** - 加密算法弱点 (CWE-327)

## 支持的框架

- Spring Boot / Spring MVC
- MyBatis / Hibernate / JPA
- Fastjson / Jackson / Gson
- OkHttp / Apache HttpClient
- Freemarker / Velocity / Thymeleaf
- Log4j / SLF4J

## 工作原理

### 函数级污点分析

不同于传统 SAST 工具的"变量级"污点分析，本工具采用"函数级"污点分析：

- **优势**：有效规避线程调用、监听回调、反射调用等场景的断链问题
- **权衡**：可能产生误报，需要结合 AI 或人工进一步分析确认

### 分析流程

1. 解析 Java 源代码，构建 AST
2. 提取所有类和方法信息
3. 构建函数调用关系图
4. 从 Sink 点（危险函数）反向追踪
5. 识别到达 Source 点（外部入口）的调用链
6. 过滤无参数的函数（排除不可控变量）
7. 提取调用链上所有函数的源代码

## 配置说明

### 规则文件

规则配置文件位于 `Rules/rules.json`，包含：

- **sink_rules**: 危险函数规则（如 `Runtime.exec`）
- **source_rules**: 外部输入源（如 `HttpServletRequest.getParameter`）
- **sanitizer_rules**: 净化函数（如 `StringEscapeUtils.escapeHtml`）

### 自定义规则

可以根据实际需求编辑 `rules.json` 添加新的 Sink、Source 或 Sanitizer 规则：

```json
{
  "sink_rules": [
    {
      "sink_name": "CUSTOM_VULN",
      "sink_desc": "自定义漏洞类型",
      "severity_level": "High",
      "cwe": "CWE-XXX",
      "sinks": [
        "com.example.DangerousClass:dangerousMethod"
      ]
    }
  ]
}
```

## 性能优化

### 缓存机制

- 首次分析项目时构建 AST 和调用图
- 后续调用自动复用缓存，大幅提升速度
- 缓存 key：`project_path:rules_path`

### 轻量级模式

`find_vulnerabilities` 工具默认使用轻量级模式：
- 仅返回漏洞链路信息
- 不立即提取源代码
- 需要时使用 `analyze_vulnerability_chain` 获取详细代码

## 常见问题

### 工具未加载？

1. 检查配置文件中的路径是否正确
2. 确认已安装所有 Python 依赖
3. 查看 Claude Desktop 的开发者工具日志

### 分析速度慢？

- 大型项目首次分析需要时间构建 AST
- 使用缓存后速度会显著提升
- 可先调用 `build_callgraph` 预热缓存

### 结果有误报？

- 函数级污点分析会产生一定误报
- 使用 `analyze_vulnerability_chain` 查看源代码
- 结合 AI 分析或人工确认漏洞真实性

## 扩展开发

### 添加新的 MCP 工具

编辑 `mcp_server.py`：

```python
@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="your_tool",
            description="工具描述",
            inputSchema={...}
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: Any):
    if name == "your_tool":
        # 实现你的工具逻辑
        pass
```

## 相关资源

- **详细使用指南**: 查看 `MCP_GUIDE.md`
- **原理说明**: 查看 `README.md`
- **优化日志**: 查看 `UPGRADE_SUMMARY.md`

## 致谢

JavaSinkTracer开发者 [Tr0e](https://github.com/Tr0e) 
