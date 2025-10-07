# JavaSinkTracer MCP 服务器使用指南

## 概述

JavaSinkTracer MCP 服务器将轻量级 Java 源代码漏洞审计工具封装为 Model Context Protocol (MCP) 工具，允许 AI 助手（如 Claude）调用分析 Java 代码中的安全漏洞。

## MCP 架构优势

将 JavaSinkTracer 拆分为 MCP 工具的优势：

1. **模块化设计**：每个功能独立为一个工具，职责清晰
2. **AI 可调用**：AI 可以智能地组合调用不同工具完成复杂分析
3. **增量分析**：可以先构建调用图，再针对性地分析特定漏洞类型
4. **交互式审计**：AI 可以根据分析结果动态决定下一步操作
5. **易于扩展**：新增漏洞类型或分析功能只需添加新工具

## 安装

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置 Claude Desktop

编辑 Claude Desktop 配置文件：

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%/Claude/claude_desktop_config.json`

添加以下配置（修改路径为实际路径）：

```json
{
  "mcpServers": {
    "javasinktracer": {
      "command": "python",
      "args": [
        "/path/to/JavaSinkTracer/mcp_server.py"
      ]
    }
  }
}
```

### 3. 重启 Claude Desktop

配置完成后重启 Claude Desktop，工具将自动加载。

## 可用工具

### 1. build_callgraph

**功能**：构建 Java 项目的函数调用关系图

**参数**：
- `project_path` (必需): Java 项目根目录路径
- `rules_path` (可选): 规则配置文件路径，默认 `Rules/rules.json`

**示例**：
```
请使用 build_callgraph 工具分析 /path/to/java-project
```

**返回**：
```json
{
  "success": true,
  "message": "调用关系图构建完成",
  "statistics": {
    "total_classes": 150,
    "total_call_edges": 3500,
    "total_methods": 800
  }
}
```

---

### 2. find_vulnerabilities

**功能**：扫描 Java 项目，寻找从 Sink 到 Source 的污点传播链路

**参数**：
- `project_path` (必需): Java 项目根目录路径
- `rules_path` (可选): 规则配置文件路径
- `sink_types` (可选): 要扫描的漏洞类型数组，如 `["RCE", "SQLI"]`

**示例**：
```
请扫描 /path/to/java-project 中的 RCE 和 SQL 注入漏洞
```

**返回**：
```json
{
  "success": true,
  "total_vulnerabilities": 5,
  "vulnerabilities": [
    {
      "vul_type": "RCE",
      "sink_desc": "任意代码执行漏洞",
      "severity": "High",
      "sink": "Runtime:exec",
      "call_chains": [...]
    }
  ]
}
```

---

### 3. analyze_vulnerability_chain

**功能**：详细分析特定的漏洞调用链，提取每个函数的源代码

**参数**：
- `project_path` (必需): Java 项目根目录路径
- `call_chain` (必需): 调用链数组，格式 `["ClassName:methodName", ...]`

**示例**：
```
请分析这条调用链的源代码：["UserController:executeCommand", "CommandExecutor:exec"]
```

**返回**：
```json
{
  "success": true,
  "chain": [
    {
      "function": "UserController:executeCommand",
      "file_path": "/path/to/UserController.java",
      "code": "public void executeCommand(String cmd) { ... }"
    }
  ]
}
```

---

### 4. extract_method_code

**功能**：从 Java 项目中提取指定类的方法源代码

**参数**：
- `project_path` (必需): Java 项目根目录路径
- `class_name` (必需): 类名
- `method_name` (必需): 方法名

**示例**：
```
请提取 UserService 类中的 validateUser 方法源代码
```

**返回**：
```json
{
  "success": true,
  "class_name": "UserService",
  "method_name": "validateUser",
  "file_path": "/path/to/UserService.java",
  "code": "public boolean validateUser(String username) { ... }"
}
```

---

### 5. list_sink_rules

**功能**：列出所有配置的 Sink 规则（漏洞危险函数）

**参数**：
- `rules_path` (可选): 规则配置文件路径
- `sink_type` (可选): 指定漏洞类型，如 `"RCE"`

**示例**：
```
列出所有 RCE 类型的 Sink 规则
```

**返回**：
```json
{
  "success": true,
  "total_rules": 1,
  "rules": [
    {
      "sink_name": "RCE",
      "sink_desc": "任意代码执行漏洞",
      "severity_level": "High",
      "cwe": "CWE-78",
      "sinks": ["java.lang.Runtime:exec", ...]
    }
  ]
}
```

---

### 6. get_project_statistics

**功能**：获取 Java 项目的统计信息

**参数**：
- `project_path` (必需): Java 项目根目录路径
- `rules_path` (可选): 规则配置文件路径

**示例**：
```
获取项目的统计信息
```

**返回**：
```json
{
  "success": true,
  "statistics": {
    "total_classes": 150,
    "total_methods": 800,
    "total_call_edges": 3500,
    "entry_points": 45,
    "classes_with_methods": ["UserController", "OrderService", ...]
  }
}
```

## 使用场景

### 场景 1：全面漏洞扫描

```
我想全面扫描 /path/to/java-sec-code 项目的安全漏洞，
请先构建调用图，然后扫描所有类型的漏洞。
```

AI 会依次调用：
1. `build_callgraph` - 构建调用图
2. `find_vulnerabilities` - 扫描所有漏洞
3. 根据结果分析并生成报告

### 场景 2：针对性漏洞分析

```
请检查项目中是否存在 SQL 注入和命令执行漏洞
```

AI 会调用：
```
find_vulnerabilities(sink_types=["SQLI", "RCE"])
```

### 场景 3：深入分析特定漏洞链

```
发现了一个 RCE 漏洞链，请帮我分析这条链路的源代码，
看看是否真的存在漏洞
```

AI 会调用：
1. `analyze_vulnerability_chain` - 提取调用链源代码
2. 分析代码判断是否为真实漏洞

### 场景 4：了解规则配置

```
目前支持哪些类型的漏洞检测？RCE 类型包含哪些 Sink 函数？
```

AI 会调用：
```
list_sink_rules() 或 list_sink_rules(sink_type="RCE")
```

## 优化后的污点规则库

新版规则库包含以下改进：

### 新增漏洞类型

1. **XPATH_INJECTION** (CWE-643) - XPath 注入
2. **CRYPTO_WEAKNESS** (CWE-327) - 加密算法弱点
3. **TEMPLATE_INJECTION** (CWE-94) - 模板注入
4. **LOG_INJECTION** (CWE-117) - 日志注入
5. **JNDI_INJECTION** (CWE-74) - JNDI 注入
6. **REFLECTION_INJECTION** (CWE-470) - 反射注入

### 增强的规则内容

- **CWE 映射**：每个规则添加了 CWE 编号
- **更多 Sink 点**：扩充了常见框架的危险函数
  - Spring Framework
  - MyBatis
  - Hibernate
  - Jackson/Fastjson
  - OkHttp/Retrofit
  - Freemarker/Velocity
- **Source 规则**：新增外部输入源识别
- **Sanitizer 规则**：新增净化函数识别

### 支持的框架

- Spring Boot / Spring MVC
- MyBatis / Hibernate / JPA
- Fastjson / Jackson / Gson
- OkHttp / Apache HttpClient
- Freemarker / Velocity / Thymeleaf
- Log4j / SLF4J
- 更多...

## 工作流程

典型的 AI 辅助审计工作流：

```
用户：请帮我审计这个 Java 项目的安全问题

AI 步骤：
1. 调用 get_project_statistics - 了解项目规模
2. 调用 build_callgraph - 构建调用关系
3. 调用 find_vulnerabilities - 扫描漏洞
4. 对于每个高危漏洞：
   a. 调用 analyze_vulnerability_chain - 提取源代码
   b. 分析代码判断真实性
   c. 评估风险等级
5. 生成审计报告
```

## 技术细节

### 缓存机制

MCP 服务器实现了分析器缓存：
- 首次分析项目时构建 AST 和调用图
- 后续调用复用缓存，提升性能
- 缓存 key: `project_path:rules_path`

### 错误处理

所有工具调用都包含错误处理：
- 捕获异常并返回详细错误信息
- 包含堆栈跟踪便于调试

### 异步设计

采用 Python asyncio 实现异步处理：
- 支持并发调用
- 不阻塞主线程

## 故障排除

### 工具未加载

1. 检查配置文件路径是否正确
2. 确认 Python 环境已安装所有依赖
3. 查看 Claude Desktop 日志

### 分析失败

1. 确认 Java 项目路径正确
2. 检查项目是否包含有效的 .java 文件
3. 查看返回的错误详情

### 性能问题

- 大型项目首次分析较慢（构建 AST）
- 使用缓存后续调用会快很多
- 可以先用 `build_callgraph` 预热缓存

## 扩展开发

### 添加新工具

编辑 `mcp_server.py`：

```python
@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # ... 现有工具
        Tool(
            name="new_tool",
            description="新工具描述",
            inputSchema={...}
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: Any):
    if name == "new_tool":
        # 实现逻辑
        pass
```

### 自定义规则

编辑 `Rules/rules.json` 添加新的 Sink/Source/Sanitizer 规则。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可

与 JavaSinkTracer 主项目相同。
