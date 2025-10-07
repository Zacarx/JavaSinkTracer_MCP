"""
@File：JavaSinkTracer.py
@Time：2025/02/15 10:39
@Auth：Tr0e
@Github：https://github.com/Tr0e
@Description：基于javalang库，对漏洞Sink点进行回溯，提取Java源代码中“函数级”的污点调用链路
"""
import argparse
import os
import json
import time

import javalang
from javalang import tree
from collections import deque
from typing import Dict, List, Union
from colorama import Fore, init
from javalang.tree import ClassDeclaration

from JavaCodeExtract import extract_method_definition
from AutoVulReport import generate_markdown_report

init(autoreset=True)


class JavaSinkTracer:
    def __init__(self, project_path: str, rules_path: str):
        self.project_path = project_path
        self.rules = self._load_rules(rules_path)
        self.call_graph: Dict[str, List[str]] = {}
        self.class_methods: Dict[str, Dict[str, Union[str, Dict[str, Dict[str, bool]]]]] = {}

        # 🚀 反向调用图索引，用于O(1)查找调用者
        self.reverse_call_graph: Dict[str, List[str]] = {}
        # 🚀 类到文件的映射，用于快速定位类文件
        self.class_to_file_map: Dict[str, str] = {}

        # 添加统计信息
        self.stats = {
            'total_files': 0,
            'parsed_files': 0,
            'skipped_files': 0,
            'error_files': 0,
            'skipped_file_list': [],
            'error_file_list': []
        }

    @staticmethod
    def _load_rules(path: str) -> dict:
        """
        读取本地json格式的配置文件的数据
        """
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f)
            print(f"[+]成功加载Rules：{rules}")
            return rules

    def _is_excluded(self, file_path):
        """
        判断当前的代码路径是不是配置文件设置的无需扫描的白名单路径
        """
        rel_path = os.path.relpath(file_path, self.project_path)
        return any(p in rel_path.split(os.sep) for p in self.rules["path_exclusions"])

    def _should_skip_file(self, file_path):
        """
        判断文件是否应该跳过（模板文件、测试资源等）
        """
        # 跳过模板文件和其他非标准Java文件
        skip_patterns = [
            '/resources/template/',
            '/src/test/resources/',
            '/target/',
            '/build/',
        ]
        skip_extensions = ['.ftl', '.jsp', '.vm', '.jspx']

        rel_path = os.path.relpath(file_path, self.project_path)

        # 检查路径模式
        if any(pattern in rel_path.replace(os.sep, '/') for pattern in skip_patterns):
            return True

        # 检查文件扩展名（可能是.java.ftl这样的文件）
        if any(file_path.endswith(ext) for ext in skip_extensions):
            return True

        return False

    def build_ast(self):
        """
        构建项目AST并建立调用关系
        """
        print(f"[+]正构建项目AST：{self.project_path}")
        for root, _, files in os.walk(self.project_path):
            for file in files:
                if not file.endswith(".java"):
                    continue

                file_path = os.path.join(root, file)
                self.stats['total_files'] += 1

                # 检查是否被排除
                if self._is_excluded(root):
                    continue

                # 检查是否应跳过（模板文件等）
                if self._should_skip_file(file_path):
                    self.stats['skipped_files'] += 1
                    self.stats['skipped_file_list'].append(file_path)
                    # print(Fore.YELLOW + f"[跳过]模板/资源文件：{file}")
                    continue

                try:
                    # print(f"[+]正在分析的文件：{file}")
                    self._process_file(file_path)
                    self.stats['parsed_files'] += 1
                except Exception as e:
                    self.stats['error_files'] += 1
                    self.stats['error_file_list'].append({'file': file_path, 'error': str(e)})
                    print(Fore.RED + f"[错误]文件解析失败：{file}, 原因：{str(e)}")  # 保留错误信息
                    continue

        print(Fore.LIGHTBLUE_EX + f"[+]AST构建全部完成！")
        print(Fore.CYAN + f"[统计]总文件: {self.stats['total_files']}, "
                          f"已解析: {self.stats['parsed_files']}, "
                          f"已跳过: {self.stats['skipped_files']}, "
                          f"错误: {self.stats['error_files']}")
        # print(f"[+]已构建的调用关系图：{self.call_graph}")
        # print(f"[+]已构建的类方法信息：{self.class_methods}")

        # 🚀 构建反向调用图索引
        print(Fore.CYAN + "[+] 正在构建反向调用图索引...")
        self._build_reverse_call_graph()
        print(Fore.LIGHTGREEN_EX + f"[+] 反向索引构建完成，共 {len(self.reverse_call_graph)} 个节点")

    def _build_reverse_call_graph(self):
        """
        构建反向调用图索引
        从 caller -> callees 构建 callee -> callers 映射
        时间复杂度: O(E)，E为调用图边数
        """
        self.reverse_call_graph.clear()
        for caller, callees in self.call_graph.items():
            for callee in callees:
                if callee not in self.reverse_call_graph:
                    self.reverse_call_graph[callee] = []
                self.reverse_call_graph[callee].append(caller)

        # 去重
        for callee in self.reverse_call_graph:
            self.reverse_call_graph[callee] = list(set(self.reverse_call_graph[callee]))

    def _process_file(self, file_path: str):
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                code_tree = javalang.parse.parse(f.read())
                # print(Fore.GREEN + f"[+]已成功解析文件：{file_path}")
                self._extract_class_info(code_tree, file_path)
                self._build_call_graph(code_tree)
            except javalang.parser.JavaSyntaxError as e:
                raise Exception(f"Java语法错误: {e}")
            except javalang.tokenizer.LexerError as e:
                raise Exception(f"词法分析错误(可能是模板文件): {e}")

    def _extract_class_info(self, code_tree, file_path: str):
        """
        提取Java项目中类和方法信息，包含完整文件路径
        """
        MAPPING_ANNOTATIONS = {
            "GetMapping", "PostMapping", "RequestMapping", "PutMapping", "DeleteMapping",
            "Path", "GET", "POST", "PUT", "DELETE"
        }
        for path, node in code_tree.filter(ClassDeclaration):
            class_name = node.name
            methods_info = {}
            for method_node in node.methods:
                method_name = method_node.name
                requires_params = len(method_node.parameters) > 0
                has_mapping_annotation = False
                if method_node.annotations:
                    for annotation in method_node.annotations:
                        annotation_name = annotation.name.lstrip("@")
                        if annotation_name in MAPPING_ANNOTATIONS:
                            has_mapping_annotation = True
                            break
                methods_info[method_name] = {
                    "requires_params": requires_params,
                    "has_mapping_annotation": has_mapping_annotation
                }

            # 🚀 记录类到文件的映射
            self.class_to_file_map[class_name] = file_path

            self.class_methods[class_name] = {
                "file_path": file_path,
                "methods": methods_info
            }

    def _build_call_graph(self, file_code_tree):
        """
        构建所有类中方法的调用图
        """
        variable_symbols = self.get_variable_symbols(file_code_tree)
        for path, node in file_code_tree.filter(javalang.tree.MethodInvocation):
            caller = self._get_current_method_from_path(path)
            callee = "[!]callee解析失败"
            if node.qualifier:
                default = node.qualifier.split('.')[0] if '.' in node.qualifier and node.qualifier.split('.')[0][0].isupper() else node.qualifier
                base_type = variable_symbols.get(node.qualifier, default)
                base_type = base_type.split('<')[0]
                callee = f"{base_type}:{node.member}"
            elif node.qualifier is None:
                base_type = '[!]base_type解析失败'
                if self.is_string_literal_caller(path):
                    base_type = "String"
                else:
                    try:
                        parent_node = path[-2] if len(path) > 1 else None
                        if isinstance(parent_node, javalang.tree.ClassCreator):
                            base_type = parent_node.type.name
                        elif isinstance(parent_node, javalang.tree.ClassReference):
                            base_type = parent_node.type.name
                        else:
                            base_type = self.call_graph[caller][-1].split(':')[0]
                    except Exception as e:
                        print(Fore.RED + f"[!]待排查异常解析：{caller} -> {node.member}, 异常信息：{e}")
                callee = f"{base_type}:{node.member}"
            elif '.' not in node.member:
                callee = f"{caller.split(':')[0]}:{node.member}"
            # if str(callee).startswith('[!]'):
            #     print(Fore.RED + f"[CallGraph] {caller} -> {callee}")
            # else:
            #     print(f"[CallGraph] {caller} -> {callee}")
            self.call_graph.setdefault(caller, []).append(callee)

    @staticmethod
    def is_string_literal_caller(path):
        """
        判断方法调用是否由字符串常量
        """
        for parent in reversed(path):
            if isinstance(parent, javalang.tree.Literal) and isinstance(parent.value, str):
                return True
        return False

    @staticmethod
    def get_variable_symbols(file_code_tree):
        """
        提取类中所有变量声明及其类型
        """
        variable_symbols = {}
        for path, node in file_code_tree:
            if isinstance(node, javalang.tree.LocalVariableDeclaration):
                var_type = node.type.name
                for declarator in node.declarators:
                    variable_symbols[declarator.name] = var_type
            elif isinstance(node, javalang.tree.FieldDeclaration):
                var_type = node.type.name
                for declarator in node.declarators:
                    variable_symbols[declarator.name] = var_type
            elif isinstance(node, javalang.tree.MethodDeclaration):
                for param in node.parameters:
                    var_type = param.type.name
                    variable_symbols[param.name] = var_type
        return variable_symbols

    def _get_current_method_from_path(self, path) -> str:
        """
        通过AST路径直接获取当前函数节点所对应的类的信息，用于构建调用图
        """
        for node in reversed(path):
            if isinstance(node, javalang.tree.MethodDeclaration):
                class_node = self.find_parent_class(path)
                return f"{class_node.name}:{node.name}"
        return "unknown:unknown"

    def find_taint_paths(self) -> List[dict]:
        print("-" * 50)
        print(f"[+]正在审计源项目：{self.project_path}")
        # print(Fore.MAGENTA + f"[+]提取到的类函数字典：{self.class_methods}")
        results = []
        for rule in self.rules["sink_rules"]:
            for sink in rule["sinks"]:
                class_name, methods = sink.split(":")
                for method in methods.split("|"):
                    class_name = class_name.split('.')[-1]
                    sink_point = f"{class_name}:{method}"
                    # print(f"[+]正在审计sink点：{sink_point}")  # MCP环境看不到，且AI不需要
                    paths = self._trace_back(sink_point, self.rules["depth"])
                    if paths:
                        results.append({
                            "vul_type": rule["sink_name"],
                            "sink_desc": rule["sink_desc"],
                            "severity": rule["severity_level"],
                            "sink": sink_point,
                            "call_chains": self.process_call_stacks(self.project_path, paths)
                        })
        print("-" * 50)
        return results

    def find_taint_paths_lightweight(self) -> List[dict]:
        """
        轻量级漏洞查找（不立即提取代码）
        只返回调用链路径，代码提取延迟到需要时
        性能优化：避免在初次扫描时进行大量I/O操作
        """
        print("-" * 50)
        print(f"[+]正在审计源项目（轻量级模式）：{self.project_path}")

        results = []
        for rule in self.rules["sink_rules"]:
            for sink in rule["sinks"]:
                class_name, methods = sink.split(":")
                for method in methods.split("|"):
                    class_name = class_name.split('.')[-1]
                    sink_point = f"{class_name}:{method}"
                    # print(f"[+]正在审计sink点：{sink_point}")  # MCP环境看不到，且AI不需要

                    paths = self._trace_back(sink_point, self.rules["depth"])

                    if paths:
                        results.append({
                            "vul_type": rule["sink_name"],
                            "sink_desc": rule["sink_desc"],
                            "severity": rule["severity_level"],
                            "sink": sink_point,
                            "call_chains": paths,  # 🚀 只存储路径，不提取代码
                            "chain_count": len(paths)
                        })

        print("-" * 50)
        total_chains = sum(v['chain_count'] for v in results)
        print(Fore.LIGHTGREEN_EX + f"[+] 找到 {len(results)} 个潜在漏洞，共 {total_chains} 条调用链")
        return results

    @staticmethod
    def process_call_stacks(root_dir, call_stacks):
        results = []
        for stack in call_stacks:
            visited = set()
            chain = []
            code_list = []
            queue = []
            for item in stack:
                cls, mtd = item.split(':', 1)
                queue.append((cls, mtd))
            while queue:
                cls, mtd = queue.pop(0)
                key = f"{cls}:{mtd}"
                if key in visited:
                    continue
                visited.add(key)
                path, code = extract_method_definition(root_dir, cls, mtd)
                if not path or not code:
                    continue
                chain.append(f"{path}:{mtd}")
                code_list.append(code)
            results.append({"chain": chain, "code": code_list})
        return results

    def _trace_back(self, sink: str, max_depth: int) -> List[List[str]]:
        """
        根据最大追溯深度的限制，回溯污点传播的路径，支持多级调用链展开
        """
        paths = []

        # 🚀 状态去重，避免重复访问相同的(节点, 深度)组合
        visited_states = set()

        # 🚀 队列元素: (路径, 深度, 路径节点集合)
        queue = deque([([sink], 0, {sink})])

        while queue:
            current_path, current_depth, path_nodes = queue.popleft()
            if current_depth >= max_depth:
                continue
            current_sink = current_path[0]
            # 🚀 使用反向索引，O(1)查找，替代O(E)的遍历
            caller_methods = self.reverse_call_graph.get(current_sink, [])
            if not caller_methods:
                continue
            # else:
            #     print(Fore.MAGENTA + f"[*]需要追溯调用点: {caller_methods}")
            for caller in caller_methods:
                # 🚀 剪枝 1 - 避免循环引用
                if caller in path_nodes:
                    # print(Fore.RED + f"[!] 检测到循环引用，跳过: {caller}")
                    continue

                # 🚀 剪枝 2 - 状态去重
                state_key = (caller, current_depth + 1)
                if state_key in visited_states:
                    continue
                visited_states.add(state_key)

                if not self.is_has_parameters(caller.split(':')[0], caller.split(':')[1]):
                    # print(Fore.RED + f"[!]发现无参的函数：{caller}，此链路忽略不计！")
                    continue

                new_path = [caller] + current_path
                new_path_nodes = path_nodes | {caller}  # 🚀 更新节点集合

                # print(Fore.YELLOW + f"[→]正在追溯的路径: [{' → '.join(new_path)}]")
                if self.is_entry_point(caller):
                    paths.append(new_path)
                    print(Fore.LIGHTGREEN_EX + f"[✓]发现完整调用链: {new_path}")  # 保留重要成果
                else:
                    queue.append((new_path, current_depth + 1, new_path_nodes))  # 🚀 传递节点集合
        return paths

    def is_has_parameters(self, class_name: str, method_name: str) -> bool:
        """
        判断给定类中的给定方法是否包含参数
        """
        try:
            class_info = self.class_methods.get(class_name, {})
            method_info = class_info.get("methods", {}).get(method_name, {})
            return method_info.get("requires_params", True)
        except KeyError:
            return True

    def is_entry_point(self, method: str) -> bool:
        """
        判断当前追溯到的函数是否已经是程序的外部入口点（MAPPING_ANNOTATIONS相关函数）
        """
        class_name, method_name = method.split(":")
        is_method_entry_point = False
        class_info = self.class_methods.get(class_name, {})
        method_info = class_info.get("methods", {}).get(method_name, {})
        if method_info:
            is_method_entry_point = method_info.get("has_mapping_annotation", False)
        return is_method_entry_point

    @staticmethod
    def find_parent_class(path) -> javalang.tree.ClassDeclaration:
        """
        从AST路径中查找最近的类声明或接口声明
        """
        for node in reversed(path):
            if isinstance(node, (javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration)):
                return node
        raise ValueError("No class declaration found")


def run():
    start_time = time.time()
    print(Fore.LIGHTCYAN_EX + """
      ███████╗███████╗ ██████╗  
     ██╔════╝██╔════╝██╔════╝ 
     ███████╗█████╗  ██║     
     ╚════██║██╔══╝  ██║      
     ███████║███████╗╚██████╗ 
     ╚══════╝╚══════╝ ╚═════╝ 
    """ + Fore.LIGHTGREEN_EX + """
    Java源代码漏洞审计工具_Tr0e
    """ + Fore.RESET)
    parser = argparse.ArgumentParser(description="JavaSinkTracer")
    parser.add_argument('-p', "--projectPath", type=str, default='D:/Code/Github/java-sec-code', help=f"待扫描的项目本地路径根目录，默认值：D:/Code/Github/java-sec-code")
    parser.add_argument('-o', "--outputPath", type=str, default='Result', help=f"指定扫描报告输出的本地路径根目录，默认值：当前项目根路径下的 Result 子文件夹")
    args = parser.parse_args()
    java_project_path = args.projectPath.replace('\\', '/')
    java_project_name = java_project_path.rstrip('/').split('/')[-1]
    print(f'[+]待扫描的project_name: {java_project_name}, project_path: {java_project_path}')
    analyzer = JavaSinkTracer(java_project_path, "Rules/rules.json")
    analyzer.build_ast()
    vulnerabilities = analyzer.find_taint_paths()
    print(Fore.LIGHTGREEN_EX + f"[+]代码审计结果汇总：\n{json.dumps(vulnerabilities, indent=2, ensure_ascii=False)}")
    target_dir = os.path.join("Result", java_project_name)
    os.makedirs(target_dir, exist_ok=True)
    sink_save_file = os.path.join(target_dir, f"sink_chains.json")
    with open(sink_save_file, "w", encoding="utf-8") as file:
        json.dump(vulnerabilities, file, indent=4, ensure_ascii=False)
    generate_markdown_report(java_project_name, java_project_path, sink_save_file, args.outputPath)
    print(f"[+]主进程任务完成，耗时：{round(time.time() - start_time, 2)}秒")


if __name__ == "__main__":
    run()
