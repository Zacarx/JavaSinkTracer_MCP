"""
@File：AutoVulReport.py
@Time：2025/6/21 13:40
@Auth：Tr0e
@Github：https://github.com/Tr0e
@Description：漏洞报告自动生成（Markdown、HTML两种格式）
"""
import datetime
import json
import os
from pathlib import Path

import markdown
from bs4 import BeautifulSoup
from colorama import Fore
from markdown.extensions.toc import TocExtension


def generate_markdown_report(project_name, local_project_path, json_file_path, output_file_path):
    """
    从本地存储了污点链路扫描结果的 JSON 文件中读取漏洞数据，并生成一个 Markdown 格式的报告
    """
    with open(json_file_path, 'r', encoding='utf-8') as f:
        sink_json_data = json.load(f)
    total_chains = sum(len(item.get("call_chains", [])) for item in sink_json_data)
    num = 1
    target_dir = os.path.join(Path(output_file_path), project_name)
    os.makedirs(target_dir, exist_ok=True)
    markdown_file_path = os.path.join(target_dir, f"VulReport_{project_name}.md")
    with open(markdown_file_path, 'w', encoding='utf-8') as md:
        md.write(f"# JavaSinkTracer扫描报告\n")
        md.write(f"- 报告时间：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        md.write(f"- 项目名称：**{project_name}**\n")
        md.write(f"- 源码路径：{local_project_path}\n")
        md.write(f"- 污点数量：共存在 **{total_chains}** 条污点链路\n\n")
        for sink_item in sink_json_data:
            md.write(f"# {sink_item.get('vul_type', '未知漏洞类型')}漏洞({len(sink_item.get('call_chains', []))}个)\n\n")
            md.write(f"本章节所示的漏洞分析结果，包含了目标源代码项目所有涉及Sink函数 **'{sink_item.get('sink', '')}'** 的调用链。\n\n")
            call_chains = sink_item.get("call_chains", [])
            for i, chain_item in enumerate(call_chains, 1):
                md.write(f"## 污点链路{num}\n\n")
                md.write("**1）漏洞基础信息**\n\n")
                md.write(f"- 漏洞简述: {sink_item.get('sink_desc', '无')}\n\n")
                md.write(f"- 严重等级: **{sink_item.get('severity', '无')}**\n\n")
                md.write(f"- Sink函数: **{sink_item.get('sink', '无')}**\n\n")
                md.write("**2）调用链路信息**\n\n")
                for chain in chain_item.get("chain", []):
                    md.write(f"- {chain}\n")
                md.write("\n")
                md.write("**3）链路完整代码**\n\n")
                md.write("```java\n")
                for chain, code_line in zip(chain_item.get("chain", []), chain_item.get("code", [])):
                    md.write(f"// {chain}\n")
                    md.write(f"{code_line}\n\n")
                md.write("```\n\n")
                num += 1
            md.write("\n")
    md_to_html_with_toc(markdown_file_path)
    print(Fore.LIGHTMAGENTA_EX + f"[+]审计结果已保存到：{markdown_file_path}")

def md_to_html_with_toc(md_path):
    """
    将Markdown文件转换为带目录导航的HTML文件，导航目录中一级、二级标题均支持折叠，其中一级题默认展开，其它标题默认折叠
    """
    with open(md_path, 'r', encoding='utf-8') as f:
        md_content = f.read()
    md = markdown.Markdown(
        extensions=[
            TocExtension(
                toc_depth="1-6",
                anchorlink=False,
                permalink=False
            ),
            'fenced_code',
            'codehilite',  # 代码高亮扩展
            'tables',
            'nl2br',
            'sane_lists'
        ],
        extension_configs={
            'codehilite': {
                'use_pygments': True,  # 启用Pygments
                'css_class': 'codehilite',
                'linenums': False
            }
        }
    )
    md_with_toc = f"[TOC]\n\n{md_content}"
    html_content = md.convert(md_with_toc)
    soup = BeautifulSoup(html_content, 'html.parser')
    toc_element = soup.find(True, class_='toc')
    if toc_element:
        for ul in toc_element.find_all('ul'):
            if not ul.find('li'):
                ul.decompose()
        for br in toc_element.find_all('br'):
            br.decompose()
    toc_html = str(toc_element) if toc_element else ""
    if toc_element:
        toc_element.decompose()
    full_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{os.path.basename(md_path)}</title>
    <style>
        :root {{
            --primary-text: #e1f0ff;
            --secondary-text: #a3c6e9;
            --heading-color: #5eabff;
            --code-bg: #1a2334;
            --code-border: #2b4369;
            --panel-bg: rgba(15, 30, 50, 0.85);
        }}
        body {{
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', 'SF Pro Display', -apple-system, system-ui, sans-serif;
            line-height: 1.2;
            color: var(--primary-text);
            background-color: #0c1e30;
            background-image: linear-gradient(135deg, #0c1e30 0%, #0a1625 100%);
            position: relative;
            min-height: 100vh;
            padding-bottom: 30px;
        }}
        /* 正文增强可读性 */
        .content {{
            color: var(--primary-text);
            font-size: 1.08em;
            line-height: 1.2; 
            font-family: "SimSun", "宋体", "Songti SC", "Segoe UI", -apple-system, sans-serif;
        }}
        .content p {{
            line-height: 1.0;
            margin-bottom: 0.8em;
        }}
        /* 目录标题及导航样式 */
        .toc-title {{
            color: var(--heading-color);
            font-weight: 600;
            font-size: 1.5em;
            margin-bottom: 15px;
            padding: 12px 20px;
            border-radius: 8px;
            background: rgba(15, 30, 50, 0.7);
            letter-spacing: 1px;
            position: sticky;
            top: 0;
            backdrop-filter: blur(3px);
            border: 1px solid rgba(52, 152, 219, 0.4);
        }}
        .toc-container a {{
            color: var(--secondary-text);
            text-decoration: none;
            transition: all 0.3s ease;
            padding: 2px 4px;
            border-radius: 3px;
        }}
        .toc-container a:hover {{
            color: #fff;
            background-color: rgba(52, 152, 219, 0.3);
        }}
        .toc-container {{
            position: fixed;
            left: 0;
            top: 0;
            width: 280px;
            height: 100vh;
            overflow: auto;
            padding: 20px 20px 30px 20px;
            background: var(--panel-bg);
            backdrop-filter: blur(5px);
            -webkit-backdrop-filter: blur(5px);
            border-right: 1px solid rgba(52, 152, 219, 0.2);
        }}
        /* 滚动条样式 */
        .toc-container::-webkit-scrollbar {{
            width: 8px;
        }}
        .toc-container::-webkit-scrollbar-track {{
            background: rgba(0, 0, 0, 0.2);
            border-radius: 4px;
        }}
        .toc-container::-webkit-scrollbar-thumb {{
            background: #2b82d9;
            border-radius: 4px;
        }}
        .content {{
            margin-left: 300px;
            padding: 40px 80px;
            max-width: 1500px;
        }}
        /* 优化标题间距 */
        h1, h2, h3, h4, h5, h6 {{
            position: relative;
            padding-left: 1.2rem;
            font-weight: 600;
            letter-spacing: 0.5px;
            color: var(--heading-color);
            margin-top: 1.2em;
            margin-bottom: 0.8em;
        }}
        h1::before, h2::before, h3::before, 
        h4::before, h5::before, h6::before {{
            content: "";
            position: absolute;
            left: 0;
            height: 60%;
            width: 4px;
            background: var(--heading-color);
            top: 20%;
            border-radius: 2px;
        }}
        h1 {{ 
            font-size: 1.35em; 
            border-bottom: 1px solid rgba(94, 171, 255, 0.3);
            padding-bottom: 0.3em;
        }}
        h2 {{ font-size: 1.2em; }}
        h3 {{ font-size: 1.1em; }}
        h4 {{ font-size: 1.0em; }}
        h5 {{ font-size: 0.9em; }}
        h6 {{ font-size: 0.8em; }}

        /* 代码高亮样式 (Pygments) - 优化可读性 */
        .codehilite {{
            background: var(--code-bg);
            padding: 0.6em;
            border-radius: 6px;
            border: 1px solid var(--code-border);
            overflow: auto;
            margin: 2em 0;
            font-size: 1.05em;
            box-shadow: 0 0 10px rgba(43, 66, 105, 0.5);
            line-height: 1.5;
        }}
        .codehilite:hover {{
            box-shadow: 0 0 15px rgba(43, 101, 208, 0.7);
        }}
        /* 增强代码可读性 */
        .codehilite .c  {{ color: #789aad; font-style: italic; }} /* Comment */
        .codehilite .k  {{ color: #ff8c42; font-weight: bold; }} /* Keyword */
        .codehilite .o  {{ color: #ffd83d; }}                     /* Operator */
        .codehilite .ch {{ color: #789aad; }}                     /* Comment.Hashbang */
        .codehilite .cm {{ color: #789aad; }}                     /* Comment.Multiline */
        .codehilite .cp {{ color: #87d7d7; }}                     /* Comment.Preproc */
        .codehilite .cpf{{ color: #789aad; }}                     /* Comment.PreprocFile */
        .codehilite .c1 {{ color: #789aad; }}                     /* Comment.Single */
        .codehilite .cs {{ color: #87d7d7; }}                     /* Comment.Special */
        .codehilite .gd {{ color: #ff5e5e; }}                     /* Generic.Deleted */
        .codehilite .ge {{ font-style: italic; }}                  /* Generic.Emph */
        .codehilite .gr {{ color: #ff5e5e; }}                     /* Generic.Error */
        .codehilite .gh {{ color: #87d极客d7; }}                     /* Generic.Heading */
        .codehilite .gi {{ color: #7fff7f; }}                     /* Generic.Inserted */
        .codehilite .go {{ color: #87d7d7; }}                     /* Generic.Output */
        .codehilite .gp {{ color: #5fafd7; }}                     /* Generic.Prompt */
        .codehilite .gs {{ font-weight: bold; }}                   /* Generic.Strong */
        .codehilite .gu {{ color: #87d7d7; }}                     /* Generic.Subheading */
        .codehilite .gt {{ color: #ff5e5e; }}                     /* Generic.Traceback */
        .codehilite .kc {{ color: #ff8c42; font-weight: bold; }}  /* Keyword.Constant */
        .codehilite .kd {{ color极客: #ff8c42; font-weight: bold; }}  /* Keyword.Declaration */
        .codehilite .kn {{ color: #ff8c42; font-weight: bold; }}  /* Keyword.Namespace */
        .codehilite .kp {{ color: #ff8c42; font-weight: bold; }}  /* Keyword.Pseudo */
        .codehilite .kr {{ color: #ff8c42; font-weight: bold; }}  /* Keyword.Reserved */
        .codehilite .kt {{ color: #4dccff; font-weight: bold; }}  /* Keyword.Type */
        .codehilite .m  {{ color: #ffaf5f; }}                     /* Literal.Number */
        .codehilite .s  {{ color: #9effe6; }}                     /* Literal.String */
        .codehilite .na {{ color: #7fff7f; }}                     /* Name.Attribute */
        .codehilite .nb {{ color: #4dccff; }}                     /* Name.Builtin */
        .codehilite .nc {{ color: #4dccff; font-weight: bold; }}  /* Name.Class */
        .codehilite .no {{ color: #7fff7f; }}                     /* Name.Constant */
        .codehilite .ni {{ color: #ff80ff; }}                     /* Name.Entity */
        .codehilite .ne {{ color: #ff7f7f; font-weight: bold; }}  /* Name.Exception */
        .codehilite .nf {{ color: #4dccff; font-weight: bold; }}  /* Name.Function */
        .codehilite .nn {{ color: #4dccff; }}                     /* Name.Namespace */
        .codehilite .nt {{ color: #ff8c42; }}                     /* Name.Tag */
        .codehilite .nv {{ color: #4dccff; }}                     /* Name.Variable */
        .codehilite .ow {{ color: #ffd83d; font-weight: bold; }}  /* Operator.Word */
        .codehilite .w  {{ color: #bbbbbb; }}                     /* Text.Whitespace */
        .codehilite .mb {{ color: #ffaf5f; }}                     /* Literal.Number.Bin */
        .codehilite .mf {{ color: #ffaf5f; }}                     /* Literal.Number.Float */
        .codehilite .mh {{ color: #ffaf5f; }}                     /* Literal.Number.Hex */
        .codehilite .mi {{ color: #ffaf5f; }}                     /* Literal.Number.Integer */
        .codehilite .mo {{ color: #ffaf5f; }}                     /* Literal.Number.Oct */
        .codehilite .sa {{ color: #9effe6; }}                     /* Literal.String.Affix */
        .codehilite .sb {{ color: #9effe6; }}                     /* Literal.String.Backtick */
        .codehilite .sc {{ color: #9effe6; }}                     /* Literal.String.Char */
        .codehilite .dl {{ color: #9effe6; }}                     /* Literal.String.Delimiter */
        .codehilite .sd {{ color: #9effe6; }}                     /* Literal.String.Doc */
        .codehilite .s2 {{ color: #9effe6; }}                     /* Literal.String.Double */
        .codehilite .se {{ color: #ffaf5f; }}                     /* Literal.String.Escape */
        .codehilite .sh {{ color: #9effe6; }}                     /* Literal.String.Heredoc */
        .codehilite .si {{ color: #9effe6; }}                     /* Literal.String.Interpol */
        .codehilite .sx {{ color: #9effe6; }}                     /* Literal.String.Other */
        .codehilite .sr {{ color: #7fff7f; }}                     /* Literal.String.Regex */
        .codehilite .s1 {{ color: #9effe6; }}                     /* Literal.String.Single */
        .codehilite .ss {{ color: #ff80ff; }}                     /* Literal.String.Symbol */
        .codehilite .bp {{ color: #4dccff; }}                     /* Name.Builtin.Pseudo */
        .codehilite .fm {{ color: #4dccff; font-weight: bold; }}   /* Name.Function.Magic */
        .codehilite .vc {{ color: #4dccff; }}                     /* Name.Variable.Class */
        .codehilite .vg {{ color: #4dccff; }}                     /* Name.Variable.Global */
        .codehilite .vi {{ color: #4dccff; }}                     /* Name.Variable.Instance */
        .codehilite .vm {{ color: #4dccff; }}                     /* Name.Variable.Magic */
        .codehilite .il {{ color: #ffaf5f; }}                     /* Literal.Number.Integer.Long */

        /* 新增：代码标识符高亮样式（适配暗黑主题） */
        .identifier-highlight {{
            background-color: rgba(0, 217, 255, 0.3); /* 蓝绿色背景，半透明 */
            border-radius: 3px;
            box-shadow: 0 0 0 1px rgba(0, 255, 213, 0.5); /* 亮蓝色发光 */
            position: relative;
        }}
        .identifier-highlight::after {{
            content: '';
            position: absolute;
            bottom: -1px;
            left: 0;
            right: 0;
            height: 2px;
            background: rgba(0, 255, 213, 0.7);
        }}

        /* 目录间距修复 */
        .toc ul, .toc li {{
            margin: 0;
            padding: 0;
            line-height: 1.0;
        }}
        .toc li {{
            margin-bottom: 8px;
            padding: 4px 0;
        }}
        .toc ul ul li {{
            margin-bottom: 2px;  /* 二级标题的上下间距 */
            padding: 1px 0;      /* 内边距 */
        }}
        .toc ul ul {{
            margin-left: 1.2em;  /* 二级标题保持缩进 */
        }}
        .toc ul ul ul {{
            margin-left: 2.0em;  /* 三级标题进一步缩进，体现层次感 */
        }}
        /* 折叠功能样式 */
        .collapse-toggle {{
            cursor: pointer;
            user-select: none;
            margin-right: 7px;
            font-size: 0.85em;
            color: var(--heading-color);
            background-color: rgba(255, 255, 255, 0.12);
            padding: 0px 5px;
            border-radius: 4px;
            transition: all 0.2s;
        }}
        .collapse-toggle:hover {{
            background-color: rgba(94, 171, 255, 0.6);
            color: white;
        }}
        .collapsed > ul {{
            display: none;
        }}

        /* 新增块引用样式 */
        blockquote {{
            border-left: 4px solid var(--heading-color);
            background: rgba(26, 35, 52, 0.4);
            padding-right: 15px;
            padding-left: 15px;
            margin: 25px 极客0;
            color: var(--secondary-text);
            border-radius: 0 6px 6px 0;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        }}
        blockquote p {{
            margin: 8px 0;
        }}
        /* 勾选框样式 */
        .vul-checkbox {{
            margin-right: 4px;
            vertical-align: middle;
            appearance: none;
            -webkit-appearance: none;
            width: 16px;
            height: 16px;
            border: 1.5px solid var(--heading-color);
            border-radius: 4px;
            position: relative;
            cursor: pointer;
            background-color: transparent;
        }}
        .vul-checkbox:checked::before {{
            content: "✓";
            position: absolute;
            top: -1px;
            left: 3px;
            color: var(--heading-color);
            font-size: 14px;
            font-weight: bold;
        }}
        .vul-checkbox:hover {{
            background-color: rgba(94, 171, 255, 0.1);
        }}

        /* 表格样式 */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 25px 0;
            background: rgba(26, 35, 52, 0.4);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.15);
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid rgba(94, 171, 255, 0.25);
            color: var(--primary-text);
        }}
        th {{
            background-color: rgba(20, 40, 70, 0.5);
            color: var(--heading-color);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.85em;
        }}
        tr:hover {{
            background-color: rgba(30, 50, 80, 0.4);
        }}
        td {{
            border-right: 1px solid rgba(94, 171, 255, 0.15);
        }}
        td:last-child {{
            border-right: none;
        }}

        /* 链接样式 */
        a {{
            color: var(--heading-color);
            text-decoration: none;
            transition: all 0.25s ease;
            position: relative;
        }}
        a:hover {{
            color: #ff8c42;
            text-decoration: underline;
            text-decoration-color: rgba(255, 140, 66, 0.5);
        }}
    </style>
</head>
<body>
    <nav class="toc-container">
        <div class="toc-title">🚀 漏洞目录_Tr0e</div>
        {toc_html}
    </nav>
    <div class="content">
        {soup.prettify()}
    </div>
    <script>
        // 遍历目录中所有 li
        document.querySelectorAll('.toc li').forEach(function(li) {{
            // 创建并插入勾选框（仅限二级标题）
            const parentUl = li.parentNode;
            const grandparent = parentUl ? parentUl.parentNode : null;
            if (grandparent && grandparent.tagName === 'LI') {{
                const topUl = grandparent.parentNode;
                // 确认是二级标题（顶级ul>li>ul>li）
                if (topUl && topUl.parentNode.classList.contains('toc')) {{
                    const checkbox = document.createElement('input');
                    checkbox.type = 'checkbox';
                    checkbox.className = 'vul-checkbox'; // 添加样式类
                    const link = li.querySelector('a');
                    const anchorId = link ? link.href.split('#')[1] : null;
                    if (anchorId) {{
                        // 从本地存储中读取该checkbox的保存状态
                        const savedState = localStorage.getItem(`checkbox_${{anchorId}}`);
                        // 如果之前保存为选中状态，则恢复选中状态
                        if (savedState === 'true') {{
                            checkbox.checked = true;
                        }}
                        // 添加change事件监听器，保存checkbox状态到本地存储
                        checkbox.addEventListener('change', function() {{
                            localStorage.setItem(`checkbox_${{anchorId}}`, this.checked);
                        }});
                    }}
                    // 将checkbox插入到li的最前面
                    li.insertBefore(checkbox, li.firstChild);
                }}
            }}
            // 添加折叠按钮（针对所有有子列表的标题）
            const subList = li.querySelector('ul');
            if (subList) {{
                // 计算层级：统计当前 li 所在的 ul 层数
                let level = 0;
                let current = li.parentNode;
                while (current && current.tagName && current.tagName.toLowerCase() === 'ul') {{
                    level++;
                    current = current.parentNode;
                }}
                // 创建折叠按钮
                const toggle = document.createElement('span');
                toggle.className = 'collapse-toggle';
                // 一级标题默认展开，其它折叠
                if(level === 1) {{
                    li.classList.add('collapsed');
                    toggle.textContent = '▶';
                }} else {{
                    toggle.textContent = '▼';
                }}
                // 插入折叠按钮到勾选框后面（如果存在）
                const firstChild = li.firstChild;
                if (firstChild && firstChild.className === 'vul-checkbox') {{
                    li.insertBefore(toggle, firstChild.nextSibling);
                }} else {{
                    li.insertBefore(toggle, li.firstChild);
                }}
                // 添加折叠行为
                toggle.onclick = function() {{
                    if(li.classList.contains('collapsed')) {{
                        li.classList.remove('collapsed');
                        toggle.textContent = '▼';
                    }} else {{
                        li.classList.add('collapsed');
                        toggle.textContent = '▶';
                    }}
                }};
            }}
        }});

        // 全局代码标识符高亮功能（跨代码块，所有相同字符串）
        (function() {{
            let currentHighlightedText = null;
            function clearHighlights() {{
                document.querySelectorAll('.identifier-highlight').forEach(el => {{
                    el.classList.remove('identifier-highlight');
                }});
                currentHighlightedText = null;
            }}
            function highlightIdentifiers(target) {{
                const text = target.textContent.trim();
                if (currentHighlightedText === text) {{
                    clearHighlights();
                    return;
                }}
                clearHighlights();
                currentHighlightedText = text;
                document.querySelectorAll('.codehilite').forEach(codeBlock => {{
                    const tokens = codeBlock.querySelectorAll('span');
                    tokens.forEach(token => {{
                        if (token.textContent.trim() === text) {{
                            token.classList.add('identifier-highlight');
                        }}
                    }});
                }});
            }}
            document.querySelectorAll('.codehilite').forEach(codeBlock => {{
                codeBlock.addEventListener('click', function(event) {{
                    const target = event.target;
                    if (target.tagName === 'SPAN') {{
                        highlightIdentifiers(target);
                        event.stopPropagation(); 
                    }} else {{
                        clearHighlights();
                    }}
                }});
            }});
            document.addEventListener('click', function(event) {{
                if (!event.target.closest('.codehilite')) {{
                    clearHighlights();
                }}
            }});
        }})();
    </script>
</body>
</html>"""
    html_path = os.path.splitext(md_path)[0] + '.html'
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(full_html)
    print(f"[+]HTML文件已自动保存到：{html_path}")
    return html_path


if __name__ == "__main__":
    generate_markdown_report("java-sec-code", r"D:\Code\Github\java-sec-code", "Result/java-sec-code/sink_chains.json")