import csv
import json
import logging
import os
import subprocess
from datetime import datetime
from typing import Dict, List, Union, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import re
import time
# --- 导入 Qwen-Agent 相关模块 ---
from qwen_agent.agents import Assistant
from qwen_agent.llm import get_chat_model
from qwen_agent.llm.schema import Message
from qwen_agent.tools.base import BaseTool
from qwen_agent.gui import WebUI

# --- 1. 全局配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
WORKSPACE = os.path.join(os.getcwd(), 'workspace/doc')
os.makedirs(os.path.join(WORKSPACE, 'reports'), exist_ok=True)
os.makedirs(os.path.join(WORKSPACE, 'debug'), exist_ok=True)


# --- 2. 核心工具类 (与之前相同) ---
# TrivyScanner, JsonToCsvConverter, CVEClassifier, CVEReportGenerator 这四个类的代码
# 和我们之前版本完全一样，这里为了简洁先折叠起来，您直接使用上一版本即可。
# (在下面的完整代码块中我会全部展开)

class TrivyScanner(BaseTool):
    name = "trivy_scanner"
    description = "Runs a Trivy vulnerability scan on a Docker image and saves the output as a JSON file."
    parameters = [{'name': 'image_name', 'type': 'string', 'description': 'The full name of the Docker image to scan (e.g., \'python:3.9-slim\')', 'required': True}]
    def call(self, params: Union[str, dict], **kwargs) -> str:
        try:
            params = self._verify_json_format_args(params)
            image_name = params['image_name']
        except Exception as e: return f'{{"error": "Parameter error: {e}"}}'
        sanitized_name = image_name.replace(':', '_').replace('/', '_')
        output_path = os.path.join(WORKSPACE, f'{sanitized_name}_cves.json')
        command = ['trivy', 'image', '--format', 'json', '--output', output_path, image_name]
        logging.info(f"Running Trivy scan for {image_name}...")
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
            success_message = f"Successfully scanned image '{image_name}'. Results saved to: {output_path}"
            logging.info(success_message)
            return json.dumps({"output_path": output_path})
        except FileNotFoundError: return '{{"error": "Trivy command not found. Please ensure Trivy is installed."}}'
        except subprocess.CalledProcessError as e: return f'{{"error": "Trivy scan failed for \'{image_name}\'. Stderr: {e.stderr}"}}'

class JsonToCsvConverter(BaseTool):
    name = "json_to_csv_converter"
    description = "Converts a Trivy JSON report file to a CSV file."
    parameters = [{'name': 'json_file_path', 'type': 'string', 'description': 'The path to the input JSON file from a Trivy scan.', 'required': True}]
    def call(self, params: Union[str, dict], **kwargs) -> str:
        try:
            params = self._verify_json_format_args(params)
            json_file_path = params['json_file_path']
        except Exception as e: return f'{{"error": "Parameter error: {e}"}}'
        if not os.path.exists(json_file_path): return f'{{"error": "Input file not found at {json_file_path}"}}'
        csv_file_path = json_file_path.replace('.json', '.csv')
        headers = ["VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Title", "Description", "PrimaryURL"]
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f_json, open(csv_file_path, 'w', encoding='utf-8', newline='') as f_csv:
                writer = csv.DictWriter(f_csv, fieldnames=headers)
                writer.writeheader()
                data = json.load(f_json)
                if 'Results' not in data: return json.dumps({"output_path": csv_file_path, "status": "empty"})
                for result in data.get('Results', []):
                    for vuln in result.get('Vulnerabilities', []): writer.writerow({h: str(vuln.get(h, "")).replace('\n', ' ') for h in headers})
            logging.info(f"Successfully converted {json_file_path} to {csv_file_path}")
            return json.dumps({"output_path": csv_file_path})
        except Exception as e: return f'{{"error": "Error during JSON to CSV conversion: {e}"}}'

class CVEClassifier(BaseTool):
    name = "cve_classifier"
    description = "Reads two CVE CSV reports (target and base), classifies the vulnerabilities."
    parameters = [{'name': 'target_csv_path', 'type': 'string', 'required': True}, {'name': 'base_csv_path', 'type': 'string', 'required': True}]
    def call(self, params: Union[str, dict], **kwargs) -> Dict:
        # ... (内部逻辑和之前版本完全一样) ...
        try:
            params = self._verify_json_format_args(params)
            target_csv_path, base_csv_path = params['target_csv_path'], params['base_csv_path']
        except Exception as e: return {"error": f"Parameter error: {e}"}
        def read_cves_from_csv(file_path: str) -> Dict[str, dict]:
            cves = {}
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if cve_id := row.get("VulnerabilityID"): cves[cve_id] = row
            except FileNotFoundError: return {}
            return cves
        target_cves, base_cves = read_cves_from_csv(target_csv_path), read_cves_from_csv(base_csv_path)
        base_cve_ids = set(base_cves.keys())
        target_cve_ids = set(target_cves.keys())
        type1_cves, type2_cves, type3_cves = [], [], []
        for cve_id, cve_data in target_cves.items():
            if not cve_data.get("FixedVersion"): type1_cves.append(cve_data)
            elif cve_id in base_cve_ids: type2_cves.append(cve_data)
            else: type3_cves.append(cve_data)

        summary = (
            f"Successfully classified CVEs. "
            f"base_cve_num{len(base_cve_ids)}"
            f"target_cve_num{len(target_cve_ids)}"
            f"Found {len(type1_cves)} Type-1, "
            f"{len(type2_cves)} Type-2, and "
            f"{len(type3_cves)} Type-3 vulnerabilities for analysis."
        )
        logging.info(summary)
        
        return {"type1_cves": type1_cves, "type2_cves": type2_cves, "type3_cves_to_analyze": type3_cves}

class CVEReportGenerator(BaseTool):
    name = "cve_report_generator"
    description = "Generates trivyignore YAML files and a suggestion report from classified CVE lists."
    parameters = [{'name': 'classified_cves', 'type': 'dict', 'required': True}]
    def call(self, params: Union[str, dict], **kwargs) -> str:
        # ... (内部逻辑和之前版本完全一样) ...
        """为每一类 CVE 生成独立的 trivyignore 文件和最终的建议报告"""
        try:
            cves_data = self._verify_json_format_args(params).get('classified_cves', {})
            # ... (省略了写入文件的详细代码, 和之前一样) ...
            def _write_ignore_file(file_path: Path, ignore_list: List[Dict], header: str):
                if not ignore_list: return 0
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"# {header}\n# Auto-generated by Qwen-Agent\n")
                    f.write("vulnerabilities:\n")
                    for entry in ignore_list:
                        f.write(f"- id: {entry['id']}\n")
                        if entry.get('url'): f.write(f"  url: {entry['url']}\n")
                        f.write(f"  statement: {entry['reason']}\n")
                return len(ignore_list)
            
            type1_ignores = [{'id': c.get('VulnerabilityID', ''), 'url':c.get('PrimaryURL',''), 'reason': "There is currently no recommended version available to fix this vulnerability. We will continue to monitor for updates and apply a fix once it is released."} for c in cves_data.get('type1_cves', [])]
            count1 = _write_ignore_file(Path(WORKSPACE)/'trivyignore-type1.yaml', type1_ignores, "There is currently no recommended version available to fix this vulnerability. We will continue to monitor for updates and apply a fix once it is released.")

            type2_ignores = [{'id': c.get('VulnerabilityID', ''), 'url':c.get('PrimaryURL',''), 'reason': "The affected package is not used directly by our application. It comes from the underlying base image. We will continue to monitor and adopt a newer base image if one becomes available that resolves this issue."} for c in cves_data.get('type2_cves', [])]
            count2 = _write_ignore_file(Path(WORKSPACE)/'trivyignore-type2.yaml', type2_ignores, "The affected package is not used directly by our application. It comes from the underlying base image. We will continue to monitor and adopt a newer base image if one becomes available that resolves this issue.")

            type3_results = cves_data.get('type3_results', [])

            type3_ignores = [{'id': i.get('cve', {}).get('VulnerabilityID'), 'url': i.get('cve', {}).get('PrimaryURL'), 'reason': f"{i.get('analysis', {}).get('analysis', 'N/A')}"} for i in type3_results]
            count3 = _write_ignore_file(Path(WORKSPACE)/'trivyignore-type3.yaml', type3_ignores, "Analyzed by agent.")

            suggestions = [f"[{i.get('cve', {}).get('VulnerabilityID')}/{i.get('cve', {}).get('PkgName')}]: {i.get('analysis', {}).get('suggestion')}" for i in type3_results if i.get('analysis', {}).get('suggestion')]
            report_path = Path(WORKSPACE)/'reports'/'upgrade_patch_suggestions.txt'
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("Suggestions from Type-3 Analysis\n" + "="*50 + "\n")
                if suggestions: f.writelines(f"{s}\n\n" for s in suggestions)
                else: f.write("No actionable suggestions were generated.\n")
            
            return (f"报告生成完成。\n" f"- {count1}条Type-1规则 -> trivyignore-type1.yaml\n" f"- {count2}条Type-2规则 -> trivyignore-type2.yaml\n" f"- {count3}条Type-3规则 -> trivyignore-type3.yaml\n" f"- {len(suggestions)}条建议 -> {report_path}")
        except Exception as e:
            return f"报告生成失败: {e}"

# --- 3. 专家代理的指令和【修复后】的处理函数 ---

# TYPE3_ANALYST_PROMPT = """You are a senior cybersecurity analyst. Your ONLY task is to analyze the provided CVE JSON data.
# Respond with a SINGLE JSON object containing your analysis. Do not add any text before or after the JSON.
# The JSON object must have this exact structure:
# {"analysis": {"action": "ignore" | "suggest_patch", "reason": "...", "suggestion": "..." | null}}"""

def call_llm_for_analysis(cve_data: dict, llm) -> dict:

    prompt = f"""
    请严格按以下JSON格式分析CVE漏洞：
    {{
        "risk_level": "高/中/低",
        "analysis": "影响分析, 是否会影响到被分析镜像的使用等",
        "suggestion": "修复建议",
        "workaround": "临时解决方案(如无则留空)"
    }}

    待分析CVE详情：
    CVE ID: {cve_data.get('VulnerabilityID', 'N/A')}
    软件包: {cve_data.get('PkgName', 'N/A')} 
    版本: {cve_data.get('InstalledVersion', 'N/A')}
    修复版本: {cve_data.get('FixedVersion', '暂无')}
    严重程度: {cve_data.get('Severity', 'N/A')}
    描述: {cve_data.get('Description', '无描述信息')}
    """

    max_retries = 5
    retry_delay = 1.5  # 适当增加延迟
    
    for attempt in range(max_retries):
        try:
            # 1. 调用API
            response = llm.chat(
                messages=[{'role': 'user', 'content': prompt}],
                stream=False
            )
            
            # 2. 验证响应格式
            if not (isinstance(response, list) and 
                   len(response) > 0 and 
                   isinstance(response[0], dict) and
                   'content' in response[0]):
                raise ValueError("响应格式不符合预期")
            
            # 3. 提取JSON内容
            content = response[0]['content']
            json_str = re.search(r'```json\n(.*?)\n```', content, re.DOTALL)
            
            if not json_str:
                # 尝试直接解析整个content
                try:
                    analysis = json.loads(content)
                except json.JSONDecodeError:
                    raise ValueError("未找到有效的JSON内容")
            else:
                analysis = json.loads(json_str.group(1))
            
            # 4. 验证必需字段
            required_fields = ["risk_level", "analysis", "suggestion"]
            for field in required_fields:
                if field not in analysis:
                    raise ValueError(f"缺少必需字段: {field}")
            print(analysis)
            return {
                "cve": cve_data,
                "analysis": analysis
            }
            
        except Exception as e:
            logging.warning(f"尝试 {attempt + 1}/{max_retries} 失败 (CVE-{cve_data.get('VulnerabilityID')}): {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (attempt + 1))
                continue
            
            return {
                "cve": cve_data,
                "analysis": {
                    "error": f"分析失败: {str(e)}",
                    "raw_response": response[0]['content'][:500] if isinstance(response, list) and len(response) > 0 else str(response)[:500]
                }
            }

# --- 4. [新架构] 专为WebUI设计的 CVE工作流工具 ---

class CVEWorkflowTool(BaseTool):
    name = "cve_workflow_tool"
    description = "为指定的Docker镜像启动一个完整的CVE分析工作流，包括扫描、分类、AI分析和报告生成。"
    parameters = [
        {'name': 'target_image', 'type': 'string', 'description': '需要分析的目标镜像, e.g., \'nginx:1.14.2-alpine\'', 'required': True},
        {'name': 'base_image', 'type': 'string', 'description': '用于对比的基础镜像, e.g., \'debian:stretch-slim\'', 'required': True}
    ]
    
    def __init__(self, llm):
        super().__init__()
        self.llm = llm
        self.scanner = TrivyScanner()
        self.converter = JsonToCsvConverter()
        self.classifier = CVEClassifier()
        self.reporter = CVEReportGenerator()
    
    def call(self, params: Union[str, dict], **kwargs) -> str:
        """
        修改后的call方法返回字符串而不是生成器，但通过kwargs['messages']传递实时更新
        """
        try:
            params = self._verify_json_format_args(params)
            target_image = params['target_image']
            base_image = params['base_image']
        except Exception as e:
            return f"❌ 参数错误: {e}"
        
        # 获取消息回调函数（用于实时更新）
        message_callback = kwargs.get('messages', None)
        
        def _send_update(msg: str):
            """辅助函数：发送更新消息"""
            if callable(message_callback):
                message_callback(msg)
        
        _send_update(f"🚀 **工作流启动**\n   - 目标镜像: `{target_image}`\n   - 基础镜像: `{base_image}`")
        
        try:
            # --- 步骤 1 & 2: 扫描和转换 ---
            _send_update("\n---\n**步骤 1/5: 扫描镜像中...** 🔍")
            target_scan_res = json.loads(self.scanner.call({'image_name': target_image}))
            if 'error' in target_scan_res: raise RuntimeError(target_scan_res['error'])
            base_scan_res = json.loads(self.scanner.call({'image_name': base_image}))
            if 'error' in base_scan_res: raise RuntimeError(base_scan_res['error'])
            
            _send_update(f"   - ✅ 扫描完成: `{target_scan_res['output_path']}`")
            _send_update("\n---\n**步骤 2/5: 转换报告为CSV...** 📄")
            target_csv_res = json.loads(self.converter.call({'json_file_path': target_scan_res['output_path']}))
            if 'error' in target_csv_res: raise RuntimeError(target_csv_res['error'])
            base_csv_res = json.loads(self.converter.call({'json_file_path': base_scan_res['output_path']}))
            if 'error' in base_csv_res: raise RuntimeError(base_csv_res['error'])
            _send_update(f"   - ✅ 转换完成: `{target_csv_res['output_path']}`")
            
            # --- 步骤 3: 分类 ---
            _send_update("\n---\n**步骤 3/5: 对比并分类CVE...** 🗂️")
            classification_result = self.classifier.call({
                'target_csv_path': target_csv_res['output_path'],
                'base_csv_path': base_csv_res['output_path']
            })
            if 'error' in classification_result: raise RuntimeError(classification_result['error'])
            
            type1_cves = classification_result.get('type1_cves', [])
            type2_cves = classification_result.get('type2_cves', [])
            type3_cves = classification_result.get('type3_cves_to_analyze', [])
            _send_update(f"   - ✅ 分类完成: 发现Type-1: {len(type1_cves)}, Type-2: {len(type2_cves)}, Type-3: {len(type3_cves)}")
            
            # --- 步骤 4: 并行AI分析 ---
            # 在 CVEWorkflowTool.call() 方法中修改并行处理部分：
            # 在CVEWorkflowTool中
            _send_update(f"\n---\n**步骤 4/5: 专业分析 {len(type3_cves)} 个关键漏洞...** 🔍")
            type3_analysis_results = []

            if type3_cves:
                # 精确控制请求速率
                max_concurrent = 2  # 进一步降低并发数
                request_interval = 2.0  # 请求间隔2秒
                
                with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
                    futures = []
                    for i, cve in enumerate(type3_cves):
                        futures.append(executor.submit(
                            call_llm_for_analysis, 
                            cve, 
                            self.llm
                        ))
                        
                        # 实时进度更新
                        _send_update(f"   - 已提交: {cve.get('VulnerabilityID')} ({i+1}/{len(type3_cves)})")
                        
                        if i < len(type3_cves) - 1:  # 最后一个不需要sleep
                            time.sleep(request_interval)
                    
                    # 处理结果
                    success_count = 0
                    for future in as_completed(futures):
                        result = future.result()
                        type3_analysis_results.append(result)
                        
                        if "error" not in result["analysis"]:
                            success_count += 1
                            status = "✅"
                        else:
                            status = f"⚠️({result['analysis']['error']})"
                        
                        cve_id = result['cve'].get('VulnerabilityID')
                        _send_update(f"   - 完成: {cve_id} {status}")
                
                # 最终统计
                _send_update(f"\n分析完成: {success_count}成功, {len(type3_cves)-success_count}失败")
            _send_update("   - ✅ 全部Type-3漏洞分析完成!")
            
            # --- 步骤 5: 生成报告 ---
            _send_update("\n---\n**步骤 5/5: 生成最终报告和忽略文件...** 📝")
            final_report_data = {
                "type1_cves": type1_cves,
                "type2_cves": type2_cves,
                "type3_results": type3_analysis_results
            }
            final_status = self.reporter.call({'classified_cves': final_report_data})
            
            return f"\n---\n✅ **工作流全部完成!**\n\n```text\n{final_status}\n```"
            
        except Exception as e:
            logging.error(f"工作流执行失败: {e}", exc_info=True)
            return f"\n❌ **工作流执行失败**: {e}"

# --- 5. 主程序入口 ---
def main():
    # --- LLM 配置 ---
    llm_config = {
        'model': 'Qwen/Qwen3-Coder-480B-A35B-Instruct',
        'model_server': 'https://api-inference.modelscope.cn/v1',
        'api_key': 'ms-df44f694-9197-4fff-beaf-677b6bdc5e1b' # 请替换为您的 ModelScope API Key
    }
    llm = get_chat_model(llm_config)

    # --- 创建主交互代理 ---
    # 这个代理很简单，它的任务就是理解用户意图，并调用我们的 CVEWorkflowTool
    system_prompt = """
    You are an intelligent cybersecurity assistant. Your mission is to automate the processing of CVE vulnerabilities in a Docker image.
    You must strictly follow these steps and call the tools in sequence:
    1.  **Scan Images**: Use the `trivy_scanner` tool to scan the user-provided target image and base image. This will produce two JSON files.
    2.  **Convert Reports**: Use the `json_to_csv_converter` tool for each of the two JSON files to convert them into CSV format.
    3.  **Classify CVEs**: Call the `cve_classifier` tool ONCE, passing the file paths of the two CSVs you just created. This tool will do the classification and return structured data containing lists of 'type1_cves', 'type2_cves', and 'type3_cves_to_analyze'.
    4.  **Analyze Type-3 CVEs**: The previous step gave you a list of Type-3 CVEs. Now, you must act as a security expert. For EACH AND EVERY CVE in the 'type3_cves_to_analyze' list, generate a JSON object with your analysis. The format for each analysis must be: `{"cve": {... a dict containing the original CVE data ...}, "analysis": {"action": "ignore" | "suggest_patch", "reason": "...determine whether the CVE is relevant to the image,if not, the image not impacted by this issue,if yes, give the reason and some details...", "suggestion": "..." | null}}`.
    5.  **Generate Final Report**: After analyzing all Type-3 CVEs, call the `cve_report_generator` tool exactly ONCE. You will construct its `classified_cves` parameter as follows:
        - The 'type1_cves' key should contain the list of Type-1 CVEs from step 3.
        - The 'type2_cves' key should contain the list of Type-2 CVEs from step 3.
        - The 'type3_results' key should contain the list of your analysis JSON objects from step 4.
    6.  **Conclude**: After the report is generated successfully, inform the user that the task is complete and state the location of the output files.
    """

    # 将llm实例传入我们的大工具
    cve_tool = CVEWorkflowTool(llm=llm)
    tool_list = [
        cve_tool,
        {
            'mcpServers': {  # You can specify the MCP configuration file
                'time': {
                    'command': 'uvx',
                    'args': ['mcp-server-time', '--local-timezone=Asia/Shanghai'],
                    'env':{
                        "http_proxy": "http://proxy.iil.intel.com:911",
                        "https_proxy": "http://proxy.iil.intel.com:911"
                    }
                },
                'fetch': {
                    'command': 'uvx',
                    'args': ['mcp-server-fetch'],
                    'env':{
                        "http_proxy": "http://proxy.iil.intel.com:911",
                        "https_proxy": "http://proxy.iil.intel.com:911"
                    }
                },
                "memory": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-memory"],
                    'env':{
                        "http_proxy": "http://proxy.iil.intel.com:911",
                        "https_proxy": "http://proxy.iil.intel.com:911"
                    }
                },
                "sqlite" : {
                    "command": "uvx",
                    "args": [
                        "mcp-server-sqlite",
                        "--db-path",
                        "test.db"
                    ],
                    'env':{
                        "http_proxy": "http://proxy.iil.intel.com:911",
                        "https_proxy": "http://proxy.iil.intel.com:911"
                    }
                },
                # "Trivy MCP": {
                #     "command": "/home/intel/cengguang/trivy",
                #     "args": [
                #         "mcp",  
                #         "--trivy-binary",  
                #         "/home/intel/cengguang/trivy",  
                #         "-t",  
                #         "stdio",  
                #         "-p",  
                #         "23456"  
                #     ],
                #     'env':{
                #         "http_proxy": "http://proxy.iil.intel.com:911",
                #         "https_proxy": "http://proxy.iil.intel.com:911"
                #     }
                # },
                "filesystem": {
                    "command": "docker",
                    "args": [
                        "run",
                        "-i",
                        "--rm",
                        "--mount", "type=bind,src=/tmp,dst=/tmp",
                        "--mount", "type=bind,src=/home/intel/chennan,dst=/home/intel/chennan",
                        "mcp/filesystem",
                        "/home/intel/chennan"
                    ],
                    'env':{
                        "http_proxy": "http://proxy.iil.intel.com:911",
                        "https_proxy": "http://proxy.iil.intel.com:911"
                    }
                },
            }
        }
    ]
    # 创建UI代理
    agent = Assistant(
        llm=llm,
        function_list=tool_list,
        system_message=system_prompt
    )

    # --- 启动WebUI ---
    # 预设一些用户可能点击的示例问题
    chatbot_config = {
        'prompt.suggestions': [
            '你好',
            '请帮我分析一下镜像 nginx:1.14.2-alpine，它的基础镜像是 debian:stretch-slim'
        ],
        'verbose': True
    }
    WebUI(agent, chatbot_config=chatbot_config).run()

if __name__ == '__main__':
    main()