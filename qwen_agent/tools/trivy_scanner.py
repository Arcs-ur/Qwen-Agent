from qwen_agent.tools.base import BaseTool, register_tool  
import subprocess  
import json  
import os  
from qwen_agent.log import logger  
 
@register_tool('trivy_scanner')  
class TrivyScanner(BaseTool):  
    description = "Execute Trivy security scanner to scan container images for vulnerabilities and return results in JSON format"  
    parameters = [{  
        'name': 'image',  
        'type': 'string',  
        'description': 'Container image to scan (e.g., intel/llm-scaler-vllm:0.2.0-b2)',  
        'required': True  
    }, {  
        'name': 'output_path',  
        'type': 'string',  
        'description': 'Output file path for JSON results (default: /projects/vuln.json)',  
        'required': False  
    }, {  
        'name': 'timeout',  
        'type': 'string',  
        'description': 'Scan timeout (default: 30m)',  
        'required': False  
    }]  
 
    def call(self, params: str, **kwargs) -> str:  
        try:  
            # 解析参数  
            params_dict = self._verify_json_format_args(params)  
            image = params_dict['image']  
            output_path = params_dict.get('output_path', '/fs/vuln.json')  
            timeout = params_dict.get('timeout', '30m')  
             
            # 确保输出目录存在  
            os.makedirs(os.path.dirname(output_path), exist_ok=True)  
             
            # 构建 Trivy 命令  
            cmd = [  
                '/home/intel/cengguang/trivy', 'image',  
                '--output', output_path,  
                '--format', 'json',  
                '--scanners', 'vuln',  
                '--timeout', timeout,  
                image  
            ]  
             
            logger.info(f"执行 Trivy 扫描命令: {' '.join(cmd)}")  
             
            # 执行命令  
            result = subprocess.run(  
                cmd,  
                capture_output=True,  
                text=True,  
                timeout=1800  # 30分钟超时  
            )  
             
            if result.returncode == 0:  
                # 读取生成的 JSON 文件  
                if os.path.exists(output_path):  
                    with open(output_path, 'r', encoding='utf-8') as f:  
                        scan_results = json.load(f)  
                     
                    # 返回扫描结果摘要  
                    summary = self._generate_summary(scan_results, output_path)  
                    return summary  
                else:  
                    return f"扫描完成，但未找到输出文件: {output_path}"  
            else:  
                error_msg = f"Trivy 扫描失败 (返回码: {result.returncode})\n"  
                error_msg += f"错误输出: {result.stderr}\n"  
                error_msg += f"标准输出: {result.stdout}"  
                return error_msg  
                 
        except subprocess.TimeoutExpired:  
            return f"Trivy 扫描超时，请检查网络连接或增加超时时间"  
        except Exception as e:  
            return f"执行 Trivy 扫描时发生错误: {str(e)}"  
     
    def _generate_summary(self, scan_results, output_path):  
        """生成扫描结果摘要"""  
        summary = f"✅ Trivy 扫描完成，结果已保存到: {output_path}\n\n"  
         
        if isinstance(scan_results, dict) and 'Results' in scan_results:  
            total_vulns = 0  
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}  
             
            for result in scan_results.get('Results', []):  
                if 'Vulnerabilities' in result:  
                    vulns = result['Vulnerabilities']  
                    if vulns:  
                        total_vulns += len(vulns)  
                        for vuln in vulns:  
                            severity = vuln.get('Severity', 'UNKNOWN')  
                            if severity in severity_counts:  
                                severity_counts[severity] += 1  
             
            summary += f"📊 扫描结果统计:\n"  
            summary += f"- 总漏洞数: {total_vulns}\n"  
            for severity, count in severity_counts.items():  
                if count > 0:  
                    summary += f"- {severity}: {count}\n"  
         
        summary += f"\n💾 完整结果已保存为 JSON 格式，可通过以下方式查看:\n"  
        summary += f"```bash\ncat {output_path}\n```"  
         
        return summary