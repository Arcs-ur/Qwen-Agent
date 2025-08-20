# Copyright 2023 The Qwen team, Alibaba Group. All rights reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""A multi-agent cooperation example implemented by router and assistant"""

import os

from qwen_agent.agents import Assistant, Router, Reflection, ReActChat
from qwen_agent.gui import WebUI

ROOT_RESOURCE = os.path.join(os.path.dirname(__file__), 'resource')


def init_agent_service():
    # settings
    # llm_cfg = {
    #     # Use your own model service compatible with OpenAI API by vLLM/SGLang:
    #     'model': '/llm/models/Qwen3-32B',
    #     'model_server': 'http://localhost:8001/v1',  # api_base
    #     # 'model': 'GLM-4.5-Air',
    #     # 'model_server': 'http://10.239.95.99:8001/v1',
    #     'api_key': 'EMPTY',
    
    #     'generate_cfg': {
    #         # When using vLLM/SGLang OAI API, pass the parameter of whether to enable thinking mode in this way
    #         'extra_body': {
    #             'chat_template_kwargs': {'enable_thinking': False}
    #         },
    
    #         # Add: When the content is `<think>this is the thought</think>this is the answer`
    #         # Do not add: When the response has been separated by reasoning_content and content
    #         # This parameter will affect the parsing strategy of tool call
    #         # 'thought_in_content': True,
    #     },
    # }
    llm_cfg = {
        # Use the OpenAI-compatible model service provided by DashScope:
        # 'model': 'qwen3-30b-a3b-instruct-2507',
        # 'model_server': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
        # 'api_key': "sk-0902e23c8a7543159d5822803f831769",
        'model_server': "https://api-inference.modelscope.cn/v1",
        'model': "Qwen/Qwen3-Coder-480B-A35B-Instruct",
        'api_key': "ms-df44f694-9197-4fff-beaf-677b6bdc5e1b",
    
        # 'generate_cfg': {
        #     # When using Dash Scope OAI API, pass the parameter of whether to enable thinking mode in this way
        #     'extra_body': {
        #         'enable_thinking': False
        #     },
        # },
    }
    tools = [
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
                        "--mount", "type=bind,src=/home/intel/projects,dst=/home/intel/projects",
                        "mcp/filesystem",
                        "/home/intel/projects"
                    ],
                    'env':{
                        "http_proxy": "http://proxy.iil.intel.com:911",
                        "https_proxy": "http://proxy.iil.intel.com:911"
                    }
                },
            }
        },
        'trivy_scanner',
        # 'code_interpreter',  # Built-in tools
    ]

    # Define cve agents for different type
    t3_generator = ReActChat(llm=llm_cfg,
                        function_list=tools,
                        name='CVE Type-3 generator',
                        # system_message = "请你在开始执行所有操作之前，输出你的执行计划。请你使用工具查找url中的资料，并用以下格式回答问题，相关性：（回答相关或者不相关），原因：（简单说明原因），建议：（如果相关给出升级建议，如果不相关就说添加到ignore文件）",
                        system_message= "请你在开始执行所有操作之前，输出你的执行计划。",
                        description="我是一个用来解决CVE漏洞检测的专家，我将帮助用户根据CVE扫描结果查找相关资料，补充相关信息，来通过CVE漏洞检测。")
    t3_reflector = Assistant(llm=llm_cfg,
                        name='CVE Type-3 reflector',
                        system_message= "你将就gerator给出的结论提出你的修改意见。请用以下格式回答问题，可信度：（回答可信或者不可信），修改意见：给出相关的意见。",
                        description="我是一个CVE漏洞检测的审核专家，我将审核generator给出的结论，并且根据generator的结论。")

    t3_planner = Reflection(
        llm=llm_cfg,
        name='CVE Type-3 planner',
        agents=[t3_generator, t3_reflector]
    )

    # Define a router (simultaneously serving as a text agent)
    planner = Router(
        llm=llm_cfg,
        agents=[t3_planner],
    )
    return t3_planner


def app_gui():
    bot = init_agent_service()
    chatbot_config = {
        'verbose': True,
    }
    WebUI(bot, chatbot_config=chatbot_config).run()


if __name__ == '__main__':
    app_gui()
