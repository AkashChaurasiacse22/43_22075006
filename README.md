# src/test_agent/config/agents.yaml

manager_agent:
  role: >
    Security Operations Manager
  goal: >
    Oversee the security monitoring process, delegate tasks to sub-agents, review their outputs, and ensure all protocols are followed. Provide a final summary and escalate any issues.
  backstory: >
    You are the SOC manager. Your job is to coordinate the team, monitor all activities, ensure policy compliance, and deliver a final report.

url_analyzer_agent:
  role: >
    Senior Security Analyst - URL Threat Detection Specialist
  goal: >
    Analyze URL: {url} and provide a confidence score between 0 and 1.
  backstory: >
    You are an expert cybersecurity analyst. With a vast experience in URL threat detection,
    and you have vast data on confidence scores of different domains and URLs.

soc_communication_agent:
  role: >
    SOC Liaison Officer - Security Operations Coordinator
  goal: >
    Send security analysis results to SOC admin using the 'assess_severity' MCP tool.
    Use the assess_severity tool with the analysis data from the URL analyzer.
  backstory: >
    You are a SOC coordinator responsible for communicating security findings to SOC admin.
    You use MCP tools to communicate with SOC systems. Always use the assess_severity tool 
    with url and confidence_score parameters.

# src/test_agent/config/tasks.yaml

manager_task:
  description: >
    Oversee the entire security monitoring process. Delegate analysis and communication tasks, review their outputs, ensure all protocols are followed, and provide a final summary report. Escalate any detected violations.
  expected_output: >
    A comprehensive report summarizing all task outputs, detected violations, and final recommendations.
  agent: manager_agent

url_analysis_task:
  description: >
    Analyze the URL: {url} for security threats.
    Provide a confidence score between 0 and 1 based on URL characteristics.
    Consider factors like domain reputation, file extensions, protocol security, etc.
  expected_output: >
    A dictionary with the following structure:
    {
      "url": "{url}",
      "confidence_score": <float between 0 and 1>
    }
    
    Where confidence_score represents the threat level:
    - 0.0-0.5: Low threat (safe)
    - 0.5-0.8: Medium threat (suspicious) 
    - 0.8-1.0: High threat (dangerous)
  agent: url_analyzer_agent

soc_communication_task:
  description: >
    Take the URL analysis results and use the 'assess_severity' MCP tool to get SOC admin recommendations.
    Call assess_severity with the url and confidence_score from the analysis.
    The tool will return an action recommendation (allow/review/block).
  expected_output: >
    SOC admin response containing:
    - url: The analyzed URL
    - confidence_score: The threat confidence score
    - result: Recommended action (allow/review/block)
  agent: soc_communication_agent


# src/test_agent/crew.py

from crewai import Agent, Crew, Process, Task, LLM
from crewai.project import CrewBase, agent, crew, task
from crewai_tools import MCPServerAdapter
from mcp import StdioServerParameters
from .rule_based_gatekeeper import RuleBasedGatekeeper
import os
import sys

@CrewBase
class SecurityCrew():
    """Hierarchical security monitoring crew with manager agent"""

    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    ollama_llm = LLM(
        model="ollama/mistral:7b-instruct-q6_K", 
        num_ctx=4096,
    )

    def __init__(self, mcp_tools=None):
        self.mcp_tools = mcp_tools or []
        self.gatekeeper = RuleBasedGatekeeper()
        super().__init__()

    @agent
    def manager_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['manager_agent'],
            verbose=True,
            llm=self.ollama_llm,
            allow_delegation=True  # Manager can delegate tasks
        )

    @agent
    def url_analyzer_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['url_analyzer_agent'],
            verbose=True,
            allow_delegation=False,
            llm=self.ollama_llm,
        )

    @agent
    def soc_communication_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['soc_communication_agent'],
            verbose=True,
            tools=self.mcp_tools,
            allow_delegation=False,
            llm=self.ollama_llm,
            step_callback=self.gatekeeper.step_callback,
        )

    @task
    def url_analysis_task(self) -> Task:
        return Task(
            config=self.tasks_config['url_analysis_task'],
            agent=self.url_analyzer_agent()
        )

    @task
    def soc_communication_task(self) -> Task:
        task_id = f"soc_comm_{id(self)}"
        self.gatekeeper.set_current_task(task_id)
        return Task(
            config=self.tasks_config['soc_communication_task'],
            agent=self.soc_communication_agent(),
            context=[self.url_analysis_task()]
        )

    @task
    def manager_task(self) -> Task:
        # The manager task takes the outputs of the sub-tasks as context
        return Task(
            config=self.tasks_config['manager_task'],
            agent=self.manager_agent(),
            context=[self.url_analysis_task(), self.soc_communication_task()]
        )

    @crew
    def crew(self) -> Crew:
        """Creates the hierarchical security monitoring crew"""
        return Crew(
            agents=self.agents,
            tasks=[self.manager_task()],  # Only the manager task at the top level
            process=Process.hierarchical,  # Hierarchical execution
            verbose=True
        )

    def get_gatekeeper_report(self) -> dict:
        return self.gatekeeper.get_validation_report()


# src/test_agent/main.py

import sys
import warnings
import os
from datetime import datetime
from crew import SecurityCrew
from crewai_tools import MCPServerAdapter
from mcp import StdioServerParameters

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")

def run():
    urls = [
        "https://example.com",
        "https://malware.com/download.exe", 
        "https://phishing-site.net/fake-login",
        "https://legitimate-site.org",
        "https://suspicious-download.org/file.exe",
        "http://unsecure-site.com"
    ]

    print(f"\n🔍 Processing {len(urls)} URLs with Hierarchical Manager Agent...")
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    mcp_server_path = os.path.join(current_dir, "mcp_soc_server.py")
    
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[mcp_server_path],
        env=dict(os.environ),
    )
    
    try:
        with MCPServerAdapter(server_params) as mcp_tools:
            print(f"Available MCP tools: {[tool.name for tool in mcp_tools]}")
            
            security_crew = SecurityCrew(mcp_tools=list(mcp_tools))
            url_inputs = [{"url": url} for url in urls]
            results = security_crew.crew().kickoff_for_each(inputs=url_inputs)

            print("\n🛡️ MANAGER AGENT FINAL REPORT")
            for i, (url, result) in enumerate(zip(urls, results), 1):
                print(f"\n{i}. {url}\n{result}\n{'-'*40}")

            gatekeeper_report = security_crew.get_gatekeeper_report()
            print("\n🛡️ GATEKEEPER REPORT")
            print(gatekeeper_report)

    except Exception as e:
        print(f"Error with MCP connection: {e}")
        return {"error": str(e)}

if __name__ == "__main__":
    results = run()
    print("\nFinal Results:")
    print(results)
    sys.exit(0)

