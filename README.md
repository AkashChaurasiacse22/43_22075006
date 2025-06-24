# src/test_agent/config/agents.yaml

manager_agent:
  role: >
    Security Operations Manager
  goal: >
    Oversee all security monitoring tasks, delegate work, review outputs, and provide a final summary and escalation as needed.
  backstory: >
    You are the SOC manager. You coordinate the team, monitor all activities, ensure policy compliance, and deliver a final report.
  allow_delegation: true

url_analyzer_agent:
  role: >
    Senior Security Analyst - URL Threat Detection Specialist
  goal: >
    Analyze URL: {url} and provide a confidence score between 0 and 1.
  backstory: >
    You are an expert cybersecurity analyst. With a vast experience in URL threat detection,
    and you have vast data on confidence scores of different domains and URLs.
  allow_delegation: false

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
  allow_delegation: false

# src/test_agent/config/tasks.yaml

manager_task:
  description: >
    Oversee the security monitoring process. Delegate analysis and communication tasks, review their outputs, ensure all protocols are followed, and provide a final summary report. Escalate any detected violations.
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

from crewai import Agent, Crew, Process, Task
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

    def __init__(self, mcp_tools=None):
        self.mcp_tools = mcp_tools or []
        self.gatekeeper = RuleBasedGatekeeper()
        super().__init__()

    @agent
    def manager_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['manager_agent'],
            verbose=True,
            llm=None,  # Use your LLM configuration here if needed
            allow_delegation=True
        )

    @agent
    def url_analyzer_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['url_analyzer_agent'],
            verbose=True,
            allow_delegation=False,
            llm=None,  # Use your LLM configuration here if needed
        )

    @agent
    def soc_communication_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['soc_communication_agent'],
            verbose=True,
            tools=self.mcp_tools,
            allow_delegation=False,
            llm=None,  # Use your LLM configuration here if needed
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
        return Task(
            config=self.tasks_config['manager_task'],
            agent=self.manager_agent(),
            context=[self.url_analysis_task(), self.soc_communication_task()]
        )

    @crew
    def crew(self) -> Crew:
        """Creates the hierarchical security monitoring crew with a manager agent"""
        return Crew(
            agents=[self.manager_agent(), self.url_analyzer_agent(), self.soc_communication_agent()],
            tasks=[self.manager_task()],
            process=Process.hierarchical,
            manager_agent=self.manager_agent(),  # This is critical!
            verbose=True
        )

    def get_gatekeeper_report(self) -> dict:
        return self.gatekeeper.get_validation_report()


