from crewai import Agent, Crew, Process, Task, LLM
from crewai.project import CrewBase, agent, crew, task
from crewai.mcp import MCPServerSSE

REMOTE_OLLAMA_URL = "http://deepestthought.cse.chalmers.se:11434/v1/"


analyzer_llm = LLM(
    model="ollama/qwen3-coder-next:latest",
    #base_url=REMOTE_OLLAMA_URL,
    #api_key="ollama"
)

fixer_llm = LLM(
    model="ollama/qwen3-coder-next:latest",
    #base_url=REMOTE_OLLAMA_URL,
    #api_key="ollama"
)

verifier_llm = LLM(
    model="ollama/qwen3-coder-next:latest",
    #base_url=REMOTE_OLLAMA_URL,
    #api_key="ollama"
)

@CrewBase
class SecurityCaseStudy:
    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"
    

  

    @agent
    def security_analyzer(self) -> Agent:
        return Agent(
            config=self.agents_config["security_analyzer"],
            llm=analyzer_llm,
            mcps=[
            MCPServerSSE(url="http://localhost:8000/sse")
            ],
            verbose=True
        )

    @agent
    def security_fixer(self) -> Agent:
        return Agent(
            config=self.agents_config["security_fixer"],
            llm=fixer_llm,
            verbose=True
        )

    @agent
    def security_verifier(self) -> Agent:
        return Agent(
            config=self.agents_config["security_verifier"],
            llm=verifier_llm,
            verbose=True
        )


    @task
    def analyze_vulnerability(self) -> Task:
        return Task(
            config=self.tasks_config["analyze_vulnerability"]
            
        )

    @task
    def propose_fix(self) -> Task:
        return Task(
            config=self.tasks_config["propose_fix"],
            context=[self.analyze_vulnerability()]
        )

    @task
    def verify_fix(self) -> Task:
        return Task(
            config=self.tasks_config["verify_fix"],
            context=[
                
                self.analyze_vulnerability(),
                self.propose_fix()
            ]
        )

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=[
                
                self.security_analyzer(),
                self.security_fixer(),
                self.security_verifier()
            ],
            tasks=[
                
                self.analyze_vulnerability(),
                self.propose_fix(),
                self.verify_fix()
            ],
            process=Process.sequential,
            verbose=True,
            tracing=True
        )