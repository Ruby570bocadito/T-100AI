"""Agent Orchestrator con Sub-Agentes para tareas paralelas"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import structlog

logger = structlog.get_logger()


class AgentStatus(Enum):
    IDLE = "idle"
    THINKING = "thinking"
    EXECUTING = "executing"
    WAITING = "waiting"
    DONE = "done"
    ERROR = "error"
    CANCELLED = "cancelled"


class AgentRole(Enum):
    ORCHESTRATOR = "orchestrator"
    RECON = "recon"
    EXPLOIT = "exploit"
    ANALYST = "analyst"
    REPORTER = "reporter"
    COORDINATOR = "coordinator"


@dataclass
class AgentMessage:
    from_agent: str
    to_agent: Optional[str]
    content: Any
    message_type: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class AgentTask:
    id: str
    description: str
    agent_role: AgentRole
    status: AgentStatus = AgentStatus.IDLE
    result: Any = None
    error: Optional[str] = None
    dependencies: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None


@dataclass
class SubAgent:
    id: str
    name: str
    role: AgentRole
    instructions: str
    capabilities: list[str]
    status: AgentStatus = AgentStatus.IDLE
    current_task: Optional[AgentTask] = None
    message_queue: list[AgentMessage] = field(default_factory=list)
    memory: dict = field(default_factory=dict)

    def can_handle(self, task: AgentTask) -> bool:
        return task.agent_role == self.role or any(
            cap in task.description.lower() for cap in self.capabilities
        )


class BaseAgent:
    """Clase base para agentes"""

    def __init__(self, agent_id: str, name: str, role: AgentRole):
        self.id = agent_id
        self.name = name
        self.role = role
        self.status = AgentStatus.IDLE
        self._running = False
        self.capabilities: list[str] = []
        self.message_queue: list[AgentMessage] = []

    def can_handle(self, task: AgentTask) -> bool:
        return task.agent_role == self.role or any(
            cap in task.description.lower() for cap in self.capabilities
        )

    async def think(self, context: dict) -> str:
        return f"{self.name} pensando..."

    async def execute(self, task: AgentTask) -> dict:
        self.status = AgentStatus.EXECUTING
        try:
            result = await self._execute_task(task)
            self.status = AgentStatus.DONE
            return {"success": True, "result": result}
        except Exception as e:
            self.status = AgentStatus.ERROR
            return {"success": False, "error": str(e)}

    async def _execute_task(self, task: AgentTask) -> Any:
        raise NotImplementedError

    def receive_message(self, message: AgentMessage) -> None:
        self.message_queue.append(message)


class ReconAgent(BaseAgent):
    """Agente especializado en reconocimiento"""

    def __init__(self, agent_id: str = "recon_1"):
        super().__init__(agent_id, "Recon Agent", AgentRole.RECON)
        self.capabilities = ["scan", "recon", "nmap", "enum", "discover"]

    async def _execute_task(self, task: AgentTask) -> Any:
        await asyncio.sleep(0.5)
        return {
            "hosts_found": 5,
            "open_ports": [22, 80, 443, 3306],
            "services": {"22": "ssh", "80": "http", "443": "https"}
        }


class ExploitAgent(BaseAgent):
    """Agente especializado en explotación"""

    def __init__(self, agent_id: str = "exploit_1"):
        super().__init__(agent_id, "Exploit Agent", AgentRole.EXPLOIT)
        self.capabilities = ["exploit", "shell", "payload", "access"]

    async def _execute_task(self, task: AgentTask) -> Any:
        await asyncio.sleep(0.5)
        return {
            "exploits_tried": 3,
            "vulnerabilities_found": 2,
            "access_obtained": False
        }


class AnalystAgent(BaseAgent):
    """Agente especializado en análisis"""

    def __init__(self, agent_id: str = "analyst_1"):
        super().__init__(agent_id, "Analyst Agent", AgentRole.ANALYST)
        self.capabilities = ["analyze", "analyse", "parse", "interpret"]

    async def _execute_task(self, task: AgentTask) -> Any:
        await asyncio.sleep(0.5)
        return {
            "analysis_complete": True,
            "severity_scores": {"HIGH": 2, "MED": 3, "LOW": 1}
        }


class ReporterAgent(BaseAgent):
    """Agente especializado en reportes"""

    def __init__(self, agent_id: str = "reporter_1"):
        super().__init__(agent_id, "Reporter Agent", AgentRole.REPORTER)
        self.capabilities = ["report", "document", "export", "summary"]

    async def _execute_task(self, task: AgentTask) -> Any:
        await asyncio.sleep(0.5)
        return {
            "report_generated": True,
            "format": "markdown",
            "sections": 5
        }


class AgentOrchestrator:
    """Orquestador principal de agentes"""

    def __init__(self):
        self.agents: dict[str, BaseAgent] = {}
        self.tasks: dict[str, AgentTask] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue()
        self.results: dict[str, Any] = {}
        self.message_history: list[AgentMessage] = []
        self._running = False
        self._background_tasks: set[asyncio.Task] = set()
        self._agent_factory: dict[AgentRole, type] = {
            AgentRole.RECON: ReconAgent,
            AgentRole.EXPLOIT: ExploitAgent,
            AgentRole.ANALYST: AnalystAgent,
            AgentRole.REPORTER: ReporterAgent,
        }

    def register_agent(self, agent: BaseAgent) -> None:
        self.agents[agent.id] = agent
        logger.info("Agent registered", agent_id=agent.id, role=agent.role.value)

    def create_agent(self, role: AgentRole, agent_id: Optional[str] = None) -> BaseAgent:
        if agent_id is None:
            agent_id = f"{role.value}_{len([a for a in self.agents.values() if a.role == role])}"

        agent_class = self._agent_factory.get(role)
        if not agent_class:
            raise ValueError(f"No factory for role {role}")

        agent = agent_class(agent_id)
        self.register_agent(agent)
        return agent

    def add_task(self, task: AgentTask) -> str:
        self.tasks[task.id] = task
        logger.info("Task added", task_id=task.id, role=task.agent_role.value)
        return task.id

    async def execute_task(self, task: AgentTask) -> dict:
        agent = self._find_available_agent(task)

        if not agent:
            agent = self.create_agent(task.agent_role)

        agent.status = AgentStatus.THINKING
        await agent.think({"task": task})

        agent.status = AgentStatus.EXECUTING
        result = await agent.execute(task)

        task.result = result
        task.status = AgentStatus.DONE if result.get("success") else AgentStatus.ERROR
        task.completed_at = time.time()

        self.results[task.id] = result

        return result

    def _find_available_agent(self, task: AgentTask) -> Optional[BaseAgent]:
        for agent in self.agents.values():
            if agent.can_handle(task) and agent.status in [AgentStatus.IDLE, AgentStatus.DONE]:
                return agent
        return None

    async def execute_parallel(self, tasks: list[AgentTask]) -> dict[str, dict]:
        async def run_task(task: AgentTask) -> tuple[str, dict]:
            result = await self.execute_task(task)
            return task.id, result

        results = await asyncio.gather(
            *[run_task(t) for t in tasks],
            return_exceptions=True
        )

        return {r[0]: r[1] for r in results if not isinstance(r, Exception)}

    async def execute_sequential(self, tasks: list[AgentTask]) -> dict[str, dict]:
        results = {}
        for task in tasks:
            if not self._check_dependencies(task):
                results[task.id] = {"success": False, "error": "Dependencies not met"}
                continue

            result = await self.execute_task(task)
            results[task.id] = result

            if not result.get("success"):
                break

        return results

    def _check_dependencies(self, task: AgentTask) -> bool:
        for dep_id in task.dependencies:
            if dep_id in self.tasks:
                dep_task = self.tasks[dep_id]
                if dep_task.status != AgentStatus.DONE:
                    return False
        return True

    async def orchestrate(self, workflow: list[dict]) -> dict:
        tasks = []
        for w in workflow:
            task = AgentTask(
                id=w.get("id", f"task_{len(tasks)}"),
                description=w.get("description", ""),
                agent_role=AgentRole[w.get("role", "RECON").upper()],
                dependencies=w.get("depends_on", [])
            )
            tasks.append(task)
            self.add_task(task)

        mode = "parallel" if workflow[0].get("mode") == "parallel" else "sequential"

        if mode == "parallel":
            return await self.execute_parallel(tasks)
        else:
            return await self.execute_sequential(tasks)

    def get_status(self) -> dict:
        return {
            "total_agents": len(self.agents),
            "total_tasks": len(self.tasks),
            "active_agents": sum(1 for a in self.agents.values() if a.status == AgentStatus.EXECUTING),
            "pending_tasks": sum(1 for t in self.tasks.values() if t.status in [AgentStatus.IDLE, AgentStatus.THINKING]),
            "completed_tasks": sum(1 for t in self.tasks.values() if t.status == AgentStatus.DONE),
            "agents": {
                agent.id: {
                    "role": agent.role.value,
                    "status": agent.status.value
                }
                for agent in self.agents.values()
            }
        }

    async def deploy_task(self, description: str, context: dict) -> str:
        """Despliega una tarea al orquestador"""

        role = self._infer_role_from_description(description)

        task = AgentTask(
            id=f"task_{int(time.time())}",
            description=description,
            agent_role=role
        )

        self.add_task(task)

        bg_task = asyncio.create_task(self.execute_task(task))
        self._background_tasks.add(bg_task)
        bg_task.add_done_callback(self._background_tasks.discard)

        return task.id

    def get_task_status(self, task_id: str) -> dict:
        """Obtiene el estado de una tarea"""
        task = self.tasks.get(task_id)
        if not task:
            return {"status": "not_found"}

        return {
            "id": task.id,
            "description": task.description,
            "status": task.status.value,
            "result": task.result,
            "error": task.error
        }

    def _infer_role_from_description(self, description: str) -> AgentRole:
        """Infiere el rol apropiado para una descripción de tarea"""
        desc = description.lower()

        if any(kw in desc for kw in ["recon", "scan", "enum", "port", "host", "descubrir"]):
            return AgentRole.RECON
        elif any(kw in desc for kw in ["exploit", "attack", "vuln", "test"]):
            return AgentRole.EXPLOIT
        elif any(kw in desc for kw in ["report", "document", "informe"]):
            return AgentRole.REPORTER
        elif any(kw in desc for kw in ["analyze", "analisis", "analizar"]):
            return AgentRole.ANALYST
        else:
            return AgentRole.RECON

    def list_agents(self) -> list[dict]:
        """Lista los agentes disponibles"""
        return [
            {
                "name": agent.name,
                "role": agent.role.value,
                "status": agent.status.value,
                "id": agent.id
            }
            for agent in self.agents.values()
        ]

    def cancel_all(self) -> None:
        for agent in self.agents.values():
            agent.status = AgentStatus.CANCELLED
        self._running = False


class SmartOrchestrator(AgentOrchestrator):
    """Orquestador inteligente que puede crear agentes según necesidad"""

    def __init__(self):
        super().__init__()
        self.max_agents_per_role = 3
        self.task_history: list[dict] = []

    async def smart_orchestrate(self, objective: str, context: dict) -> dict:
        decomposed = await self._decompose_task(objective)

        tasks = []
        for i, subtask in enumerate(decomposed):
            role = self._infer_role(subtask)
            task = AgentTask(
                id=f"smart_task_{i}",
                description=subtask,
                agent_role=role
            )
            tasks.append(task)

        results = await self.execute_parallel(tasks)

        synthesis = await self._synthesize_results(results)

        self.task_history.append({
            "objective": objective,
            "tasks": len(tasks),
            "results": results,
            "synthesis": synthesis
        })

        return {
            "objective": objective,
            "tasks_executed": len(tasks),
            "results": results,
            "final_report": synthesis
        }

    async def _decompose_task(self, objective: str) -> list[str]:
        subtasks = []

        if any(kw in objective.lower() for kw in ["scan", "recon", "enum"]):
            subtasks.append("Realizar reconocimiento de puertos y servicios")
            subtasks.append("Enumerar vulnerabilidades encontradas")

        if any(kw in objective.lower() for kw in ["exploit", "attack", "test"]):
            subtasks.append("Intentar explotación de vulnerabilidades")
            subtasks.append("Verificar acceso obtenido")

        if any(kw in objective.lower() for kw in ["analyze", "analisis"]):
            subtasks.append("Analizar resultados de reconocimiento")

        if any(kw in objective.lower() for kw in ["report", "informe"]):
            subtasks.append("Generar reporte final")

        if not subtasks:
            subtasks = [f"Ejecutar: {objective}"]

        return subtasks

    def _infer_role(self, task_description: str) -> AgentRole:
        desc = task_description.lower()

        if any(kw in desc for kw in ["recon", "scan", "enum", "port", "host"]):
            return AgentRole.RECON
        elif any(kw in desc for kw in ["exploit", "attack", "vuln"]):
            return AgentRole.EXPLOIT
        elif any(kw in desc for kw in ["report", "document"]):
            return AgentRole.REPORTER
        else:
            return AgentRole.ANALYST

    async def _synthesize_results(self, results: dict) -> str:
        if not results:
            return "No results to synthesize"

        success_count = sum(1 for r in results.values() if r.get("success"))
        total = len(results)

        synthesis = f"Se ejecutaron {total} tareas, {success_count} exitosas.\n\n"

        for task_id, result in results.items():
            if result.get("success"):
                synthesis += f"- {task_id}: Exitoso\n"
            else:
                synthesis += f"- {task_id}: Fallido ({result.get('error', 'Unknown')})\n"

        return synthesis
