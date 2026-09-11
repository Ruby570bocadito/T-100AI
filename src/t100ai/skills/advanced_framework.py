"""Advanced Skill Framework con Dependencies, Events, Templates, Cross-skill y Analytics"""

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Optional

import structlog

if TYPE_CHECKING:
    pass

logger = structlog.get_logger()


class RiskLevel(Enum):
    PASSIVE = 0
    ACTIVE = 1
    INTRUSIVE = 2


class SkillEvent(Enum):
    BEFORE_EXECUTE = "before_execute"
    AFTER_EXECUTE = "after_execute"
    ON_ERROR = "on_error"
    ON_SUCCESS = "on_success"
    ON_WARNING = "on_warning"


@dataclass
class SkillResult:
    success: bool
    output: str = ""
    error: Optional[str] = None
    findings: list[dict] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    execution_time: float = 0.0
    metadata: dict = field(default_factory=dict)


@dataclass
class SkillDependency:
    name: str
    version: str = "any"
    required: bool = True
    check_func: Optional[Callable] = None


@dataclass
class SkillEventHook:
    event: SkillEvent
    callback: Callable
    priority: int = 0


@dataclass
class SkillAnalytics:
    executions: int = 0
    successes: int = 0
    failures: int = 0
    total_time: float = 0.0
    last_execution: Optional[datetime] = None
    average_time: float = 0.0
    errors: list[str] = field(default_factory=list)


@dataclass
class CrossSkillAction:
    name: str
    description: str
    skills_required: list[str]
    workflow: list[dict]
    auto_execute: bool = False


class BaseSkill(ABC):
    name: str = ""
    description: str = ""
    category: str = ""
    risk_level: RiskLevel = RiskLevel.ACTIVE

    def __init__(self):
        self.tools: list[str] = []
        self.workflows: list[str] = []
        self._dependencies: list[SkillDependency] = []
        self._hooks: list[SkillEventHook] = []
        self._analytics = SkillAnalytics()

    @abstractmethod
    async def execute(self, action: str, params: dict) -> SkillResult:
        pass

    @abstractmethod
    async def validate_params(self, action: str, params: dict) -> bool:
        pass

    def add_dependency(self, dependency: SkillDependency) -> None:
        self._dependencies.append(dependency)

    def add_hook(self, event: SkillEvent, callback: Callable, priority: int = 0) -> None:
        self._hooks.append(SkillEventHook(event, callback, priority))
        self._hooks.sort(key=lambda h: h.priority, reverse=True)

    def get_available_actions(self) -> list[str]:
        return []

    def requires_confirmation(self, action: str) -> bool:
        return self.risk_level == RiskLevel.INTRUSIVE

    def check_dependencies(self) -> tuple[bool, list[str]]:
        missing = []
        for dep in self._dependencies:
            if dep.required and not self._check_single_dependency(dep):
                missing.append(dep.name)
        return len(missing) == 0, missing

    def _check_single_dependency(self, dep: SkillDependency) -> bool:
        if dep.check_func:
            return dep.check_func()
        import shutil
        return shutil.which(dep.name) is not None

    async def _emit_event(self, event: SkillEvent, context: dict) -> None:
        for hook in self._hooks:
            if hook.event == event:
                try:
                    if asyncio.iscoroutinefunction(hook.callback):
                        await hook.callback(context)
                    else:
                        hook.callback(context)
                except Exception as e:
                    logger.warning(f"Hook error in {self.name}", event=event.value, error=str(e))

    def _update_analytics(self, result: SkillResult) -> None:
        self._analytics.executions += 1
        self._analytics.total_time += result.execution_time
        self._analytics.last_execution = datetime.now()
        self._analytics.average_time = (
            self._analytics.total_time / self._analytics.executions
        )
        if result.success:
            self._analytics.successes += 1
        else:
            self._analytics.failures += 1
            if result.error:
                self._analytics.errors.append(result.error)

    def get_analytics(self) -> dict:
        return {
            "skill": self.name,
            "executions": self._analytics.executions,
            "successes": self._analytics.successes,
            "failures": self._analytics.failures,
            "success_rate": f"{(self._analytics.successes / max(1, self._analytics.executions)) * 100:.1f}%",
            "average_time": f"{self._analytics.average_time:.2f}s",
            "last_execution": self._analytics.last_execution.isoformat() if self._analytics.last_execution else "Never",
        }


class SkillTemplate:
    """Plantilla para crear skills rápidamente"""

    def __init__(
        self,
        name: str,
        description: str,
        category: str,
        actions: dict[str, dict],
        tools_required: list[str] = None,
    ):
        self.name = name
        self.description = description
        self.category = category
        self.actions = actions
        self.tools_required = tools_required or []

    def generate_skill(self) -> type:
        """Genera una clase de skill desde la plantilla"""
        class GeneratedSkill(BaseSkill):
            name = self.name
            description = self.description
            category = self.category

            def __init__(self):
                super().__init__()
                self.tools = self.__class__.get_tools()
                for tool in self.tools_required:
                    self.add_dependency(SkillDependency(name=tool))

            @classmethod
            def get_tools(cls) -> list[str]:
                return self.tools_required

            async def execute(self, action: str, params: dict) -> SkillResult:
                start_time = time.time()
                await self._emit_event(SkillEvent.BEFORE_EXECUTE, {"action": action, "params": params})

                try:
                    if action not in self.actions:
                        return SkillResult(success=False, error=f"Unknown action: {action}")

                    result = SkillResult(
                        success=True,
                        output=f"Executed {action} with params {params}"
                    )

                    await self._emit_event(SkillEvent.ON_SUCCESS, {"result": result})
                    await self._emit_event(SkillEvent.AFTER_EXECUTE, {"result": result})

                    result.execution_time = time.time() - start_time
                    self._update_analytics(result)
                    return result

                except Exception as e:
                    result = SkillResult(success=False, error=str(e))
                    await self._emit_event(SkillEvent.ON_ERROR, {"error": str(e)})
                    result.execution_time = time.time() - start_time
                    self._update_analytics(result)
                    return result

            async def validate_params(self, action: str, params: dict) -> bool:
                if action not in self.actions:
                    return False
                required = self.actions[action].get("required_params", [])
                return all(p in params for p in required)

            def get_available_actions(self) -> list[str]:
                return list(self.actions.keys())

        return GeneratedSkill


class SkillManager:
    """Gestor avanzado de skills con todas las características"""

    def __init__(self):
        self.skills: dict[str, BaseSkill] = {}
        self._cross_skills: dict[str, CrossSkillAction] = {}
        self._templates: dict[str, SkillTemplate] = {}
        self._global_analytics: dict[str, dict] = {}

    def register_skill(self, skill: BaseSkill) -> None:
        self.skills[skill.name] = skill
        logger.info("Skill registered", skill=skill.name)

    def register_cross_skill(self, action: CrossSkillAction) -> None:
        self._cross_skills[action.name] = action
        logger.info("Cross-skill registered", name=action.name)

    def register_template(self, template: SkillTemplate) -> None:
        self._templates[template.name] = template

    def create_skill_from_template(self, template_name: str) -> Optional[BaseSkill]:
        if template_name not in self._templates:
            return None
        template = self._templates[template_name]
        skill_class = template.generate_skill()
        return skill_class()

    async def execute_skill(self, skill_name: str, action: str, params: dict) -> SkillResult:
        if skill_name not in self.skills:
            return SkillResult(success=False, error=f"Skill not found: {skill_name}")

        skill = self.skills[skill_name]

        deps_ok, missing = skill.check_dependencies()
        if not deps_ok:
            return SkillResult(
                success=False,
                error=f"Missing dependencies: {', '.join(missing)}"
            )

        if not await skill.validate_params(action, params):
            return SkillResult(success=False, error="Invalid parameters")

        return await skill.execute(action, params)

    async def execute_cross_skill(self, action_name: str, initial_params: dict, session: Any) -> list[SkillResult]:
        if action_name not in self._cross_skills:
            return [SkillResult(success=False, error=f"Cross-skill not found: {action_name}")]

        action = self._cross_skills[action_name]
        results = []
        context = {**initial_params}

        for step in action.workflow:
            skill_name = step.get("skill")
            skill_action = step.get("action", "execute")
            params = step.get("params", {})

            for key, value in params.items():
                if isinstance(value, str) and value.startswith("$"):
                    context_key = value[1:]
                    params[key] = context.get(context_key, value)

            if skill_name in self.skills:
                result = await self.execute_skill(skill_name, skill_action, params)
                results.append(result)
                context[f"{skill_name}.{skill_action}"] = result

        return results

    def get_analytics(self) -> dict:
        all_analytics = {}
        for name, skill in self.skills.items():
            all_analytics[name] = skill.get_analytics()

        total_executions = sum(a["executions"] for a in all_analytics.values())
        total_successes = sum(a["successes"] for a in all_analytics.values())

        return {
            "skills": all_analytics,
            "summary": {
                "total_skills": len(self.skills),
                "total_executions": total_executions,
                "overall_success_rate": f"{(total_successes / max(1, total_executions)) * 100:.1f}%",
                "cross_skills": len(self._cross_skills),
            }
        }

    def list_skills(self) -> list[dict]:
        return [
            {
                "name": s.name,
                "description": s.description,
                "category": s.category,
                "risk_level": s.risk_level.value,
                "actions": s.get_available_actions(),
                "dependencies": [d.name for d in s._dependencies],
            }
            for s in self.skills.values()
        ]

    def list_cross_skills(self) -> list[dict]:
        return [
            {
                "name": cs.name,
                "description": cs.description,
                "skills_required": cs.skills_required,
                "steps": len(cs.workflow),
            }
            for cs in self._cross_skills.values()
        ]


SKILL_TEMPLATES = {
    "recon_basic": SkillTemplate(
        name="recon_basic",
        description="Reconocimiento básico",
        category="recon",
        actions={
            "scan": {
                "description": "Escaneo básico",
                "required_params": ["target"],
            },
            "ping": {
                "description": "Ping sweep",
                "required_params": ["network"],
            },
        },
        tools_required=["nmap"],
    ),
    "web_enum": SkillTemplate(
        name="web_enum",
        description="Enumeración web",
        category="web",
        actions={
            "dir_scan": {
                "description": "Escaneo de directorios",
                "required_params": ["url"],
            },
            "subdomain": {
                "description": "Enumeración de subdominios",
                "required_params": ["domain"],
            },
        },
        tools_required=["gobuster", "amass"],
    ),
    "osint_basic": SkillTemplate(
        name="osint_basic",
        description="OSINT básico",
        category="osint",
        actions={
            "whois": {
                "description": "WHOIS lookup",
                "required_params": ["domain"],
            },
            "emails": {
                "description": "Recolección de emails",
                "required_params": ["domain"],
            },
        },
        tools_required=["theHarvester"],
    ),
}
