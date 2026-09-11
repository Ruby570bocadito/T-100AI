"""Advanced Workflow Engine con Conditional Steps, Loop, Variables, Interactive y Editor"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import structlog

logger = structlog.get_logger()


@dataclass
class StepCondition:
    """Condición para ejecutar un step"""
    field: str
    operator: str
    value: Any
    logical: str = "AND"

    def evaluate(self, context: dict) -> bool:
        actual = self._get_nested_value(context, self.field)

        if self.operator == "==":
            return actual == self.value
        elif self.operator == "!=":
            return actual != self.value
        elif self.operator == ">":
            return actual > self.value
        elif self.operator == "<":
            return actual < self.value
        elif self.operator == ">=":
            return actual >= self.value
        elif self.operator == "<=":
            return actual <= self.value
        elif self.operator == "contains":
            return self.value in str(actual)
        elif self.operator == "exists":
            return actual is not None
        elif self.operator == "not_exists":
            return actual is None
        elif self.operator == "matches":
            return bool(re.match(self.value, str(actual)))

        return False

    def _get_nested_value(self, data: dict, path: str) -> Any:
        keys = path.split(".")
        value = data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value


@dataclass
class Step:
    skill: str
    action: str
    params: dict = field(default_factory=dict)
    requires_confirmation: bool = False
    depends_on: list[str] = field(default_factory=list)
    id: Optional[str] = None

    if_condition: Optional[StepCondition] = None
    else_steps: list[dict] = field(default_factory=list)

    loop: Optional[dict] = None
    loop_variable: Optional[str] = None
    loop_items: Optional[list] = None

    on_success: Optional[str] = None
    on_failure: Optional[str] = None


@dataclass
class Workflow:
    name: str
    description: str
    steps: list[Step] = field(default_factory=list)
    source: str = "builtin"
    variables: dict = field(default_factory=dict)
    interactive: bool = False
    pause_on_step: int = -1

    metadata: dict = field(default_factory=dict)


@dataclass
class WorkflowContext:
    variables: dict
    results: dict
    current_step: int = 0
    paused: bool = False
    paused_at_step: int = 0
    user_data: dict = field(default_factory=dict)


class WorkflowVariableEngine:
    """Motor de sustitución de variables"""

    @staticmethod
    def substitute(text: str, context: dict) -> str:
        if not text:
            return text

        for match in re.finditer(r"\{\{([^}]+)\}\}", text):
            path = match.group(1).strip()
            value = WorkflowVariableEngine._get_value(context, path)
            if value is not None:
                text = text.replace(match.group(0), str(value))

        return text

    @staticmethod
    def _get_value(data: dict, path: str) -> Any:
        keys = path.split(".")
        value = data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key, f"${{{path}}}")
            elif isinstance(value, list) and key.isdigit():
                idx = int(key)
                value = value[idx] if idx < len(value) else f"${{{path}}}"
            else:
                return f"${{{path}}}"
        return value

    @staticmethod
    def extract_variables(text: str) -> list[str]:
        return re.findall(r"\{\{([^}]+)\}\}", text)


class WorkflowEditor:
    """Editor CLI para crear y modificar workflows"""

    def __init__(self):
        self.workflows_dir = Path("workflows")
        # El directorio se crea de forma perezosa al guardar (save_workflow);
        # al cargar solo se escanea si existe.

    def create_workflow_interactive(self) -> dict:
        """Crea un workflow de forma interactiva"""
        print("\n=== Workflow Editor ===")

        name = input("Nombre del workflow: ").strip()
        description = input("Descripcion: ").strip()

        workflow = {
            "name": name,
            "description": description,
            "steps": [],
            "variables": {},
            "interactive": False,
        }

        print("\nAnade pasos (enter vacio para terminar):")
        step_num = 1
        while True:
            print(f"\n--- Paso {step_num} ---")
            skill = input("Skill: ").strip()
            if not skill:
                break

            action = input("Accion: ").strip()
            params_str = input("Parametros (key=value, comma separated): ").strip()
            params = {}
            if params_str:
                for pair in params_str.split(","):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        params[k.strip()] = v.strip()

            step = {
                "skill": skill,
                "action": action or "execute",
                "params": params,
            }

            condition_str = input("Condicion (field,operator,value) o vacio: ").strip()
            if condition_str:
                parts = condition_str.split(",")
                if len(parts) >= 3:
                    step["if_condition"] = {
                        "field": parts[0].strip(),
                        "operator": parts[1].strip(),
                        "value": parts[2].strip(),
                    }

            workflow["steps"].append(step)
            step_num += 1

        print("\nAnade variables iniciales (enter vacio para terminar):")
        while True:
            var_name = input("Variable: ").strip()
            if not var_name:
                break
            var_value = input("Valor: ").strip()
            workflow["variables"][var_name] = var_value

        workflow["interactive"] = input("Modo interactivo? (s/n): ").strip().lower() == "s"

        return workflow

    def save_workflow(self, workflow: dict, filename: Optional[str] = None) -> Path:
        if not filename:
            filename = f"{workflow['name'].lower().replace(' ', '_')}.yaml"

        self.workflows_dir.mkdir(parents=True, exist_ok=True)
        filepath = self.workflows_dir / filename

        import yaml
        with open(filepath, 'w') as f:
            yaml.dump(workflow, f, default_flow_style=False)

        logger.info("Workflow saved", path=str(filepath))
        return filepath

    def load_workflow(self, name: str) -> Optional[dict]:
        for ext in [".yaml", ".yml", ".json"]:
            filepath = self.workflows_dir / f"{name}{ext}"
            if filepath.exists():
                with open(filepath) as f:
                    if ext == ".json":
                        return json.load(f)
                    else:
                        import yaml
                        return yaml.safe_load(f)
        return None


class AdvancedWorkflowEngine:
    """Motor avanzado de workflows con todas las características"""

    def __init__(self, workflows_dir: Optional[str] = None):
        self.workflows: dict[str, Workflow] = {}
        self.workflows_dir = Path(workflows_dir) if workflows_dir else Path("workflows")
        self._var_engine = WorkflowVariableEngine()
        self._editor = WorkflowEditor()
        self._interactive_callback: Optional[Callable] = None
        self._cancel_requested = False
        self._load_all_workflows()

    def set_interactive_callback(self, callback: Callable) -> None:
        self._interactive_callback = callback

    def _load_all_workflows(self) -> None:
        self.workflows = self._build_default_workflows()

        if self.workflows_dir.exists():
            for filepath in self.workflows_dir.rglob("*.yaml"):
                self._load_workflow_file(filepath)
            for filepath in self.workflows_dir.rglob("*.json"):
                self._load_workflow_file(filepath)

    def _load_workflow_file(self, path: Path) -> None:
        try:
            with open(path) as f:
                if path.suffix == ".json":
                    data = json.load(f)
                else:
                    import yaml
                    data = yaml.safe_load(f)

            workflow = self._parse_workflow_data(data)
            self.workflows[workflow.name] = workflow
            logger.info("Workflow loaded", name=workflow.name)
        except Exception as e:
            logger.warning("Failed to load workflow", path=str(path), error=str(e))

    def _parse_workflow_data(self, data: dict) -> Workflow:
        steps = []
        for step_data in data.get("steps", []):
            step = Step(
                skill=step_data.get("skill", ""),
                action=step_data.get("action", "execute"),
                params=step_data.get("params", {}),
                requires_confirmation=step_data.get("requires_confirmation", False),
                depends_on=step_data.get("depends_on", []),
                id=step_data.get("id"),
            )

            if "if_condition" in step_data:
                cond = step_data["if_condition"]
                step.if_condition = StepCondition(
                    field=cond.get("field", ""),
                    operator=cond.get("operator", "=="),
                    value=cond.get("value", ""),
                )

            if "loop" in step_data:
                step.loop = step_data["loop"]

            steps.append(step)

        return Workflow(
            name=data.get("name", ""),
            description=data.get("description", ""),
            steps=steps,
            source="file",
            variables=data.get("variables", {}),
            interactive=data.get("interactive", False),
            pause_on_step=data.get("pause_on_step", -1),
        )

    def _build_default_workflows(self) -> dict[str, Workflow]:
        return {
            "full_recon": Workflow(
                name="full_recon",
                description="Reconocimiento completo",
                steps=[
                    Step(skill="recon", action="ping_sweep", id="ping"),
                    Step(skill="recon", action="port_scan", id="port_scan", depends_on=["ping"]),
                    Step(skill="recon", action="service_scan", id="service_scan", depends_on=["port_scan"]),
                    Step(skill="recon", action="os_fingerprint", id="os_scan", depends_on=["port_scan"]),
                ],
            ),
            "web_audit": Workflow(
                name="web_audit",
                description="Auditoría web completa",
                steps=[
                    Step(skill="web", action="dir_fuzz", id="dir_scan"),
                    Step(skill="web", action="nuclei_scan", id="nuclei", depends_on=["dir_scan"]),
                    Step(skill="web", action="sqlmap_test", id="sqlmap", depends_on=["dir_scan"]),
                ],
            ),
            "osint_full": Workflow(
                name="osint_full",
                description="OSINT completo",
                steps=[
                    Step(skill="osint", action="whois_lookup", id="whois"),
                    Step(skill="osint", action="subdomain_enum", id="subdomains", depends_on=["whois"]),
                    Step(skill="osint", action="email_harvest", id="emails", depends_on=["whois"]),
                ],
            ),
        }

    async def execute_workflow(
        self,
        name: str,
        session: Any,
        initial_vars: Optional[dict] = None
    ) -> dict[str, Any]:
        if name not in self.workflows:
            return {"error": f"Workflow '{name}' not found", "success": False}

        workflow = self.workflows[name]
        context = WorkflowContext(
            variables={**workflow.variables, **(initial_vars or {})},
            results={}
        )

        completed = set()
        results = []

        for i, step in enumerate(workflow.steps):
            if self._cancel_requested:
                return {"error": "Workflow cancelled", "success": False, "partial_results": results}

            context.current_step = i

            if workflow.interactive or (workflow.pause_on_step >= 0 and i == workflow.pause_on_step):
                if self._interactive_callback:
                    context.paused = True
                    context.paused_at_step = i
                    await self._interactive_callback(context)

            if not self._check_dependencies(step, completed):
                logger.warning("Skipping step, dependencies not met", step_id=step.id)
                continue

            step_result = await self._execute_step(step, context, session)
            results.append(step_result)

            if step.id:
                context.results[step.id] = step_result
                completed.add(step.id)

            if not step_result.get("success", False) and step.on_failure:
                if step.on_failure == "stop":
                    break
                elif step.on_failure == "continue":
                    continue

            if step.on_success == "stop":
                break

        return {
            "workflow": name,
            "success": all(r.get("success", False) for r in results),
            "results": results,
            "context": context.variables
        }

    async def _execute_step(self, step: Step, context: WorkflowContext, session: Any) -> dict:
        for key, value in step.params.items():
            if isinstance(value, str):
                step.params[key] = self._var_engine.substitute(value, context.variables)

        for key, value in context.variables.items():
            if isinstance(value, str):
                context.variables[key] = self._var_engine.substitute(value, context.variables)

        if step.if_condition:
            if not step.if_condition.evaluate(context.results):
                logger.info("Step condition not met, skipping", step_id=step.id)
                return {"step": step.id, "skipped": True, "success": True}

        if step.loop and step.loop_variable:
            loop_result = await self._execute_loop(step, context, session)
            return loop_result

        try:
            skill_manager = getattr(session, "skill_manager", None)
            if not skill_manager:
                return {
                    "step": step.id,
                    "success": False,
                    "error": "No skill manager available on session",
                    "skill": step.skill,
                    "action": step.action,
                }

            skill_result = await skill_manager.execute_skill(step.skill, step.action, step.params)

            return {
                "step": step.id,
                "success": skill_result.success,
                "output": skill_result.output,
                "findings": skill_result.findings,
                "skill": step.skill,
                "action": step.action,
                "error": skill_result.error,
            }
        except Exception as e:
            logger.error("Step execution failed", step=step.id, skill=step.skill, action=step.action, error=str(e))
            return {
                "step": step.id,
                "success": False,
                "error": str(e),
                "skill": step.skill,
                "action": step.action,
            }

    async def _execute_loop(self, step: Step, context: WorkflowContext, session: Any) -> dict:
        items = context.variables.get(step.loop_variable, [])
        if not isinstance(items, list):
            items = [items]

        results = []
        for idx, item in enumerate(items):
            context.variables[f"{step.loop_variable}_current"] = item
            context.variables[f"{step.loop_variable}_index"] = idx

            result = await self._execute_step(step, context, session)
            results.append(result)

        return {
            "step": step.id,
            "success": all(r.get("success", False) for r in results),
            "loop_results": results,
            "iterations": len(items)
        }

    def _check_dependencies(self, step: Step, completed: set) -> bool:
        if not step.depends_on:
            return True
        return all(dep in completed for dep in step.depends_on)

    def cancel_workflow(self) -> None:
        self._cancel_requested = True

    def list_workflows(self) -> list[dict]:
        return [
            {
                "name": w.name,
                "description": w.description,
                "steps": len(w.steps),
                "source": w.source,
                "interactive": w.interactive,
            }
            for w in self.workflows.values()
        ]

    def create_workflow_interactive(self) -> bool:
        workflow_data = self._editor.create_workflow_interactive()
        self._editor.save_workflow(workflow_data)

        workflow = self._parse_workflow_data(workflow_data)
        self.workflows[workflow.name] = workflow

        return True

    def export_workflow_yaml(self, name: str) -> Optional[str]:
        if name not in self.workflows:
            return None

        workflow = self.workflows[name]
        import yaml

        data = {
            "name": workflow.name,
            "description": workflow.description,
            "variables": workflow.variables,
            "interactive": workflow.interactive,
            "steps": []
        }

        for step in workflow.steps:
            step_data = {
                "id": step.id,
                "skill": step.skill,
                "action": step.action,
                "params": step.params,
            }
            if step.depends_on:
                step_data["depends_on"] = step.depends_on
            if step.if_condition:
                step_data["if_condition"] = {
                    "field": step.if_condition.field,
                    "operator": step.if_condition.operator,
                    "value": step.if_condition.value,
                }
            data["steps"].append(step_data)

        return yaml.dump(data, default_flow_style=False)
