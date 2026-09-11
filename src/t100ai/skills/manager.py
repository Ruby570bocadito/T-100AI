"""Skill Manager - Gestor de Skills con carga lazy"""

import asyncio
from typing import Optional

import structlog

from t100ai.core.config import T100AIConfig
from t100ai.mcp import ToolRegistry
from t100ai.skills.base import BaseSkill, SkillResult

logger = structlog.get_logger()

SKILL_REGISTRY = {
    "recon": ("t100ai.skills.recon", "ReconSkill"),
    "osint": ("t100ai.skills.osint", "OsintSkill"),
    "web": ("t100ai.skills.web", "WebSkill"),
    "postex": ("t100ai.skills.postex", "PostExSkill"),
    "forense": ("t100ai.skills.forense", "ForenseSkill"),
    "ad": ("t100ai.skills.ad", "AdSkill"),
    "report": ("t100ai.skills.report", "ReportSkill"),
}


class SkillManager:
    """Gestiona los skills disponibles en T-100AI con carga lazy"""

    def __init__(self, tool_registry: ToolRegistry, config: T100AIConfig):
        self.tool_registry = tool_registry
        self.config = config
        self.skills: dict[str, BaseSkill] = {}
        self._loaded_skills: set[str] = set()
        self._loading_skills: set[str] = set()
        self._lazy_mode = True
        self._load_lock = asyncio.Lock()
        self._skill_events: dict[str, asyncio.Event] = {}

    async def load_skills(self) -> None:
        """Carga solo metadatos de skills (lazy mode)"""
        logger.info("Initializing skill registry (lazy mode)", count=len(SKILL_REGISTRY))
        logger.info("Skills will be loaded on-demand when executed")

    async def load_all_skills(self) -> None:
        """Fuerza carga de todos los skills"""
        logger.info("Loading all skills...")
        for skill_name in SKILL_REGISTRY:
            await self._load_skill(skill_name)
        logger.info("All skills loaded", count=len(self.skills))

    async def _load_skill(self, skill_name: str) -> Optional[BaseSkill]:
        """Carga un skill específico con thread-safety"""
        if skill_name in self._loaded_skills:
            return self.skills.get(skill_name)

        if skill_name in self._loading_skills:
            event = self._skill_events.setdefault(skill_name, asyncio.Event())
            await event.wait()
            return self.skills.get(skill_name)

        if skill_name not in SKILL_REGISTRY:
            logger.warning("Unknown skill", skill=skill_name)
            return None

        async with self._load_lock:
            # Double-check after acquiring lock
            if skill_name in self._loaded_skills:
                return self.skills.get(skill_name)

            if skill_name in self._loading_skills:
                event = self._skill_events.setdefault(skill_name, asyncio.Event())
                await event.wait()
                return self.skills.get(skill_name)

            self._loading_skills.add(skill_name)
            event = self._skill_events.setdefault(skill_name, asyncio.Event())
            event.clear()

        try:
            module_path, class_name = SKILL_REGISTRY[skill_name]
            module = __import__(module_path, fromlist=[class_name])
            skill_class = getattr(module, class_name)
            skill_instance = skill_class()

            self.skills[skill_name] = skill_instance
            self._loaded_skills.add(skill_name)
            logger.debug("Skill loaded on-demand", skill=skill_name)
            return skill_instance
        except Exception as e:
            logger.error("Failed to load skill", skill=skill_name, error=str(e))
            return None
        finally:
            self._loading_skills.discard(skill_name)
            event.set()

    async def _register_skill(self, skill: BaseSkill) -> None:
        """Registra un skill en el manager"""
        self.skills[skill.name] = skill
        logger.debug("Skill registered", skill=skill.name)

    async def execute_skill(
        self,
        skill_name: str,
        action: str,
        params: dict
    ) -> SkillResult:
        """Ejecuta una acción de un skill con carga lazy"""

        if self._lazy_mode and skill_name not in self._loaded_skills:
            logger.debug("Loading skill on-demand", skill=skill_name)
            await self._load_skill(skill_name)

        if skill_name not in self.skills:
            return SkillResult(
                success=False,
                error=f"Skill no encontrado: {skill_name}"
            )

        skill = self.skills[skill_name]

        # Validar parámetros
        if not await skill.validate_params(action, params):
            return SkillResult(
                success=False,
                error=f"Parámetros inválidos para {action}"
            )

        # Ejecutar
        try:
            result = await skill.execute(action, params)
            return result
        except Exception as e:
            logger.error("Skill execution failed", skill=skill_name, action=action, error=str(e))
            return SkillResult(
                success=False,
                error=str(e)
            )

    def get_skill(self, name: str) -> Optional[BaseSkill]:
        """Obtiene un skill por nombre (sin carga lazy)"""
        return self.skills.get(name)

    async def get_skill_lazy(self, name: str) -> Optional[BaseSkill]:
        """Obtiene un skill por nombre con carga lazy"""
        if name not in self._loaded_skills:
            await self._load_skill(name)
        return self.skills.get(name)

    def get_loaded_skills(self) -> list[str]:
        """Retorna lista de skills cargados"""
        return list(self._loaded_skills)

    def get_available_skills(self) -> list[str]:
        """Retorna lista de skills disponibles (sin cargar)"""
        return list(SKILL_REGISTRY.keys())

    def list_skills(self) -> list[dict]:
        """Lista todos los skills disponibles (cargados y no cargados)"""
        result = []
        for skill_name in SKILL_REGISTRY:
            if skill_name in self.skills:
                s = self.skills[skill_name]
                result.append({
                    "name": s.name,
                    "description": s.description,
                    "category": s.category,
                    "risk_level": s.risk_level.value,
                    "actions": s.get_available_actions(),
                    "loaded": True,
                })
            else:
                result.append({
                    "name": skill_name,
                    "description": f"Skill: {skill_name}",
                    "category": skill_name,
                    "risk_level": 0,
                    "actions": [],
                    "loaded": False,
                })
        return result
