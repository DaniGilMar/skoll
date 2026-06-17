from skoll_agent.config.skill_registry import register_skill
from skoll_agent.skills.code_analysis_skill import CodeAnalysisSkill
from skoll_agent.skills.engine_skill import EngineSkill

register_skill("code_analysis", CodeAnalysisSkill)
register_skill("tool_runner", EngineSkill)

__version__ = "0.1.0"
