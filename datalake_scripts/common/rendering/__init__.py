from datalake.common.output_mode import rich_output_enabled
from datalake_scripts.common.rendering.base import Progress, Renderer
from datalake_scripts.common.rendering.rich_renderer import RichRenderer
from datalake_scripts.common.rendering.simple_renderer import SimpleRenderer


def get_renderer(dtl) -> Renderer:
    """Factory: the only place choosing between the rich and the simple output"""
    if rich_output_enabled():
        return RichRenderer(dtl.logger)
    return SimpleRenderer(dtl.logger, terminal_size=dtl.Threats.terminal_size)


__all__ = ["get_renderer", "Renderer", "Progress", "RichRenderer", "SimpleRenderer"]
