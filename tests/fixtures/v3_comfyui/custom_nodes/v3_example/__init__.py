from .nodes import V3Example

from comfy_api.latest import ComfyExtension


class V3ExampleExtension(ComfyExtension):
    async def get_node_list(self):
        return [V3Example]


async def comfy_entrypoint():
    return V3ExampleExtension()
