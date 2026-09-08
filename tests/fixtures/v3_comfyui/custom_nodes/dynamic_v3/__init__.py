from comfy_api.latest import ComfyExtension


class DynamicExtension(ComfyExtension):
    async def get_node_list(self):
        return discover_nodes()


async def comfy_entrypoint():
    return DynamicExtension()
