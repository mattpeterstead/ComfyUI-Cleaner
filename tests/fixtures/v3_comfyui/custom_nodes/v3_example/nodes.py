from comfy_api.latest import io


class V3Example(io.ComfyNode):
    @classmethod
    def define_schema(cls):
        return io.Schema(node_id="CleanerV3Example")
