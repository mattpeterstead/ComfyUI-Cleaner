import importlib
import subprocess

image_module = importlib.import_module("PIL.Image")
yaml_module = __import__("yaml")
run_pip("installer-only>=1")
subprocess.run(["external-tool", "--version"])
