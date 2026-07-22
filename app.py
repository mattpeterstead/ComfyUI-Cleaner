from __future__ import annotations

import ast
import configparser
import datetime as dt
import html
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import uuid
import zipfile
import zlib
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any


APP_HOST = "127.0.0.1"
APP_PORT = int(os.environ.get("COMFYUI_CLEANER_PORT", "8765"))
DEFAULT_BACKUP_DIR = Path(__file__).resolve().parent / "backups"
BACKUP_PREFIX = "comfyui-cleaner-backup-"

SCAN_CACHE: dict[str, dict[str, Any]] = {}
SCAN_JOBS: dict[str, dict[str, Any]] = {}
SCAN_LOCK = threading.Lock()
PICKER_LOCK = threading.Lock()
ACTIVE_OPERATION: str | None = None
MAX_CACHED_SCANS = 20
MAX_SCAN_JOBS = 30
SCAN_JOB_TTL_SECONDS = 60 * 60
MAX_REQUEST_BODY_BYTES = 1024 * 1024

PROTECTED_DISTS = {
    "pip",
    "setuptools",
    "wheel",
}

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "venv",
    ".venv",
    "env",
    ".env",
    "models",
    "output",
    "input",
    "temp",
    "user",
}
CUSTOM_NODE_IGNORED_DIRS = IGNORED_DIRS.difference({"models", "output", "input", "temp", "user"})


def norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def clean_req_name(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    egg_match = re.search(r"[#&]egg=([A-Za-z0-9_.-]+)", line)
    if egg_match:
        return norm_name(egg_match.group(1))

    if line.startswith(("-e ", "--editable ")):
        line = line.split(maxsplit=1)[1].strip()
    elif line.startswith("-"):
        return None

    line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
    if not line:
        return None

    if " @ " in line:
        return norm_name(line.split(" @ ", 1)[0])

    line = line.split(";", 1)[0].strip()
    match = re.match(r"([A-Za-z0-9_.-]+)", line)
    if not match:
        return None
    return norm_name(match.group(1))


def parse_requires_dist(requirement: str) -> str | None:
    requirement = requirement.strip()
    match = re.match(r"([A-Za-z0-9_.-]+)", requirement)
    if not match:
        return None
    return norm_name(match.group(1))


def safe_resolve(path: str) -> Path:
    return Path(path).expanduser().resolve()


def format_log_time(started_at: float) -> str:
    elapsed = max(0.0, time.time() - started_at)
    minutes, seconds = divmod(int(elapsed), 60)
    return f"{minutes:02d}:{seconds:02d}"


def update_scan_job(
    job_id: str,
    *,
    progress: float | None = None,
    phase: str | None = None,
    message: str | None = None,
    status: str | None = None,
    result: dict[str, Any] | None = None,
    error: str | None = None,
    append_log: bool = True,
) -> None:
    with SCAN_LOCK:
        job = SCAN_JOBS.get(job_id)
        if not job:
            return

        if progress is not None:
            job["progress"] = max(0.0, min(100.0, float(progress)))
        if phase is not None:
            job["phase"] = phase
        if message is not None:
            job["message"] = message
        if status is not None:
            job["status"] = status
        if result is not None:
            job["result"] = result
        if error is not None:
            job["error"] = error

        job["updated_at"] = time.time()
        elapsed = job["updated_at"] - job["started_at"]
        job["elapsed_seconds"] = elapsed
        progress_value = job.get("progress") or 0.0
        if progress_value >= 100:
            job["eta_seconds"] = 0.0
        elif 0 < progress_value < 100 and elapsed > 1:
            job["eta_seconds"] = max(0.0, elapsed * (100.0 - progress_value) / progress_value)
        else:
            job["eta_seconds"] = None

        if append_log and message:
            log = job.setdefault("log", [])
            entry = {
                "time": format_log_time(job["started_at"]),
                "phase": job.get("phase", ""),
                "message": message,
                "progress": round(job.get("progress", 0.0), 1),
            }
            if not log or log[-1]["message"] != message:
                log.append(entry)
            del log[:-80]


def scan_job_snapshot(job_id: str) -> dict[str, Any] | None:
    with SCAN_LOCK:
        job = SCAN_JOBS.get(job_id)
        if not job:
            return None
        snapshot = dict(job)
        snapshot["log"] = list(job.get("log", []))
        return snapshot


def prune_scan_state_locked(now: float | None = None) -> None:
    current_time = now or time.time()
    expired_job_ids = [
        job_id
        for job_id, job in SCAN_JOBS.items()
        if job.get("status") != "running"
        and current_time - float(job.get("updated_at") or current_time) > SCAN_JOB_TTL_SECONDS
    ]
    for job_id in expired_job_ids:
        SCAN_JOBS.pop(job_id, None)

    if len(SCAN_JOBS) > MAX_SCAN_JOBS:
        completed_jobs = sorted(
            (
                (job_id, float(job.get("updated_at") or 0))
                for job_id, job in SCAN_JOBS.items()
                if job.get("status") != "running"
            ),
            key=lambda item: item[1],
        )
        for job_id, _ in completed_jobs[: max(0, len(SCAN_JOBS) - MAX_SCAN_JOBS)]:
            SCAN_JOBS.pop(job_id, None)

    while len(SCAN_CACHE) > MAX_CACHED_SCANS:
        oldest_scan_id = next(iter(SCAN_CACHE))
        SCAN_CACHE.pop(oldest_scan_id, None)


def begin_exclusive_operation(operation: str) -> str | None:
    global ACTIVE_OPERATION
    with SCAN_LOCK:
        if ACTIVE_OPERATION:
            return f"{ACTIVE_OPERATION} is already running."
        if any(job.get("status") == "running" for job in SCAN_JOBS.values()):
            return f"Wait for the active scan to finish before starting {operation.lower()}."
        ACTIVE_OPERATION = operation
    return None


def end_exclusive_operation() -> None:
    global ACTIVE_OPERATION
    with SCAN_LOCK:
        ACTIVE_OPERATION = None


def begin_cleanup() -> str | None:
    return begin_exclusive_operation("Cleanup")


def end_cleanup() -> None:
    end_exclusive_operation()


def shutdown_block_reason() -> str | None:
    with SCAN_LOCK:
        if ACTIVE_OPERATION:
            return f"{ACTIVE_OPERATION} is still running. Wait for it to finish before shutting down."
        if any(job.get("status") == "running" for job in SCAN_JOBS.values()):
            return "A scan is still running. Wait for it to finish before shutting down."
    return None


def start_scan_job(comfyui_path: str, venv_path: str, workflows_path: str) -> dict[str, Any]:
    job_id = str(uuid.uuid4())
    now = time.time()
    with SCAN_LOCK:
        prune_scan_state_locked(now)
        if ACTIVE_OPERATION:
            return {"ok": False, "error": f"{ACTIVE_OPERATION} is running. Wait for it to finish before scanning."}
        if any(job.get("status") == "running" for job in SCAN_JOBS.values()):
            return {"ok": False, "error": "A scan is already running."}
        SCAN_JOBS[job_id] = {
            "job_id": job_id,
            "status": "running",
            "phase": "Queued",
            "message": "Scan queued.",
            "progress": 0.0,
            "started_at": now,
            "updated_at": now,
            "elapsed_seconds": 0.0,
            "eta_seconds": None,
            "log": [],
            "result": None,
            "error": None,
        }

    def worker() -> None:
        try:
            update_scan_job(job_id, progress=1, phase="Starting", message="Starting scan.")
            result = run_scan(comfyui_path, venv_path, workflows_path, job_id=job_id)
            update_scan_job(
                job_id,
                progress=100,
                phase="Complete",
                message="Scan complete.",
                status="complete",
                result=result,
            )
        except Exception as exc:
            update_scan_job(
                job_id,
                phase="Error",
                message=f"Scan failed: {exc}",
                status="error",
                error=str(exc),
            )

    thread = threading.Thread(target=worker, name=f"scan-{job_id}", daemon=True)
    thread.start()
    return scan_job_snapshot(job_id) or {"job_id": job_id, "status": "running"}


def pick_local_path(title: str, initial_path_raw: str = "") -> dict[str, Any]:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as exc:
        return {"ok": False, "error": f"Could not open the system picker dialog: {exc}"}

    initial_path = Path(initial_path_raw).expanduser() if initial_path_raw else Path.cwd()
    if initial_path.is_file():
        initial_path = initial_path.parent
    if not initial_path.exists():
        initial_path = Path.cwd()

    with PICKER_LOCK:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        root.update()
        try:
            selected = filedialog.askdirectory(
                parent=root,
                title=title or "Select folder",
                initialdir=str(initial_path),
                mustexist=True,
            )
        finally:
            root.destroy()

    return {"ok": True, "path": selected or "", "cancelled": not bool(selected)}


def default_paths_for_comfy(comfyui_path_raw: str) -> dict[str, Any]:
    if not comfyui_path_raw.strip():
        return {"ok": False, "error": "ComfyUI path is missing."}

    comfyui_path = safe_resolve(comfyui_path_raw)
    workflows_path = comfyui_path / "user" / "default" / "workflows"

    venv_candidates = [
        comfyui_path / "venv",
        comfyui_path / ".venv",
        comfyui_path.parent / "venv",
        comfyui_path.parent / ".venv",
    ]

    found_venv = None
    checked: list[str] = []
    for candidate in venv_candidates:
        checked.append(str(candidate))
        if find_venv_python(candidate):
            found_venv = candidate
            break

    return {
        "ok": True,
        "comfyui_path": str(comfyui_path),
        "workflows_path": str(workflows_path),
        "venv_path": str(found_venv) if found_venv else "",
        "venv_found": found_venv is not None,
        "venv_candidates_checked": checked,
    }


def iter_py_files(
    root: Path,
    *,
    exclude_custom_nodes: bool = False,
    ignored_dirs: set[str] | None = None,
) -> list[Path]:
    files: list[Path] = []
    if not root.exists():
        return files

    ignored = IGNORED_DIRS if ignored_dirs is None else ignored_dirs
    for current, dirs, names in os.walk(root):
        current_path = Path(current)
        dirs[:] = [
            d
            for d in dirs
            if d not in ignored
            and not d.endswith(".egg-info")
            and not d.endswith(".dist-info")
            and not (exclude_custom_nodes and current_path == root and d == "custom_nodes")
        ]
        for name in names:
            if name.endswith(".py"):
                files.append(current_path / name)
    return files


@dataclass
class PythonFileAnalysis:
    imports: set[str] = field(default_factory=set)
    node_types: set[str] = field(default_factory=set)
    class_names: set[str] = field(default_factory=set)
    mapping_declared: bool = False
    mapping_complete: bool = True
    parse_ok: bool = True
    evidence: set[str] = field(default_factory=set)
    declared_requirements: set[str] = field(default_factory=set)
    invoked_commands: set[str] = field(default_factory=set)
    usage_uncertain: bool = False


def static_string(value: ast.AST | None) -> str | None:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return None


def static_mapping_keys(
    value: ast.AST | None,
    known_mappings: dict[str, tuple[set[str], bool]],
) -> tuple[set[str], bool]:
    if isinstance(value, ast.Name):
        keys, complete = known_mappings.get(value.id, (set(), False))
        return set(keys), complete
    if isinstance(value, ast.Dict):
        keys: set[str] = set()
        complete = True
        for key, item_value in zip(value.keys, value.values):
            if key is None:
                spread_keys, spread_complete = static_mapping_keys(item_value, known_mappings)
                keys.update(spread_keys)
                complete = complete and spread_complete
                continue
            text = static_string(key)
            if text is None:
                complete = False
            else:
                keys.add(text)
        return keys, complete
    if isinstance(value, ast.BinOp) and isinstance(value.op, ast.BitOr):
        left_keys, left_complete = static_mapping_keys(value.left, known_mappings)
        right_keys, right_complete = static_mapping_keys(value.right, known_mappings)
        return left_keys.union(right_keys), left_complete and right_complete
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "dict":
        keys: set[str] = set()
        complete = True
        for argument in value.args:
            argument_keys, argument_complete = static_mapping_keys(argument, known_mappings)
            keys.update(argument_keys)
            complete = complete and argument_complete
        for keyword in value.keywords:
            if keyword.arg is None:
                keyword_keys, keyword_complete = static_mapping_keys(keyword.value, known_mappings)
                keys.update(keyword_keys)
                complete = complete and keyword_complete
            else:
                keys.add(keyword.arg)
        return keys, complete
    return set(), False


def call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = [node.func.attr]
        value = node.func.value
        while isinstance(value, ast.Attribute):
            parts.append(value.attr)
            value = value.value
        if isinstance(value, ast.Name):
            parts.append(value.id)
        return ".".join(reversed(parts))
    return ""


def static_command_tokens(value: ast.AST | None) -> list[str]:
    if isinstance(value, (ast.List, ast.Tuple)):
        return [text for item in value.elts if (text := static_string(item)) is not None]
    text = static_string(value)
    if text is None:
        return []
    try:
        return shlex.split(text, posix=False)
    except ValueError:
        return text.split()


def parse_python_file(path: Path) -> PythonFileAnalysis:
    result = PythonFileAnalysis()
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source)
    except Exception:
        result.parse_ok = False
        result.mapping_complete = False
        return result

    known_mappings: dict[str, tuple[set[str], bool]] = {}
    for statement in tree.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            keys, complete = static_mapping_keys(statement.value, known_mappings)
            for target in targets:
                if isinstance(target, ast.Name):
                    known_mappings[target.id] = (set(keys), complete)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".", 1)[0]
                if top:
                    result.imports.add(top)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                top = node.module.split(".", 1)[0]
                if top:
                    result.imports.add(top)
            if any(alias.name == "NODE_CLASS_MAPPINGS" for alias in node.names):
                result.mapping_declared = True
                if node.level == 0:
                    result.mapping_complete = False
                    result.evidence.add("absolute NODE_CLASS_MAPPINGS import could not be resolved")
                else:
                    result.evidence.add("local NODE_CLASS_MAPPINGS import")
        elif isinstance(node, ast.ClassDef):
            result.class_names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                if isinstance(target, ast.Name) and target.id == "NODE_CLASS_MAPPINGS":
                    result.mapping_declared = True
                    keys, complete = static_mapping_keys(value, known_mappings)
                    result.node_types.update(keys)
                    result.mapping_complete = result.mapping_complete and complete
                    result.evidence.add("static NODE_CLASS_MAPPINGS assignment" if complete else "dynamic NODE_CLASS_MAPPINGS assignment")
                elif (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "NODE_CLASS_MAPPINGS"
                ):
                    result.mapping_declared = True
                    key = static_string(target.slice)
                    if key is None:
                        result.mapping_complete = False
                        result.evidence.add("dynamic NODE_CLASS_MAPPINGS key")
                    else:
                        result.node_types.add(key)
                        result.evidence.add("static NODE_CLASS_MAPPINGS key assignment")
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == "NODE_CLASS_MAPPINGS":
            result.mapping_declared = True
            keys, complete = static_mapping_keys(node.value, known_mappings)
            result.node_types.update(keys)
            result.mapping_complete = result.mapping_complete and complete and isinstance(node.op, ast.BitOr)
            result.evidence.add("NODE_CLASS_MAPPINGS merge")
        elif isinstance(node, ast.Call):
            name = call_name(node)
            if name in {"__import__", "importlib.import_module", "importlib.util.find_spec", "pkgutil.resolve_name"} and node.args:
                imported = static_string(node.args[0])
                if imported:
                    result.imports.add(imported.split(".", 1)[0])
                    result.evidence.add("literal dynamic import")
                else:
                    result.usage_uncertain = True
                    result.evidence.add("non-literal dynamic import")
            if node.args and name.split(".")[-1] in {"run", "Popen", "call", "check_call", "check_output", "system", "run_pip", "pip_install"}:
                tokens = static_command_tokens(node.args[0])
                if not tokens and name in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "os.system"}:
                    result.usage_uncertain = True
                    result.evidence.add("non-literal subprocess command")
                if tokens and name in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "os.system"}:
                    command = Path(tokens[0].strip("'\"")).stem.lower()
                    if command and command not in {"python", "python3", "py", "pip", "pip3"}:
                        result.invoked_commands.add(command)
                        result.evidence.add("literal subprocess command")
                if "-m" in tokens:
                    module_index = tokens.index("-m") + 1
                    if module_index < len(tokens) and tokens[module_index] != "pip":
                        result.imports.add(tokens[module_index].split(".", 1)[0])
                        result.evidence.add("literal Python -m invocation")
                installer_helper = name.split(".")[-1] in {"run_pip", "pip_install"}
                if ("install" in tokens and "pip" in tokens) or installer_helper:
                    requirement_tokens = tokens[tokens.index("install") + 1:] if "install" in tokens else tokens
                    for token in requirement_tokens:
                        requirement = clean_req_name(token.strip("'\""))
                        if requirement:
                            result.declared_requirements.add(requirement)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "update":
                owner = node.func.value
                if isinstance(owner, ast.Name) and owner.id == "NODE_CLASS_MAPPINGS":
                    result.mapping_declared = True
                    if node.args:
                        keys, complete = static_mapping_keys(node.args[0], known_mappings)
                        result.node_types.update(keys)
                        result.mapping_complete = result.mapping_complete and complete
                    else:
                        complete = not any(keyword.arg is None for keyword in node.keywords)
                        result.node_types.update(keyword.arg for keyword in node.keywords if keyword.arg)
                        result.mapping_complete = result.mapping_complete and complete
                    result.evidence.add("static NODE_CLASS_MAPPINGS update" if complete else "dynamic NODE_CLASS_MAPPINGS update")

    return result


def collect_python_usage(
    paths: list[Path],
    progress_callback: Any | None = None,
    progress_start: float = 55,
    progress_end: float = 68,
) -> tuple[set[str], set[str], set[str], bool]:
    imports: set[str] = set()
    declared_requirements: set[str] = set()
    invoked_commands: set[str] = set()
    usage_uncertain = False
    total = max(1, len(paths))
    for index, path in enumerate(paths, start=1):
        analysis = parse_python_file(path)
        imports.update(analysis.imports)
        declared_requirements.update(analysis.declared_requirements)
        invoked_commands.update(analysis.invoked_commands)
        usage_uncertain = usage_uncertain or analysis.usage_uncertain or not analysis.parse_ok
        if progress_callback and (index == total or index == 1 or index % 50 == 0):
            progress = progress_start + (progress_end - progress_start) * (index / total)
            progress_callback(progress, "ComfyUI core", f"Scanned imports from {index}/{total} Python file(s).")
    return imports, declared_requirements, invoked_commands, usage_uncertain


def collect_imports(
    paths: list[Path],
    progress_callback: Any | None = None,
    progress_start: float = 55,
    progress_end: float = 68,
) -> set[str]:
    imports, _, _, _ = collect_python_usage(paths, progress_callback, progress_start, progress_end)
    return imports


def requirement_names(values: Any) -> set[str]:
    if isinstance(values, str):
        values = values.splitlines()
    if not isinstance(values, (list, tuple, set)):
        return set()
    result: set[str] = set()
    for value in values:
        if isinstance(value, str):
            name = clean_req_name(value)
            if name:
                result.add(name)
    return result


def requirements_from_file(path: Path, seen: set[Path] | None = None) -> set[str]:
    seen = seen or set()
    try:
        resolved = path.resolve()
    except OSError:
        return set()
    if resolved in seen or not resolved.is_file():
        return set()
    seen.add(resolved)
    result: set[str] = set()
    try:
        lines = resolved.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return result
    for line in lines:
        stripped = line.strip()
        include_match = re.match(r"^(?:-r|--requirement)\s+(.+)$", stripped)
        if include_match:
            result.update(requirements_from_file(resolved.parent / include_match.group(1).strip(), seen))
            continue
        name = clean_req_name(stripped)
        if name:
            result.add(name)
    return result


def pyproject_requirements(path: Path) -> set[str]:
    try:
        import tomllib

        data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return set()
    result = requirement_names((data.get("project") or {}).get("dependencies") or [])
    for values in ((data.get("project") or {}).get("optional-dependencies") or {}).values():
        result.update(requirement_names(values))
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for name in (poetry.get("dependencies") or {}):
        if norm_name(str(name)) != "python":
            result.add(norm_name(str(name)))
    for group in (poetry.get("group") or {}).values():
        for name in ((group or {}).get("dependencies") or {}):
            if norm_name(str(name)) != "python":
                result.add(norm_name(str(name)))
    return result


def setup_cfg_requirements(path: Path) -> set[str]:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return set()
    result = requirement_names(parser.get("options", "install_requires", fallback=""))
    if parser.has_section("options.extras_require"):
        for _, values in parser.items("options.extras_require"):
            result.update(requirement_names(values))
    return result


def ast_literal_strings(
    value: ast.AST | None,
    known_values: dict[str, list[str]] | None = None,
) -> list[str]:
    known_values = known_values or {}
    if isinstance(value, ast.Name):
        return list(known_values.get(value.id, []))
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return [value.value]
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return [text for item in value.elts for text in ast_literal_strings(item, known_values)]
    if isinstance(value, ast.Dict):
        return [text for item in value.values for text in ast_literal_strings(item, known_values)]
    if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
        return ast_literal_strings(value.left, known_values) + ast_literal_strings(value.right, known_values)
    return []


def setup_py_requirements(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return set()
    result: set[str] = set()
    known_values: dict[str, list[str]] = {}
    for statement in tree.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            values = ast_literal_strings(statement.value, known_values)
            for target in targets:
                if isinstance(target, ast.Name) and values:
                    known_values[target.id] = values
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or call_name(node).split(".")[-1] != "setup":
            continue
        for keyword in node.keywords:
            if keyword.arg in {"install_requires", "extras_require", "tests_require", "setup_requires"}:
                result.update(requirement_names(ast_literal_strings(keyword.value, known_values)))
    return result


def collect_requirements(
    root: Path,
    *,
    exclude_custom_nodes: bool = False,
    ignored_dirs: set[str] | None = None,
) -> set[str]:
    reqs: set[str] = set()
    if not root.exists() or root.is_file():
        return reqs

    ignored = IGNORED_DIRS if ignored_dirs is None else ignored_dirs
    for current, dirs, names in os.walk(root):
        current_path = Path(current)
        dirs[:] = [
            d
            for d in dirs
            if d not in ignored
            and not d.endswith(".egg-info")
            and not d.endswith(".dist-info")
            and not (exclude_custom_nodes and current_path == root and d == "custom_nodes")
        ]
        for name in names:
            lowered = name.lower()
            path = current_path / name
            if lowered == "requirements.txt" or (
                lowered.startswith("requirements") and lowered.endswith(".txt")
            ):
                reqs.update(requirements_from_file(path))
            elif lowered == "pyproject.toml":
                reqs.update(pyproject_requirements(path))
            elif lowered in {"setup.cfg", "tox.ini"}:
                reqs.update(setup_cfg_requirements(path))
            elif lowered == "setup.py":
                reqs.update(setup_py_requirements(path))
    return reqs


def extract_workflow_node_types(obj: Any) -> set[str]:
    found: set[str] = set()

    if isinstance(obj, dict):
        class_type = obj.get("class_type")
        if isinstance(class_type, str) and class_type:
            found.add(class_type)

        nodes = obj.get("nodes")
        if isinstance(nodes, list):
            for item in nodes:
                if isinstance(item, dict):
                    node_type = item.get("type")
                    if isinstance(node_type, str) and node_type:
                        found.add(node_type)

        for value in obj.values():
            found.update(extract_workflow_node_types(value))
    elif isinstance(obj, list):
        for item in obj:
            found.update(extract_workflow_node_types(item))

    return found


def png_text_metadata(path: Path) -> dict[str, str]:
    metadata: dict[str, str] = {}
    try:
        with path.open("rb") as handle:
            if handle.read(8) != b"\x89PNG\r\n\x1a\n":
                return metadata
            while True:
                length_raw = handle.read(4)
                if len(length_raw) != 4:
                    break
                length = struct.unpack(">I", length_raw)[0]
                chunk_type = handle.read(4)
                if length > 32 * 1024 * 1024:
                    handle.seek(length + 4, os.SEEK_CUR)
                    continue
                data = handle.read(length)
                handle.read(4)
                if chunk_type == b"IEND":
                    break
                if chunk_type == b"tEXt" and b"\0" in data:
                    key, value = data.split(b"\0", 1)
                    metadata[key.decode("latin-1", errors="ignore")] = value.decode("utf-8", errors="ignore")
                elif chunk_type == b"zTXt" and b"\0" in data:
                    key, compressed = data.split(b"\0", 1)
                    if compressed[:1] == b"\0":
                        value = zlib.decompressobj().decompress(compressed[1:], 32 * 1024 * 1024)
                        metadata[key.decode("latin-1", errors="ignore")] = value.decode("utf-8", errors="ignore")
                elif chunk_type == b"iTXt" and b"\0" in data:
                    key, remainder = data.split(b"\0", 1)
                    if len(remainder) < 2:
                        continue
                    compressed = remainder[0] == 1
                    remainder = remainder[2:]
                    parts = remainder.split(b"\0", 2)
                    if len(parts) != 3:
                        continue
                    value = parts[2]
                    if compressed:
                        value = zlib.decompressobj().decompress(value, 32 * 1024 * 1024)
                    metadata[key.decode("latin-1", errors="ignore")] = value.decode("utf-8", errors="ignore")
    except Exception:
        return metadata
    return metadata


def read_workflow_documents(path: Path) -> tuple[list[Any], bool]:
    if path.suffix.lower() == ".json":
        return [json.loads(path.read_text(encoding="utf-8", errors="ignore"))], False
    if path.suffix.lower() == ".png":
        documents: list[Any] = []
        invalid_metadata = False
        metadata = png_text_metadata(path)
        for key, value in metadata.items():
            if key.lower() not in {"workflow", "prompt"}:
                continue
            try:
                documents.append(json.loads(value))
            except Exception:
                invalid_metadata = True
        return documents, invalid_metadata
    return [], False


def workflow_documents(path: Path) -> list[Any]:
    documents, _ = read_workflow_documents(path)
    return documents


def scan_workflows(
    workflows_path: Path,
    progress_callback: Any | None = None,
    progress_start: float = 10,
    progress_end: float = 30,
) -> dict[str, Any]:
    result = {
        "path": str(workflows_path),
        "files_scanned": 0,
        "files_failed": 0,
        "files_skipped": 0,
        "node_types": set(),
        "examples": [],
    }
    if not workflows_path.exists():
        return result

    workflow_files = (
        [workflows_path]
        if workflows_path.is_file()
        else sorted(
            (path for path in workflows_path.rglob("*") if path.suffix.lower() in {".json", ".png"}),
            key=lambda path: str(path).lower(),
        )
    )
    total = max(1, len(workflow_files))
    if progress_callback:
        progress_callback(progress_start, "Workflows", f"Found {len(workflow_files)} JSON or PNG workflow file(s).")
    for index, file_path in enumerate(workflow_files, start=1):
        try:
            documents, invalid_metadata = read_workflow_documents(file_path)
            if invalid_metadata:
                result["files_failed"] += 1
            elif not documents:
                result["files_skipped"] += 1
            else:
                node_types: set[str] = set()
                for document in documents:
                    node_types.update(extract_workflow_node_types(document))
                result["node_types"].update(node_types)
                result["files_scanned"] += 1
                if node_types and len(result["examples"]) < 20:
                    result["examples"].append(
                        {
                            "file": str(file_path),
                            "node_types": sorted(node_types)[:20],
                        }
                    )
        except Exception:
            result["files_failed"] += 1
        if progress_callback and (index == total or index == 1 or index % 10 == 0):
            progress = progress_start + (progress_end - progress_start) * (index / total)
            progress_callback(
                progress,
                "Workflows",
                f"Scanned {index}/{total} workflow file(s).",
            )

    return result


@dataclass
class CustomNodePackage:
    name: str
    path: str
    status: str
    node_types: set[str] = field(default_factory=set)
    matched_node_types: set[str] = field(default_factory=set)
    imports: set[str] = field(default_factory=set)
    requirements: set[str] = field(default_factory=set)
    required_dists: set[str] = field(default_factory=set)
    mapping_complete: bool = False
    confidence: str = "low"
    evidence: list[str] = field(default_factory=list)
    analysis_warnings: list[str] = field(default_factory=list)
    source_kind: str = "directory"
    invoked_commands: set[str] = field(default_factory=set)
    usage_uncertain: bool = False


def standalone_node_requirements(path: Path) -> set[str]:
    result: set[str] = set()
    for candidate in (
        path.with_name(f"{path.stem}_requirements.txt"),
        path.with_name(f"{path.stem}.requirements.txt"),
    ):
        result.update(requirements_from_file(candidate))
    return result


def scan_custom_nodes(
    custom_nodes_dir: Path,
    workflow_node_types: set[str],
    workflow_scan_complete: bool = True,
    progress_callback: Any | None = None,
    progress_start: float = 30,
    progress_end: float = 55,
) -> list[CustomNodePackage]:
    packages: list[CustomNodePackage] = []
    if not custom_nodes_dir.exists():
        return packages

    children = [
        child
        for child in sorted(custom_nodes_dir.iterdir(), key=lambda p: p.name.lower())
        if not child.name.startswith(".")
        and child.name != "_comfyui_cleaner_removed"
        and (child.is_dir() or (child.is_file() and child.suffix.lower() == ".py" and child.name != "__init__.py"))
    ]
    total = max(1, len(children))
    if progress_callback:
        progress_callback(progress_start, "Custom nodes", f"Found {len(children)} custom node package(s) or standalone file(s).")

    for index, child in enumerate(children, start=1):
        py_files = iter_py_files(child, ignored_dirs=CUSTOM_NODE_IGNORED_DIRS) if child.is_dir() else [child]
        imports: set[str] = set()
        node_types: set[str] = set()
        fallback_classes: set[str] = set()
        mapping_declared = False
        mapping_complete = True
        parse_failures: list[str] = []
        evidence: set[str] = set()
        source_requirements: set[str] = set()
        invoked_commands: set[str] = set()
        usage_uncertain = False
        for file_path in py_files:
            analysis = parse_python_file(file_path)
            imports.update(analysis.imports)
            node_types.update(analysis.node_types)
            fallback_classes.update(analysis.class_names)
            mapping_declared = mapping_declared or analysis.mapping_declared
            if analysis.mapping_declared:
                mapping_complete = mapping_complete and analysis.mapping_complete
            if not analysis.parse_ok:
                parse_failures.append(str(file_path))
            evidence.update(analysis.evidence)
            source_requirements.update(analysis.declared_requirements)
            invoked_commands.update(analysis.invoked_commands)
            usage_uncertain = usage_uncertain or analysis.usage_uncertain or not analysis.parse_ok

        if parse_failures:
            mapping_complete = False
        mapped_matches = node_types.intersection(workflow_node_types)
        fallback_matches = fallback_classes.intersection(workflow_node_types)
        if mapped_matches:
            status = "used"
            confidence = "high"
            matched = mapped_matches
            evidence.add("workflow node type matched a declared mapping")
        elif fallback_matches:
            status = "used"
            confidence = "medium"
            matched = fallback_matches
            evidence.add("workflow node type matched a Python class name")
        elif mapping_declared and mapping_complete and node_types and workflow_scan_complete:
            status = "unused"
            confidence = "high"
            matched = set()
            evidence.add("complete static mapping had no workflow matches")
        else:
            status = "unknown"
            confidence = "low"
            matched = set()
            if not mapping_declared:
                evidence.add("NODE_CLASS_MAPPINGS declaration was not found")
            elif not mapping_complete:
                evidence.add("NODE_CLASS_MAPPINGS could not be resolved completely")
            elif not workflow_scan_complete:
                evidence.add("one or more workflow files could not be read")

        requirements = (
            collect_requirements(child, ignored_dirs=CUSTOM_NODE_IGNORED_DIRS)
            if child.is_dir()
            else standalone_node_requirements(child)
        )
        requirements.update(source_requirements)

        packages.append(
            CustomNodePackage(
                name=child.name if child.is_dir() else child.stem,
                path=str(child),
                status=status,
                node_types=set(node_types),
                matched_node_types=set(matched),
                imports=imports,
                requirements=requirements,
                mapping_complete=mapping_declared and mapping_complete,
                confidence=confidence,
                evidence=sorted(evidence),
                analysis_warnings=[f"Could not parse {path}" for path in parse_failures],
                source_kind="directory" if child.is_dir() else "standalone_python",
                invoked_commands=invoked_commands,
                usage_uncertain=usage_uncertain,
            )
        )
        if progress_callback and (index == total or index == 1 or index % 3 == 0):
            progress = progress_start + (progress_end - progress_start) * (index / total)
            progress_callback(
                progress,
                "Custom nodes",
                f"Scanned {index}/{total} custom node package(s): {child.name}",
            )

    return packages


def find_venv_python(venv_path: Path) -> Path | None:
    candidates = [
        venv_path / "Scripts" / "python.exe",
        venv_path / "Scripts" / "python",
        venv_path / "bin" / "python",
        venv_path / "bin" / "python3",
    ]
    if venv_path.is_file() and venv_path.name.lower().startswith("python"):
        candidates.insert(0, venv_path)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def read_venv_distributions(venv_path: Path) -> dict[str, Any]:
    python_exe = find_venv_python(venv_path)
    if not python_exe:
        return {
            "ok": False,
            "error": "Could not find the virtual environment Python interpreter.",
            "python": None,
            "packages": {},
            "top_level_to_dists": {},
            "requires": {},
            "entry_point_groups": {},
            "startup_hook_dists": [],
            "console_scripts": {},
        }

    script = r"""
import importlib.metadata as im
import json

packages = {}
requires = {}
entry_point_groups = {}
startup_hook_dists = []
console_scripts = {}
for dist in im.distributions():
    name = dist.metadata.get("Name") or dist.metadata.get("Summary") or ""
    if not name:
        continue
    normalized = name.lower().replace("_", "-")
    packages[normalized] = {"name": name, "version": dist.version}
    requires[normalized] = list(dist.requires or [])
    entry_point_groups[normalized] = sorted({
        entry_point.group
        for entry_point in dist.entry_points
        if entry_point.group not in {"console_scripts", "gui_scripts"}
    })
    if any(str(path).lower().endswith(".pth") for path in (dist.files or [])):
        startup_hook_dists.append(normalized)
    for entry_point in dist.entry_points:
        if entry_point.group == "console_scripts":
            console_scripts.setdefault(entry_point.name.lower(), []).append(normalized)

top_level_to_dists = {}
try:
    for key, value in im.packages_distributions().items():
        top_level_to_dists[key] = value
except Exception:
    pass

print(json.dumps({
    "packages": packages,
    "requires": requires,
    "top_level_to_dists": top_level_to_dists,
    "entry_point_groups": entry_point_groups,
    "startup_hook_dists": startup_hook_dists,
    "console_scripts": console_scripts,
}, ensure_ascii=False))
"""
    try:
        proc = subprocess.run(
            [str(python_exe), "-c", script],
            text=True,
            capture_output=True,
            timeout=45,
        )
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Failed to read the virtual environment: {exc}",
            "python": str(python_exe),
            "packages": {},
            "top_level_to_dists": {},
            "requires": {},
            "entry_point_groups": {},
            "startup_hook_dists": [],
            "console_scripts": {},
        }

    if proc.returncode != 0:
        return {
            "ok": False,
            "error": proc.stderr.strip() or "Failed to read Python packages.",
            "python": str(python_exe),
            "packages": {},
            "top_level_to_dists": {},
            "requires": {},
            "entry_point_groups": {},
            "startup_hook_dists": [],
            "console_scripts": {},
        }

    try:
        data = json.loads(proc.stdout)
    except Exception:
        return {
            "ok": False,
            "error": "Could not parse the virtual environment response.",
            "python": str(python_exe),
            "packages": {},
            "top_level_to_dists": {},
            "requires": {},
            "entry_point_groups": {},
            "startup_hook_dists": [],
            "console_scripts": {},
        }

    packages = {norm_name(k): v for k, v in data.get("packages", {}).items()}
    requires = {norm_name(k): v for k, v in data.get("requires", {}).items()}
    entry_point_groups = {norm_name(k): v for k, v in data.get("entry_point_groups", {}).items()}
    top_level = data.get("top_level_to_dists", {})
    return {
        "ok": True,
        "error": None,
        "python": str(python_exe),
        "packages": packages,
        "top_level_to_dists": top_level,
        "requires": requires,
        "entry_point_groups": entry_point_groups,
        "startup_hook_dists": [norm_name(name) for name in data.get("startup_hook_dists", [])],
        "console_scripts": {
            str(command).lower(): [norm_name(name) for name in names]
            for command, names in data.get("console_scripts", {}).items()
        },
    }


def imports_to_dists(imports: set[str], venv_info: dict[str, Any]) -> set[str]:
    mapped: set[str] = set()
    top_level = venv_info.get("top_level_to_dists") or {}
    installed = set((venv_info.get("packages") or {}).keys())

    for import_name in imports:
        candidates = top_level.get(import_name, [])
        if candidates:
            mapped.update(norm_name(candidate) for candidate in candidates)
            continue
        guessed = norm_name(import_name)
        if guessed in installed:
            mapped.add(guessed)
    return mapped


def commands_to_dists(commands: set[str], venv_info: dict[str, Any]) -> set[str]:
    console_scripts = venv_info.get("console_scripts") or {}
    result: set[str] = set()
    for command in commands:
        result.update(norm_name(name) for name in console_scripts.get(command.lower(), []))
    return result


def dependency_closure(seeds: set[str], requires: dict[str, list[str]]) -> set[str]:
    closure: set[str] = set()
    queue = [norm_name(seed) for seed in seeds if seed]

    while queue:
        name = queue.pop()
        if name in closure:
            continue
        closure.add(name)
        for requirement in requires.get(name, []):
            dep = parse_requires_dist(requirement)
            if dep and dep not in closure:
                queue.append(dep)

    return closure


def summarize_python_packages(
    core_imports: set[str],
    core_requirements: set[str],
    custom_packages: list[CustomNodePackage],
    venv_info: dict[str, Any],
    core_invoked_commands: set[str] | None = None,
    core_usage_uncertain: bool = False,
) -> dict[str, Any]:
    installed: dict[str, dict[str, str]] = venv_info.get("packages") or {}
    requires: dict[str, list[str]] = venv_info.get("requires") or {}
    entry_point_groups: dict[str, list[str]] = venv_info.get("entry_point_groups") or {}
    startup_hook_dists = set(venv_info.get("startup_hook_dists") or [])

    core_dists = (
        imports_to_dists(core_imports, venv_info)
        .union(core_requirements)
        .union(commands_to_dists(core_invoked_commands or set(), venv_info))
    )
    for package in custom_packages:
        package.required_dists = (
            imports_to_dists(package.imports, venv_info)
            .union(package.requirements)
            .union(commands_to_dists(package.invoked_commands, venv_info))
        )

    active_usage_uncertain = core_usage_uncertain or any(
        package.usage_uncertain
        for package in custom_packages
        if package.status in {"used", "unknown"}
    )

    active_dists = set(core_dists)
    all_custom_dists: set[str] = set()
    unused_custom_dists: set[str] = set()
    for package in custom_packages:
        all_custom_dists.update(package.required_dists)
        if package.status in {"used", "unknown"}:
            active_dists.update(package.required_dists)
        elif package.status == "unused":
            unused_custom_dists.update(package.required_dists)

    all_known_dists = core_dists.union(all_custom_dists)
    active_closure = dependency_closure(active_dists, requires)
    all_known_closure = dependency_closure(all_known_dists, requires)

    installed_names = set(installed.keys())
    dynamic_plugin_dists = {
        name
        for name, groups in entry_point_groups.items()
        if groups
    }
    dynamically_loaded_dists = dynamic_plugin_dists.union(startup_hook_dists)
    no_detected_use = sorted(
        installed_names - all_known_closure - PROTECTED_DISTS - dynamically_loaded_dists,
        key=lambda name: installed[name]["name"].lower(),
    )
    only_unused_nodes = sorted(
        (dependency_closure(unused_custom_dists, requires) - active_closure)
        .intersection(installed_names)
        .difference(PROTECTED_DISTS)
        .difference(dynamically_loaded_dists),
        key=lambda name: installed[name]["name"].lower(),
    )
    unused_package_closures = {
        package.path: dependency_closure(package.required_dists, requires)
        for package in custom_packages
        if package.status == "unused"
    }

    return {
        "installed_count": len(installed),
        "core_required_count": len(core_dists),
        "known_required_count": len(all_known_closure),
        "active_required_count": len(active_closure),
        "protected_dynamic_plugin_count": len(dynamic_plugin_dists),
        "protected_startup_hook_count": len(startup_hook_dists),
        "active_usage_uncertain": active_usage_uncertain,
        "no_detected_use": [
            {
                "name": installed[name]["name"],
                "normalized_name": name,
                "version": installed[name].get("version", ""),
                "confidence": "review",
                "reason": "No use was found in literal imports, ComfyUI source, custom node source, dependency metadata, or supported project manifests.",
                "evidence": ["No detected static or declared dependency path"],
            }
            for name in no_detected_use
        ],
        "only_unused_custom_nodes": [
            {
                "name": installed[name]["name"],
                "normalized_name": name,
                "version": installed[name].get("version", ""),
                "confidence": "review" if active_usage_uncertain else "high",
                "reason": (
                    "Required only by custom node packages identified as unused, but unresolved dynamic loading exists in active code."
                    if active_usage_uncertain
                    else "Required only by custom node packages identified as unused."
                ),
                "evidence": [
                    "Known dependency closure leads only to high-confidence unused custom nodes",
                    *( ["Active code contains unresolved dynamic loading"] if active_usage_uncertain else [] ),
                ],
                "required_by_custom_nodes": [
                    package.name
                    for package in custom_packages
                    if package.status == "unused" and name in unused_package_closures.get(package.path, set())
                ],
                "required_by_custom_node_paths": [
                    package.path
                    for package in custom_packages
                    if package.status == "unused" and name in unused_package_closures.get(package.path, set())
                ],
            }
            for name in only_unused_nodes
        ],
    }


def run_scan(
    comfyui_path_raw: str,
    venv_path_raw: str,
    workflows_path_raw: str,
    *,
    job_id: str | None = None,
) -> dict[str, Any]:
    def progress(value: float, phase: str, message: str, append_log: bool = True) -> None:
        if job_id:
            update_scan_job(job_id, progress=value, phase=phase, message=message, append_log=append_log)

    progress(2, "Validating paths", "Resolving configured paths.")
    errors: list[str] = []
    warnings: list[str] = []

    comfyui_missing = not comfyui_path_raw.strip()
    venv_missing = not venv_path_raw.strip()
    workflows_missing = not workflows_path_raw.strip()

    if comfyui_missing:
        errors.append("ComfyUI installation path has not been set.")
    if venv_missing:
        errors.append("Virtual environment path has not been set.")
    if workflows_missing:
        errors.append("Workflows path has not been set.")

    if errors:
        return {
            "scan_id": str(uuid.uuid4()),
            "paths": {
                "comfyui": "",
                "custom_nodes": "",
                "venv": "",
                "venv_python": None,
                "workflows": "",
            },
            "errors": errors,
            "warnings": warnings,
            "workflow": {
                "files_scanned": 0,
                "files_failed": 0,
                "node_type_count": 0,
                "node_types": [],
                "examples": [],
            },
            "custom_nodes": [],
            "python_packages": {
                "installed_count": 0,
                "core_required_count": 0,
                "known_required_count": 0,
                "active_required_count": 0,
                "no_detected_use": [],
                "only_unused_custom_nodes": [],
            },
            "notes": ["Set all required paths before scanning."],
        }

    comfyui_path = safe_resolve(comfyui_path_raw)
    venv_path = safe_resolve(venv_path_raw)
    workflows_path = safe_resolve(workflows_path_raw)

    if not comfyui_path.exists():
        errors.append("ComfyUI path does not exist.")
    if not workflows_path.exists():
        errors.append("Workflows path does not exist.")
    if not venv_path.exists():
        errors.append("Virtual environment path does not exist.")

    if errors:
        return {
            "scan_id": str(uuid.uuid4()),
            "paths": {
                "comfyui": str(comfyui_path),
                "custom_nodes": str(comfyui_path / "custom_nodes"),
                "venv": str(venv_path),
                "venv_python": None,
                "workflows": str(workflows_path),
            },
            "errors": errors,
            "warnings": warnings,
            "workflow": {
                "files_scanned": 0,
                "files_failed": 0,
                "node_type_count": 0,
                "node_types": [],
                "examples": [],
            },
            "custom_nodes": [],
            "python_packages": {
                "installed_count": 0,
                "core_required_count": 0,
                "known_required_count": 0,
                "active_required_count": 0,
                "no_detected_use": [],
                "only_unused_custom_nodes": [],
            },
            "notes": ["Correct the invalid paths before scanning again."],
        }

    progress(8, "Workflows", "Scanning workflow JSON files and PNG metadata.")
    workflow_result = scan_workflows(workflows_path, progress_callback=progress, progress_start=10, progress_end=30)
    workflow_node_types = workflow_result["node_types"]

    custom_nodes_dir = comfyui_path / "custom_nodes"
    if not custom_nodes_dir.exists():
        warnings.append("ComfyUI/custom_nodes folder was not found.")
    progress(30, "Custom nodes", "Scanning installed custom node packages.")
    custom_packages = scan_custom_nodes(
        custom_nodes_dir,
        workflow_node_types,
        workflow_result["files_failed"] == 0,
        progress_callback=progress,
        progress_start=30,
        progress_end=55,
    )

    progress(55, "ComfyUI core", "Collecting ComfyUI Python files.")
    core_py_files = iter_py_files(comfyui_path, exclude_custom_nodes=True)
    progress(56, "ComfyUI core", f"Found {len(core_py_files)} ComfyUI Python file(s).")
    core_imports, core_source_requirements, core_invoked_commands, core_usage_uncertain = collect_python_usage(
        core_py_files,
        progress_callback=progress,
        progress_start=56,
        progress_end=68,
    )
    progress(69, "Requirements", "Reading requirements files.")
    core_requirements = collect_requirements(comfyui_path, exclude_custom_nodes=True)
    core_requirements.update(core_source_requirements)

    progress(75, "Virtual environment", "Reading installed Python packages and dependency metadata.")
    venv_info = read_venv_distributions(venv_path)
    if not venv_info["ok"]:
        warnings.append(venv_info["error"])

    progress(88, "Python packages", "Comparing installed Python packages with detected usage.")
    python_summary = summarize_python_packages(
        core_imports,
        core_requirements,
        custom_packages,
        venv_info,
        core_invoked_commands,
        core_usage_uncertain,
    )

    progress(96, "Finalizing", "Building scan report.")
    scan_id = str(uuid.uuid4())
    result = {
        "scan_id": scan_id,
        "paths": {
            "comfyui": str(comfyui_path),
            "custom_nodes": str(custom_nodes_dir),
            "venv": str(venv_path),
            "venv_python": venv_info.get("python"),
            "workflows": str(workflows_path),
        },
        "errors": errors,
        "warnings": warnings,
        "workflow": {
            "files_scanned": workflow_result["files_scanned"],
            "files_failed": workflow_result["files_failed"],
            "files_skipped": workflow_result.get("files_skipped", 0),
            "node_type_count": len(workflow_node_types),
            "node_types": sorted(workflow_node_types),
            "examples": workflow_result["examples"],
        },
        "custom_nodes": [
            {
                "name": package.name,
                "path": package.path,
                "status": package.status,
                "node_type_count": len(package.node_types),
                "node_types": sorted(package.node_types)[:50],
                "matched_node_types": sorted(package.matched_node_types),
                "required_python_packages": sorted(package.required_dists),
                "mapping_complete": package.mapping_complete,
                "confidence": package.confidence,
                "evidence": package.evidence,
                "analysis_warnings": package.analysis_warnings,
                "source_kind": package.source_kind,
                "usage_uncertain": package.usage_uncertain,
            }
            for package in custom_packages
        ],
        "python_packages": python_summary,
        "notes": [
            "Bypassed and muted nodes remain in workflow node lists and are counted as used.",
            "A custom node package is considered unused only when its NODE_CLASS_MAPPINGS can be resolved completely and none of the scanned workflows use those node types.",
            "Incomplete, dynamic, imported-from-unknown, or unparsable node mappings remain unknown and are never offered for removal.",
            "Python detection uses literal dynamic imports, requirements files, pyproject.toml, setup.cfg, setup.py, dependency metadata, and non-CLI entry-point protection.",
            *(
                ["Unresolved dynamic loading was found in active code, so affected Python package results are marked for review instead of high confidence."]
                if python_summary.get("active_usage_uncertain")
                else []
            ),
        ],
    }

    with SCAN_LOCK:
        SCAN_CACHE[scan_id] = result
        prune_scan_state_locked()
    return result


def move_custom_node_to_trash(path_raw: str, custom_nodes_root_raw: str) -> dict[str, Any]:
    source = safe_resolve(path_raw)
    custom_nodes_root = safe_resolve(custom_nodes_root_raw)
    try:
        source.relative_to(custom_nodes_root)
    except ValueError:
        return {"ok": False, "path": str(source), "error": "Path is not inside the custom_nodes folder."}

    if not source.exists() or not (source.is_dir() or source.is_file()):
        return {"ok": False, "path": str(source), "error": "Custom node path was not found."}

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    trash_root = custom_nodes_root.parent / "_comfyui_cleaner_removed" / stamp
    trash_root.mkdir(parents=True, exist_ok=True)
    target = trash_root / source.name
    suffix = 2
    while target.exists():
        target = trash_root / f"{source.name}-{suffix}"
        suffix += 1

    shutil.move(str(source), str(target))
    return {"ok": True, "path": str(source), "moved_to": str(target)}


def pip_freeze(venv_path_raw: str) -> dict[str, Any]:
    venv_path = safe_resolve(venv_path_raw)
    python_exe = find_venv_python(venv_path)
    if not python_exe:
        return {"ok": False, "error": "Could not find the virtual environment Python interpreter.", "stdout": ""}

    proc = subprocess.run(
        [str(python_exe), "-m", "pip", "freeze"],
        text=True,
        capture_output=True,
        timeout=120,
    )
    return {
        "ok": proc.returncode == 0,
        "error": proc.stderr.strip(),
        "stdout": proc.stdout,
        "returncode": proc.returncode,
    }


def package_display_name(normalized_name: str, scan: dict[str, Any]) -> str:
    for bucket in ("no_detected_use", "only_unused_custom_nodes"):
        for package in scan.get("python_packages", {}).get(bucket, []):
            if package.get("normalized_name") == norm_name(normalized_name):
                version = package.get("version")
                name = package.get("name") or normalized_name
                return f"{name}=={version}" if version else name
    return normalized_name


def create_backup(
    scan: dict[str, Any],
    selected_node_paths: set[str],
    selected_python_packages: list[str],
    backup_path_raw: str | None,
) -> dict[str, Any]:
    backup_root = safe_resolve(backup_path_raw) if backup_path_raw else DEFAULT_BACKUP_DIR
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup_dir = backup_root / f"{BACKUP_PREFIX}{stamp}"
    backup_dir.mkdir(parents=True, exist_ok=False)

    result: dict[str, Any] = {
        "ok": True,
        "backup_dir": str(backup_dir),
        "custom_nodes_zip": None,
        "python_freeze": None,
        "python_reinstall": None,
        "manifest": str(backup_dir / "manifest.json"),
        "warnings": [],
    }

    if selected_node_paths:
        zip_path = backup_dir / "custom_nodes.zip"
        custom_nodes_root = safe_resolve(scan["paths"]["custom_nodes"])
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path_raw in sorted(selected_node_paths):
                source = safe_resolve(path_raw)
                source.relative_to(custom_nodes_root)
                if source.is_file():
                    archive.write(source, source.relative_to(custom_nodes_root))
                else:
                    for file_path in source.rglob("*"):
                        if file_path.is_file():
                            archive.write(file_path, file_path.relative_to(source.parent))
        result["custom_nodes_zip"] = str(zip_path)

    if selected_python_packages:
        freeze = pip_freeze(scan["paths"]["venv"])
        freeze_path = backup_dir / "pip-freeze-before.txt"
        freeze_path.write_text(freeze.get("stdout") or "", encoding="utf-8")
        result["python_freeze"] = str(freeze_path)
        if not freeze.get("ok"):
            result["warnings"].append(f"pip freeze failed: {freeze.get('error') or 'unknown error'}")

        reinstall_lines = [
            package_display_name(name, scan)
            for name in sorted({norm_name(name) for name in selected_python_packages})
        ]
        reinstall_path = backup_dir / "selected-python-packages.txt"
        reinstall_path.write_text("\n".join(reinstall_lines) + "\n", encoding="utf-8")
        result["python_reinstall"] = str(reinstall_path)

    manifest = {
        "created_at": dt.datetime.now().isoformat(timespec="seconds"),
        "paths": scan.get("paths", {}),
        "selected_custom_node_paths": sorted(selected_node_paths),
        "selected_python_packages": sorted({norm_name(name) for name in selected_python_packages}),
        "notes": [
            "custom_nodes.zip contains the selected custom node folders or standalone files using their paths under custom_nodes.",
            "selected-python-packages.txt contains the selected Python packages for pip installation, with versions when known.",
            "pip-freeze-before.txt is the full virtual environment state before cleanup.",
        ],
    }
    (backup_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return result


def backup_root_path(backup_path_raw: str | None) -> Path:
    return safe_resolve(backup_path_raw) if backup_path_raw else DEFAULT_BACKUP_DIR.resolve()


def managed_backup_directory(backup_path_raw: str | None, backup_name: str) -> tuple[Path, Path]:
    root = backup_root_path(backup_path_raw)
    name = str(backup_name or "").strip()
    if not name or name != Path(name).name or not name.startswith(BACKUP_PREFIX):
        raise ValueError("Invalid backup name.")

    backup_dir = (root / name).resolve()
    try:
        backup_dir.relative_to(root)
    except ValueError as exc:
        raise ValueError("Backup path is outside the selected backup folder.") from exc
    is_junction = getattr(backup_dir, "is_junction", lambda: False)
    if backup_dir.is_symlink() or is_junction():
        raise ValueError("Backup links and junctions are not supported.")
    if not backup_dir.is_dir() or not (backup_dir / "manifest.json").is_file():
        raise ValueError("The selected managed backup was not found.")
    return root, backup_dir


def read_backup_manifest(backup_dir: Path) -> dict[str, Any]:
    manifest_path = backup_dir / "manifest.json"
    if manifest_path.stat().st_size > MAX_REQUEST_BODY_BYTES:
        raise ValueError("Backup manifest is too large.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("paths"), dict):
        raise ValueError("Backup manifest is invalid.")
    return manifest


def safe_backup_archive_members(zip_path: Path) -> tuple[list[tuple[zipfile.ZipInfo, tuple[str, ...]]], list[str]]:
    members: list[tuple[zipfile.ZipInfo, tuple[str, ...]]] = []
    top_level: set[str] = set()
    seen_paths: set[tuple[str, ...]] = set()
    total_uncompressed = 0

    with zipfile.ZipFile(zip_path, "r") as archive:
        if len(archive.infolist()) > 1_000_000:
            raise ValueError("Custom node backup contains too many files.")
        for info in archive.infolist():
            normalized = info.filename.replace("\\", "/")
            archive_path = PurePosixPath(normalized)
            parts = tuple(part for part in archive_path.parts if part not in {"", "."})
            if (
                not parts
                or archive_path.is_absolute()
                or any(part == ".." or ":" in part for part in parts)
            ):
                raise ValueError(f"Unsafe path in custom node backup: {info.filename}")
            file_type = (info.external_attr >> 16) & 0o170000
            if file_type == 0o120000:
                raise ValueError(f"Symbolic links are not supported in custom node backups: {info.filename}")
            if parts in seen_paths:
                raise ValueError(f"Duplicate path in custom node backup: {info.filename}")
            seen_paths.add(parts)
            total_uncompressed += max(0, int(info.file_size))
            if total_uncompressed > 500 * 1024 * 1024 * 1024:
                raise ValueError("Custom node backup is too large to restore safely.")
            members.append((info, parts))
            top_level.add(parts[0])

    return members, sorted(top_level, key=str.lower)


RESTORE_REQUIREMENT_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]*(?:==[A-Za-z0-9][A-Za-z0-9_.+!-]*)?$"
)


def read_restore_requirements(requirements_path: Path) -> list[str]:
    if requirements_path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Python package restore list is too large.")
    requirements: list[str] = []
    for raw_line in requirements_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not RESTORE_REQUIREMENT_RE.fullmatch(line):
            raise ValueError(f"Unsupported Python restore requirement: {line}")
        requirements.append(line)
    if not requirements:
        raise ValueError("Python package restore list is empty.")
    return requirements


def list_backups(backup_path_raw: str | None) -> dict[str, Any]:
    root = backup_root_path(backup_path_raw)
    if not root.exists():
        return {"ok": True, "backup_root": str(root), "backups": []}
    if not root.is_dir():
        return {"ok": False, "error": "Backup folder is not a directory.", "backup_root": str(root), "backups": []}

    backups: list[dict[str, Any]] = []
    for backup_dir in sorted(root.iterdir(), key=lambda path: path.name.lower(), reverse=True):
        if not backup_dir.is_dir() or not backup_dir.name.startswith(BACKUP_PREFIX):
            continue
        if not (backup_dir / "manifest.json").is_file():
            continue

        summary: dict[str, Any] = {
            "name": backup_dir.name,
            "path": str(backup_dir.resolve()),
            "valid": True,
            "error": "",
            "created_at": "",
            "custom_node_count": 0,
            "python_package_count": 0,
            "has_custom_nodes": (backup_dir / "custom_nodes.zip").is_file(),
            "has_python_packages": (backup_dir / "selected-python-packages.txt").is_file(),
            "custom_nodes_path": "",
            "venv_path": "",
            "size_bytes": 0,
        }
        try:
            _, validated_dir = managed_backup_directory(str(root), backup_dir.name)
            manifest = read_backup_manifest(validated_dir)
            paths = manifest.get("paths") or {}
            summary["created_at"] = str(manifest.get("created_at") or "")
            summary["custom_nodes_path"] = str(paths.get("custom_nodes") or "")
            summary["venv_path"] = str(paths.get("venv") or "")
            summary["python_package_count"] = len(manifest.get("selected_python_packages") or [])
            if summary["has_custom_nodes"]:
                _, top_level = safe_backup_archive_members(validated_dir / "custom_nodes.zip")
                summary["custom_node_count"] = len(top_level)
            size_result = directory_file_size(validated_dir)
            summary["size_bytes"] = int(size_result.get("bytes") or 0)
        except Exception as exc:
            summary["valid"] = False
            summary["error"] = str(exc)
        backups.append(summary)

    backups.sort(key=lambda item: (item.get("created_at") or "", item["name"]), reverse=True)
    return {"ok": True, "backup_root": str(root), "backups": backups}


def prepare_custom_node_restore(backup_dir: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    zip_path = backup_dir / "custom_nodes.zip"
    if not zip_path.is_file():
        raise ValueError("This backup does not contain custom nodes.")
    custom_nodes_raw = str((manifest.get("paths") or {}).get("custom_nodes") or "").strip()
    if not custom_nodes_raw:
        raise ValueError("The custom_nodes destination is missing from the backup manifest.")
    destination = safe_resolve(custom_nodes_raw)
    if destination.name.lower() != "custom_nodes":
        raise ValueError("The backup custom node destination is invalid.")
    members, top_level = safe_backup_archive_members(zip_path)
    if not top_level:
        raise ValueError("Custom node backup is empty.")
    conflicts = [str(destination / name) for name in top_level if (destination / name).exists()]
    if conflicts:
        raise ValueError("Restore would overwrite existing custom nodes: " + ", ".join(conflicts))
    return {
        "zip_path": zip_path,
        "destination": destination,
        "members": members,
        "top_level": top_level,
    }


def restore_custom_nodes(prepared: dict[str, Any]) -> dict[str, Any]:
    zip_path: Path = prepared["zip_path"]
    destination: Path = prepared["destination"]
    members: list[tuple[zipfile.ZipInfo, tuple[str, ...]]] = prepared["members"]
    top_level: list[str] = prepared["top_level"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(parents=True, exist_ok=True)
    staging = (destination.parent / f".comfyui-cleaner-restore-{uuid.uuid4().hex}").resolve()
    staging.relative_to(destination.parent.resolve())
    staging.mkdir(parents=False, exist_ok=False)
    moved: list[Path] = []
    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            for info, parts in members:
                target = staging.joinpath(*parts)
                target.relative_to(staging)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)

        for name in top_level:
            source = staging / name
            target = destination / name
            if target.exists():
                raise FileExistsError(f"Restore destination appeared during restore: {target}")
            shutil.move(str(source), str(target))
            moved.append(target)
    except Exception:
        for target in reversed(moved):
            rollback_target = staging / target.name
            if target.exists() and not rollback_target.exists():
                shutil.move(str(target), str(rollback_target))
        raise
    finally:
        staging.relative_to(destination.parent.resolve())
        shutil.rmtree(staging, ignore_errors=True)

    return {
        "ok": True,
        "destination": str(destination),
        "restored": [str(destination / name) for name in top_level],
    }


def prepare_python_restore(backup_dir: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    requirements_path = backup_dir / "selected-python-packages.txt"
    if not requirements_path.is_file():
        raise ValueError("This backup does not contain Python packages.")
    venv_raw = str((manifest.get("paths") or {}).get("venv") or "").strip()
    if not venv_raw:
        raise ValueError("The virtual environment path is missing from the backup manifest.")
    venv_path = safe_resolve(venv_raw)
    python_exe = find_venv_python(venv_path)
    if not python_exe:
        raise ValueError("Could not find the backup virtual environment Python interpreter.")
    requirements = read_restore_requirements(requirements_path)
    return {
        "python_exe": python_exe,
        "requirements_path": requirements_path,
        "requirements": requirements,
    }


def restore_python_packages(prepared: dict[str, Any]) -> dict[str, Any]:
    proc = subprocess.run(
        [
            str(prepared["python_exe"]),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "-r",
            str(prepared["requirements_path"]),
        ],
        text=True,
        capture_output=True,
        timeout=900,
    )
    return {
        "ok": proc.returncode == 0,
        "packages": list(prepared["requirements"]),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "returncode": proc.returncode,
    }


def restore_backup(payload: dict[str, Any]) -> dict[str, Any]:
    backup_path = str(payload.get("backup_path") or "").strip() or None
    backup_name = str(payload.get("backup_name") or "")
    restore_nodes = bool(payload.get("restore_custom_nodes", True))
    restore_python = bool(payload.get("restore_python_packages", True))
    if not restore_nodes and not restore_python:
        return {"ok": False, "error": "Select at least one backup component to restore."}

    try:
        _, backup_dir = managed_backup_directory(backup_path, backup_name)
        manifest = read_backup_manifest(backup_dir)
        prepared_nodes = prepare_custom_node_restore(backup_dir, manifest) if restore_nodes else None
        prepared_python = prepare_python_restore(backup_dir, manifest) if restore_python else None
    except Exception as exc:
        return {"ok": False, "error": str(exc), "custom_nodes": None, "python_packages": None}

    python_result = restore_python_packages(prepared_python) if prepared_python else None
    if python_result is not None and not python_result.get("ok"):
        return {
            "ok": False,
            "error": "Python package restoration failed; custom nodes were not restored.",
            "backup_dir": str(backup_dir),
            "custom_nodes": None,
            "python_packages": python_result,
        }

    try:
        node_result = restore_custom_nodes(prepared_nodes) if prepared_nodes else None
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Custom node restoration failed: {exc}",
            "backup_dir": str(backup_dir),
            "custom_nodes": None,
            "python_packages": python_result,
        }

    return {
        "ok": True,
        "backup_dir": str(backup_dir),
        "custom_nodes": node_result,
        "python_packages": python_result,
    }


def delete_backup(backup_path_raw: str | None, backup_name: str) -> dict[str, Any]:
    try:
        root, backup_dir = managed_backup_directory(backup_path_raw, backup_name)
        backup_dir.relative_to(root)
        shutil.rmtree(backup_dir)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "deleted": str(backup_dir)}


def python_removal_candidates(scan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    for bucket in ("no_detected_use", "only_unused_custom_nodes"):
        for package in scan.get("python_packages", {}).get(bucket, []):
            normalized = norm_name(str(package.get("normalized_name") or ""))
            if normalized:
                candidates[normalized] = {**package, "bucket": bucket}
    return candidates


def validate_python_selection(
    normalized_names: list[str],
    selected_node_paths: set[str],
    scan: dict[str, Any],
) -> dict[str, Any]:
    candidates = python_removal_candidates(scan)
    allowed: list[str] = []
    blocked: list[dict[str, Any]] = []
    seen: set[str] = set()

    for requested_name in normalized_names:
        normalized = norm_name(requested_name)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        candidate = candidates.get(normalized)
        if not candidate or normalized in PROTECTED_DISTS:
            blocked.append({"package": requested_name, "reason": "Package is not an allowed removal candidate."})
            continue

        required_node_paths = set(candidate.get("required_by_custom_node_paths") or [])
        missing_node_paths = sorted(required_node_paths - selected_node_paths)
        if missing_node_paths:
            blocked.append(
                {
                    "package": candidate.get("name") or requested_name,
                    "reason": "The package is still required by custom nodes that are not selected for removal.",
                    "required_custom_node_paths": missing_node_paths,
                }
            )
            continue
        allowed.append(normalized)

    return {"allowed": allowed, "blocked": blocked}


def validate_cleanup_selection(
    scan: dict[str, Any],
    selected_node_paths: set[str],
    selected_python_packages: list[str],
) -> dict[str, Any]:
    removable_node_paths = {
        item["path"]
        for item in scan.get("custom_nodes", [])
        if item.get("status") == "unused" and item.get("confidence") == "high"
    }
    python_validation = validate_python_selection(selected_python_packages, selected_node_paths, scan)
    return {
        "invalid_node_paths": sorted(selected_node_paths - removable_node_paths),
        "python_packages": python_validation["allowed"],
        "blocked_python_packages": python_validation["blocked"],
    }


def directory_file_size(root: Path) -> dict[str, Any]:
    total_bytes = 0
    file_count = 0
    warnings: list[str] = []
    if root.is_file():
        try:
            return {
                "ok": True,
                "bytes": root.lstat().st_size,
                "file_count": 1,
                "warnings": [],
                "error": None,
            }
        except OSError as exc:
            return {"ok": False, "bytes": 0, "file_count": 0, "warnings": [], "error": str(exc)}
    if not root.exists() or not root.is_dir():
        return {
            "ok": False,
            "bytes": 0,
            "file_count": 0,
            "warnings": [],
            "error": f"Path was not found: {root}",
        }

    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = [name for name in dirs if not (current_path / name).is_symlink()]
        for name in files:
            file_path = current_path / name
            try:
                total_bytes += file_path.lstat().st_size
                file_count += 1
            except OSError as exc:
                if len(warnings) < 20:
                    warnings.append(f"Could not read file size for {file_path}: {exc}")

    return {
        "ok": True,
        "bytes": total_bytes,
        "file_count": file_count,
        "warnings": warnings,
        "error": None,
    }


def python_package_file_sizes(venv_path_raw: str, normalized_names: list[str]) -> dict[str, Any]:
    venv_path = safe_resolve(venv_path_raw)
    python_exe = find_venv_python(venv_path)
    if not python_exe:
        return {
            "ok": False,
            "error": "Could not find the virtual environment Python interpreter.",
            "bytes": 0,
            "file_count": 0,
            "packages": [],
            "warnings": [],
        }

    script = r"""
import importlib.metadata as im
import json
import os
import re
import sys

def norm_name(value):
    return re.sub(r"[-_.]+", "-", value.strip().lower())

targets = {norm_name(value) for value in sys.argv[1:]}
environment_root = os.path.normcase(os.path.realpath(sys.prefix))
found = set()
seen_files = set()
outside_environment = set()
packages = []
warnings = []
total_bytes = 0
total_files = 0

for dist in im.distributions():
    name = dist.metadata.get("Name") or ""
    normalized = norm_name(name)
    if not name or normalized not in targets:
        continue
    found.add(normalized)
    package_bytes = 0
    package_files = 0
    files = dist.files
    if files is None:
        warnings.append(f"{name}: installed-file metadata is unavailable.")
        files = []
    for entry in files:
        try:
            path = os.path.abspath(os.fspath(dist.locate_file(entry)))
            real_path = os.path.normcase(os.path.realpath(path))
            try:
                if os.path.commonpath([environment_root, real_path]) != environment_root:
                    outside_environment.add(name)
                    continue
            except ValueError:
                outside_environment.add(name)
                continue
            key = os.path.normcase(path)
            if key in seen_files or not os.path.isfile(path):
                continue
            size = os.path.getsize(path)
            seen_files.add(key)
            package_bytes += size
            package_files += 1
            total_bytes += size
            total_files += 1
        except OSError as exc:
            if len(warnings) < 20:
                warnings.append(f"{name}: could not read {entry}: {exc}")
    packages.append({
        "name": name,
        "normalized_name": normalized,
        "bytes": package_bytes,
        "file_count": package_files,
    })

for name in sorted(outside_environment):
    warnings.append(f"{name}: files outside the virtual environment were excluded from the estimate.")

for missing in sorted(targets - found):
    warnings.append(f"{missing}: distribution metadata was not found.")

print(json.dumps({
    "bytes": total_bytes,
    "file_count": total_files,
    "packages": sorted(packages, key=lambda item: item["name"].lower()),
    "warnings": warnings,
}, ensure_ascii=False))
"""
    try:
        proc = subprocess.run(
            [str(python_exe), "-c", script, *normalized_names],
            text=True,
            capture_output=True,
            timeout=120,
        )
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Failed to calculate Python package sizes: {exc}",
            "bytes": 0,
            "file_count": 0,
            "packages": [],
            "warnings": [],
        }

    if proc.returncode != 0:
        return {
            "ok": False,
            "error": proc.stderr.strip() or "Failed to calculate Python package sizes.",
            "bytes": 0,
            "file_count": 0,
            "packages": [],
            "warnings": [],
        }

    try:
        result = json.loads(proc.stdout)
    except Exception:
        return {
            "ok": False,
            "error": "Could not parse the Python package size response.",
            "bytes": 0,
            "file_count": 0,
            "packages": [],
            "warnings": [],
        }
    return {"ok": True, "error": None, **result}


def calculate_cleanup_size(payload: dict[str, Any]) -> dict[str, Any]:
    scan_id = str(payload.get("scan_id") or "")
    with SCAN_LOCK:
        scan = SCAN_CACHE.get(scan_id)
    if not scan:
        return {"ok": False, "error": "Scan result was not found. Run the scan again."}

    selected_node_paths = set(str(item) for item in payload.get("custom_node_paths") or [])
    selected_python_packages = [str(item) for item in payload.get("python_packages") or []]
    validation = validate_cleanup_selection(scan, selected_node_paths, selected_python_packages)
    if validation["invalid_node_paths"] or validation["blocked_python_packages"]:
        return {
            "ok": False,
            "error": "Size was not calculated because one or more selections failed the safety checks.",
            "invalid_custom_node_paths": validation["invalid_node_paths"],
            "blocked_python_packages": validation["blocked_python_packages"],
        }

    custom_nodes_root = safe_resolve(scan["paths"]["custom_nodes"])
    node_bytes = 0
    node_file_count = 0
    node_details: list[dict[str, Any]] = []
    warnings: list[str] = []
    for path_raw in sorted(selected_node_paths):
        node_path = safe_resolve(path_raw)
        try:
            node_path.relative_to(custom_nodes_root)
        except ValueError:
            return {"ok": False, "error": f"Custom node path is outside custom_nodes: {node_path}"}
        size = directory_file_size(node_path)
        if not size["ok"]:
            return {"ok": False, "error": size["error"]}
        node_bytes += size["bytes"]
        node_file_count += size["file_count"]
        warnings.extend(size["warnings"])
        node_details.append(
            {
                "name": node_path.name,
                "path": str(node_path),
                "bytes": size["bytes"],
                "file_count": size["file_count"],
            }
        )

    python_result = {
        "ok": True,
        "error": None,
        "bytes": 0,
        "file_count": 0,
        "packages": [],
        "warnings": [],
    }
    if validation["python_packages"]:
        python_result = python_package_file_sizes(
            scan["paths"]["venv"],
            validation["python_packages"],
        )
        if not python_result["ok"]:
            return python_result
        warnings.extend(python_result.get("warnings") or [])

    python_bytes = int(python_result.get("bytes") or 0)
    python_file_count = int(python_result.get("file_count") or 0)
    return {
        "ok": True,
        "total_bytes": node_bytes + python_bytes,
        "total_file_count": node_file_count + python_file_count,
        "custom_nodes": {
            "bytes": node_bytes,
            "file_count": node_file_count,
            "packages": node_details,
        },
        "python_packages": {
            "bytes": python_bytes,
            "file_count": python_file_count,
            "packages": python_result.get("packages") or [],
        },
        "warnings": warnings[:40],
    }


def uninstall_python_packages(
    venv_path_raw: str,
    normalized_names: list[str],
    selected_node_paths: set[str],
    scan: dict[str, Any],
) -> dict[str, Any]:
    venv_path = safe_resolve(venv_path_raw)
    python_exe = find_venv_python(venv_path)
    if not python_exe:
        return {"ok": False, "error": "Could not find the virtual environment Python interpreter.", "stdout": "", "stderr": ""}

    validation = validate_python_selection(normalized_names, selected_node_paths, scan)
    selected = validation["allowed"]
    blocked = validation["blocked"]
    if not selected:
        return {
            "ok": False,
            "error": "No Python package passed the removal safety checks.",
            "blocked": blocked,
            "stdout": "",
            "stderr": "",
        }

    display_names = []
    installed = read_venv_distributions(venv_path).get("packages") or {}
    for normalized in selected:
        display_names.append(installed.get(normalized, {}).get("name", normalized))

    proc = subprocess.run(
        [str(python_exe), "-m", "pip", "uninstall", "-y", *display_names],
        text=True,
        capture_output=True,
        timeout=300,
    )
    return {
        "ok": proc.returncode == 0,
        "packages": display_names,
        "blocked": blocked,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "returncode": proc.returncode,
    }


def run_clean(payload: dict[str, Any]) -> dict[str, Any]:
    scan_id = str(payload.get("scan_id") or "")
    with SCAN_LOCK:
        scan = SCAN_CACHE.get(scan_id)
    if not scan:
        return {"ok": False, "error": "Scan result was not found. Run the scan again."}

    selected_node_paths = set(str(item) for item in payload.get("custom_node_paths") or [])
    selected_python_packages = [str(item) for item in payload.get("python_packages") or []]
    backup_enabled = bool(payload.get("backup_enabled", True))
    backup_path = str(payload.get("backup_path") or "").strip()

    validation = validate_cleanup_selection(scan, selected_node_paths, selected_python_packages)
    if validation["invalid_node_paths"] or validation["blocked_python_packages"]:
        return {
            "ok": False,
            "error": "Cleanup was not started because one or more selections failed the safety checks.",
            "invalid_custom_node_paths": validation["invalid_node_paths"],
            "blocked_python_packages": validation["blocked_python_packages"],
            "backup": None,
            "custom_nodes": [],
            "python_packages": None,
        }
    selected_python_packages = validation["python_packages"]

    node_results = []
    backup_result = None
    if backup_enabled and (selected_node_paths or selected_python_packages):
        try:
            backup_result = create_backup(
                scan,
                selected_node_paths,
                selected_python_packages,
                backup_path or None,
            )
        except Exception as exc:
            return {
                "ok": False,
                "error": f"Backup failed, so cleanup was not performed: {exc}",
                "backup": {"ok": False, "error": str(exc)},
                "custom_nodes": [],
                "python_packages": None,
            }

    for path in sorted(selected_node_paths):
        node_results.append(move_custom_node_to_trash(path, scan["paths"]["custom_nodes"]))

    python_result = None
    if selected_python_packages:
        successfully_removed_node_paths = {
            str(item.get("path"))
            for item in node_results
            if item.get("ok")
        }
        python_result = uninstall_python_packages(
            scan["paths"]["venv"],
            selected_python_packages,
            successfully_removed_node_paths,
            scan,
        )

    return {
        "ok": all(item.get("ok") for item in node_results) and (python_result is None or python_result.get("ok")),
        "backup": backup_result,
        "custom_nodes": node_results,
        "python_packages": python_result,
    }


HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ComfyUI Cleaner</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fa;
      --panel: #ffffff;
      --text: #172026;
      --muted: #5d6973;
      --line: #d8dee5;
      --strong: #0f766e;
      --strong-dark: #115e59;
      --danger: #b42318;
      --warn: #a15c07;
      --ok: #147d3f;
      --shadow: 0 14px 40px rgba(23, 32, 38, 0.08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    header {
      border-bottom: 1px solid var(--line);
      background: #fff;
    }
    .wrap {
      width: min(1180px, calc(100vw - 32px));
      margin: 0 auto;
    }
    header .wrap {
      padding: 24px 0 18px;
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 20px;
    }
    h1 {
      margin: 0;
      font-size: 26px;
      line-height: 1.2;
      letter-spacing: 0;
    }
    .subtitle {
      margin: 6px 0 0;
      color: var(--muted);
      max-width: 760px;
    }
    main {
      padding: 24px 0 48px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
      border-radius: 8px;
      padding: 18px;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr 1fr;
      gap: 14px;
      align-items: end;
    }
    label {
      display: block;
      font-weight: 650;
      font-size: 13px;
      margin-bottom: 7px;
    }
    input[type="text"],
    select {
      width: 100%;
      min-height: 40px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 10px;
      font: inherit;
      background: #fff;
      color: var(--text);
    }
    select { cursor: pointer; }
    .path-picker {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 8px;
    }
    .path-picker button {
      min-width: 78px;
      padding-left: 12px;
      padding-right: 12px;
    }
    input[type="checkbox"] {
      width: 16px;
      height: 16px;
      accent-color: var(--strong);
    }
    .actions {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      margin-top: 14px;
    }
    .backup-panel { margin-top: 18px; }
    .backup-grid {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(280px, .65fr);
      gap: 14px;
      align-items: end;
    }
    .backup-details {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px 16px;
      padding-top: 14px;
      margin-top: 14px;
      border-top: 1px solid var(--line);
    }
    .backup-details div { min-width: 0; }
    .backup-details strong {
      display: block;
      margin-bottom: 3px;
      font-size: 12px;
      color: var(--muted);
    }
    button {
      min-height: 40px;
      border: 1px solid transparent;
      border-radius: 6px;
      padding: 9px 14px;
      font: inherit;
      font-weight: 650;
      cursor: pointer;
    }
    button.primary {
      background: var(--strong);
      color: #fff;
    }
    button.primary:hover { background: var(--strong-dark); }
    button.secondary {
      background: #fff;
      border-color: var(--line);
      color: var(--text);
    }
    button.shutdown {
      background: #fff;
      border-color: #f2b8b5;
      color: var(--danger);
    }
    button.shutdown:hover {
      background: #fff5f4;
    }
    button.danger {
      background: var(--danger);
      color: #fff;
    }
    button:disabled {
      opacity: .58;
      cursor: not-allowed;
    }
    .status {
      color: var(--muted);
      font-size: 14px;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin: 18px 0;
    }
    .metric {
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }
    .metric b {
      display: block;
      font-size: 26px;
      line-height: 1;
      margin-bottom: 6px;
    }
    .metric span {
      color: var(--muted);
      font-size: 13px;
    }
    section {
      margin-top: 18px;
    }
    h2 {
      margin: 0 0 10px;
      font-size: 18px;
      letter-spacing: 0;
    }
    .table {
      width: 100%;
      border-collapse: collapse;
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }
    .table th,
    .table td {
      border-bottom: 1px solid var(--line);
      padding: 10px;
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }
    .table th {
      background: #eef2f5;
      color: #34414c;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    .table tr:last-child td { border-bottom: 0; }
    .muted { color: var(--muted); }
    .badge {
      display: inline-block;
      padding: 3px 7px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: #fff;
      font-size: 12px;
      font-weight: 650;
      white-space: nowrap;
    }
    .badge.unused { color: var(--danger); border-color: #f2b8b5; background: #fff5f4; }
    .badge.used { color: var(--ok); border-color: #b7dfc4; background: #f2fbf5; }
    .badge.unknown { color: var(--warn); border-color: #f4d19a; background: #fff8eb; }
    .notice {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fff;
      color: var(--muted);
      margin-top: 12px;
    }
    .notice.error {
      border-color: #f2b8b5;
      background: #fff5f4;
      color: var(--danger);
    }
    .notice.warn {
      border-color: #f4d19a;
      background: #fff8eb;
      color: #6f4300;
    }
    .progress-card {
      margin-top: 12px;
    }
    .progress-head {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: baseline;
      margin-bottom: 8px;
    }
    .progress-title {
      font-weight: 700;
    }
    .progress-meta {
      color: var(--muted);
      font-size: 13px;
      text-align: right;
    }
    .progress-track {
      height: 10px;
      background: #e8edf2;
      border-radius: 999px;
      overflow: hidden;
      border: 1px solid var(--line);
    }
    .progress-bar {
      width: 0%;
      height: 100%;
      background: var(--strong);
      transition: width .25s ease;
    }
    .scan-log {
      margin-top: 10px;
      max-height: 180px;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #f8fafc;
    }
    .scan-log-row {
      display: grid;
      grid-template-columns: 58px 130px minmax(0, 1fr);
      gap: 8px;
      padding: 7px 9px;
      border-bottom: 1px solid var(--line);
      font-size: 13px;
    }
    .scan-log-row:last-child { border-bottom: 0; }
    .scan-log-row span:first-child,
    .scan-log-row span:nth-child(2) {
      color: var(--muted);
    }
    .path {
      font-family: Consolas, "Courier New", monospace;
      font-size: 12px;
      word-break: break-all;
      color: #34414c;
    }
    .hidden { display: none; }
    .toolbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 8px;
    }
    .toolbar .actions { margin: 0; }
    .checkline {
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 12px 0;
      font-weight: 650;
    }
    .checkline label {
      margin: 0;
      font-size: 14px;
    }
    pre {
      white-space: pre-wrap;
      background: #172026;
      color: #f7f8fa;
      border-radius: 8px;
      padding: 12px;
      overflow: auto;
      max-height: 260px;
    }
    @media (max-width: 900px) {
      header .wrap { align-items: start; flex-direction: column; }
      .grid { grid-template-columns: 1fr; }
      .backup-grid { grid-template-columns: 1fr; }
      .backup-details { grid-template-columns: 1fr 1fr; }
      .summary { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 560px) {
      .summary { grid-template-columns: 1fr; }
      .backup-details { grid-template-columns: 1fr; }
      .table { display: block; overflow-x: auto; }
      button { width: 100%; }
    }
  </style>
</head>
<body>
  <header>
    <div class="wrap">
      <div>
        <h1>ComfyUI Cleaner</h1>
        <p class="subtitle">Scan workflows, custom node packages, and Python packages in the virtual environment. You choose what to remove before cleanup.</p>
      </div>
      <button id="shutdownBtn" class="shutdown" type="button">Shutdown</button>
    </div>
  </header>

  <main class="wrap">
    <div class="panel">
      <div class="grid">
        <div>
          <label for="comfyPath">ComfyUI installation</label>
          <div class="path-picker">
            <input id="comfyPath" type="text" placeholder="C:\ComfyUI">
            <button type="button" class="secondary browse-btn" data-target="comfyPath" data-title="Select ComfyUI installation">Browse</button>
          </div>
        </div>
        <div>
          <label for="venvPath">Virtual environment</label>
          <div class="path-picker">
            <input id="venvPath" type="text" placeholder="C:\ComfyUI\venv or python.exe">
            <button type="button" class="secondary browse-btn" data-target="venvPath" data-title="Select virtual environment folder">Browse</button>
          </div>
        </div>
        <div>
          <label for="workflowPath">Workflows</label>
          <div class="path-picker">
            <input id="workflowPath" type="text" placeholder="C:\ComfyUI\user\default\workflows">
            <button type="button" class="secondary browse-btn" data-target="workflowPath" data-title="Select workflows folder">Browse</button>
          </div>
        </div>
      </div>
      <div class="actions">
        <button id="scanBtn" class="primary">Scan</button>
        <button id="clearBtn" class="secondary">Clear selections</button>
        <span id="status" class="status"></span>
      </div>
    </div>

    <section class="panel backup-panel" aria-labelledby="backupManagerTitle">
      <div class="toolbar">
        <h2 id="backupManagerTitle">Backup management</h2>
        <button id="refreshBackupsBtn" class="secondary" type="button">Refresh</button>
      </div>
      <div class="backup-grid">
        <div>
          <label for="backupManagerPath">Backup folder</label>
          <div class="path-picker">
            <input id="backupManagerPath" type="text" placeholder="Empty = application backups folder">
            <button type="button" class="secondary browse-btn" data-target="backupManagerPath" data-title="Select backup folder">Browse</button>
          </div>
        </div>
        <div>
          <label for="backupSelect">Backup</label>
          <select id="backupSelect"><option value="">No backups found</option></select>
        </div>
      </div>
      <div id="backupDetails" class="backup-details hidden"></div>
      <div id="backupRestoreOptions" class="actions hidden">
        <div class="checkline">
          <input id="restoreCustomNodes" type="checkbox">
          <label for="restoreCustomNodes">Custom nodes</label>
        </div>
        <div class="checkline">
          <input id="restorePythonPackages" type="checkbox">
          <label for="restorePythonPackages">Python packages</label>
        </div>
      </div>
      <div class="actions">
        <button id="restoreBackupBtn" class="primary" type="button" disabled>Restore selected</button>
        <button id="deleteBackupBtn" class="danger" type="button" disabled>Delete backup</button>
        <span id="backupStatus" class="status"></span>
      </div>
      <div id="backupOutput"></div>
    </section>

    <div id="messages"></div>
    <div id="scanProgress" class="notice progress-card hidden">
      <div class="progress-head">
        <div>
          <div id="scanProgressTitle" class="progress-title">Scan queued</div>
          <div id="scanProgressMessage" class="muted"></div>
        </div>
        <div id="scanProgressMeta" class="progress-meta"></div>
      </div>
      <div class="progress-track"><div id="scanProgressBar" class="progress-bar"></div></div>
      <div id="scanLog" class="scan-log"></div>
    </div>

    <div id="results" class="hidden">
      <div class="summary" id="summary"></div>

      <section>
        <div class="toolbar">
          <h2>Unused custom node packages</h2>
          <div class="actions">
            <button class="secondary" id="selectNodesBtn">Select all</button>
            <button class="secondary" id="deselectNodesBtn">Deselect all</button>
          </div>
        </div>
        <div id="unusedNodes"></div>
      </section>

      <section>
        <div class="toolbar">
          <h2>Python packages to review for removal</h2>
          <div class="actions">
            <button class="secondary" id="selectPyBtn">Select all</button>
            <button class="secondary" id="deselectPyBtn">Deselect all</button>
          </div>
        </div>
        <div id="pythonPackages"></div>
      </section>

      <section>
        <h2>Other findings</h2>
        <div id="otherFindings"></div>
      </section>

      <section class="panel">
        <h2>Cleanup</h2>
        <p class="muted">Selected items are backed up first. Custom node folders or standalone files are moved to quarantine outside the active custom_nodes folder. Python packages are removed from the selected virtual environment with pip uninstall.</p>
        <div class="checkline">
          <input id="backupEnabled" type="checkbox" checked>
          <label for="backupEnabled">Create a backup before cleanup</label>
        </div>
        <div>
          <label for="backupPath">Backup folder</label>
          <div class="path-picker">
            <input id="backupPath" type="text" placeholder="Empty = application backups folder">
            <button type="button" class="secondary browse-btn" data-target="backupPath" data-title="Select backup folder">Browse</button>
          </div>
        </div>
        <div class="actions">
          <button id="cleanBtn" class="danger">Clean selected</button>
          <button id="sizeBtn" class="secondary">Calculate size</button>
          <span id="cleanStatus" class="status"></span>
        </div>
        <div id="sizeOutput"></div>
        <div id="cleanOutput"></div>
      </section>
    </div>
  </main>

  <script>
    const $ = (id) => document.getElementById(id);
    let currentScan = null;
    let scanPollTimer = null;
    let sizeRequestVersion = 0;
    let backups = [];
    let backupBusy = false;
    const autoFilledPath = {
      venvPath: false,
      workflowPath: false
    };

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
      }[ch]));
    }

    function setStatus(text) {
      $("status").textContent = text;
    }

    function renderMessages(scan) {
      const parts = [];
      for (const error of scan.errors || []) {
        parts.push(`<div class="notice error">${escapeHtml(error)}</div>`);
      }
      for (const warning of scan.warnings || []) {
        parts.push(`<div class="notice warn">${escapeHtml(warning)}</div>`);
      }
      for (const note of scan.notes || []) {
        parts.push(`<div class="notice">${escapeHtml(note)}</div>`);
      }
      $("messages").innerHTML = parts.join("");
    }

    function renderSummary(scan) {
      const nodes = scan.custom_nodes || [];
      const unusedNodes = nodes.filter((item) => item.status === "unused").length;
      const unknownNodes = nodes.filter((item) => item.status === "unknown").length;
      const py = scan.python_packages || {};
      const pyCandidates = (py.no_detected_use || []).length + (py.only_unused_custom_nodes || []).length;
      $("summary").innerHTML = `
        <div class="metric"><b>${scan.workflow.files_scanned}</b><span>workflow JSON/PNG files read</span></div>
        <div class="metric"><b>${scan.workflow.node_type_count}</b><span>node types in workflows</span></div>
        <div class="metric"><b>${unusedNodes}</b><span>high-confidence unused node packages</span></div>
        <div class="metric"><b>${pyCandidates}</b><span>Python packages to review</span></div>
      `;
    }

    function badge(status) {
      const labels = { used: "used", unused: "unused", unknown: "unknown" };
      return `<span class="badge ${status}">${labels[status] || status}</span>`;
    }

    function renderUnusedNodes(scan) {
      const items = (scan.custom_nodes || []).filter((item) => item.status === "unused");
      if (!items.length) {
        $("unusedNodes").innerHTML = `<div class="notice">No unused custom node packages were found by static analysis.</div>`;
        return;
      }
      const rows = items.map((item) => `
        <tr>
          <td><input type="checkbox" class="node-check" value="${escapeHtml(item.path)}"></td>
          <td><strong>${escapeHtml(item.name)}</strong><div class="path">${escapeHtml(item.path)}</div></td>
          <td>${badge(item.status)}</td>
          <td>${escapeHtml(item.confidence || "high")}</td>
          <td>${item.node_type_count}</td>
          <td>${escapeHtml((item.node_types || []).slice(0, 12).join(", "))}</td>
          <td>${escapeHtml((item.evidence || []).join("; "))}</td>
        </tr>
      `).join("");
      $("unusedNodes").innerHTML = `
        <table class="table">
          <thead><tr><th></th><th>Package</th><th>Status</th><th>Confidence</th><th>Nodes</th><th>Examples</th><th>Evidence</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      `;
    }

    function renderPythonPackages(scan) {
      const py = scan.python_packages || {};
      const buckets = [
        ["no_detected_use", "No detected use"],
        ["only_unused_custom_nodes", "Only in unused custom nodes"]
      ];
      const rows = [];
      for (const [key, label] of buckets) {
        for (const item of py[key] || []) {
          const requiredNodePaths = item.required_by_custom_node_paths || [];
          const requiredNodeNames = item.required_by_custom_nodes || [];
          const dependencyData = requiredNodePaths.length
            ? ` data-required-node-paths="${escapeHtml(encodeURIComponent(JSON.stringify(requiredNodePaths)))}" disabled`
            : "";
          const dependencyNote = requiredNodeNames.length
            ? ` Remove the related custom nodes first: ${requiredNodeNames.join(", ")}.`
            : "";
          rows.push(`
            <tr>
              <td><input type="checkbox" class="py-check" value="${escapeHtml(item.normalized_name)}"${dependencyData}></td>
              <td><strong>${escapeHtml(item.name)}</strong><div class="muted">${escapeHtml(item.version)}</div></td>
              <td>${escapeHtml(label)}</td>
              <td>${escapeHtml(item.confidence || "review")}</td>
              <td>${escapeHtml(item.reason + dependencyNote)}</td>
            </tr>
          `);
        }
      }
      if (!rows.length) {
        $("pythonPackages").innerHTML = `<div class="notice">No Python package removal candidates were found.</div>`;
        return;
      }
      $("pythonPackages").innerHTML = `
        <table class="table">
          <thead><tr><th></th><th>Package</th><th>Category</th><th>Confidence</th><th>Reason</th></tr></thead>
          <tbody>${rows.join("")}</tbody>
        </table>
      `;
    }

    function syncDependentPythonChoices() {
      const selectedNodePaths = new Set(
        Array.from(document.querySelectorAll(".node-check:checked")).map((box) => box.value)
      );
      document.querySelectorAll(".py-check[data-required-node-paths]").forEach((box) => {
        let requiredNodePaths = [];
        try {
          requiredNodePaths = JSON.parse(decodeURIComponent(box.dataset.requiredNodePaths || ""));
        } catch {
          requiredNodePaths = [];
        }
        const eligible = requiredNodePaths.length > 0
          && requiredNodePaths.every((path) => selectedNodePaths.has(path));
        box.disabled = !eligible;
        if (!eligible) box.checked = false;
        box.title = eligible
          ? "Eligible because all related custom nodes are selected."
          : "Select all related custom nodes before removing this Python package.";
      });
    }

    function renderOtherFindings(scan) {
      const nodes = scan.custom_nodes || [];
      const used = nodes.filter((item) => item.status === "used");
      const unknown = nodes.filter((item) => item.status === "unknown");
      const rows = [
        `<div class="notice"><strong>Custom node packages in use:</strong> ${used.length}</div>`,
        `<div class="notice"><strong>Unknown custom node packages:</strong> ${unknown.length}. These are not suggested for automatic removal.</div>`,
      ];
      if (unknown.length) {
        rows.push(`<table class="table"><thead><tr><th>Package</th><th>Path</th><th>Reason</th></tr></thead><tbody>${
          unknown.map((item) => `<tr><td>${escapeHtml(item.name)}</td><td class="path">${escapeHtml(item.path)}</td><td>${escapeHtml((item.evidence || []).join("; "))}</td></tr>`).join("")
        }</tbody></table>`);
      }
      $("otherFindings").innerHTML = rows.join("");
    }

    function renderScan(scan) {
      currentScan = scan;
      clearSizeEstimate();
      renderMessages(scan);
      renderSummary(scan);
      renderUnusedNodes(scan);
      renderPythonPackages(scan);
      syncDependentPythonChoices();
      renderOtherFindings(scan);
      $("results").classList.remove("hidden");
    }

    async function postJson(url, payload) {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Request failed.");
      }
      return data;
    }

    async function getJson(url) {
      const response = await fetch(url);
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Request failed.");
      }
      return data;
    }

    function formatDuration(seconds) {
      if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "estimating";
      seconds = Math.max(0, Math.round(seconds));
      const minutes = Math.floor(seconds / 60);
      const rest = seconds % 60;
      if (minutes <= 0) return `${rest}s`;
      return `${minutes}m ${String(rest).padStart(2, "0")}s`;
    }

    function formatBytes(bytes) {
      const value = Math.max(0, Number(bytes) || 0);
      if (value < 1024) return `${Math.round(value)} B`;
      const units = ["KB", "MB", "GB", "TB"];
      let scaled = value;
      let unit = "B";
      for (const candidate of units) {
        scaled /= 1024;
        unit = candidate;
        if (scaled < 1024) break;
      }
      const decimals = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
      return `${scaled.toFixed(decimals)} ${unit}`;
    }

    function selectedBackup() {
      return backups.find((item) => item.name === $("backupSelect").value) || null;
    }

    function backupDateLabel(value) {
      return value ? String(value).replace("T", " ") : "Unknown";
    }

    function updateBackupButtons() {
      const item = selectedBackup();
      const selectedComponent = $("restoreCustomNodes").checked || $("restorePythonPackages").checked;
      $("restoreBackupBtn").disabled = backupBusy || !item || !item.valid || !selectedComponent;
      $("deleteBackupBtn").disabled = backupBusy || !item;
    }

    function renderBackupSelection() {
      const item = selectedBackup();
      $("backupOutput").innerHTML = "";
      if (!item) {
        $("backupDetails").classList.add("hidden");
        $("backupRestoreOptions").classList.add("hidden");
        $("restoreCustomNodes").checked = false;
        $("restorePythonPackages").checked = false;
        updateBackupButtons();
        return;
      }

      $("backupDetails").classList.remove("hidden");
      $("backupRestoreOptions").classList.remove("hidden");
      $("backupDetails").innerHTML = item.valid ? `
        <div><strong>Created</strong>${escapeHtml(backupDateLabel(item.created_at))}</div>
        <div><strong>Contents</strong>${item.custom_node_count} custom node package(s), ${item.python_package_count} Python package(s)</div>
        <div><strong>Custom nodes destination</strong><span class="path">${escapeHtml(item.custom_nodes_path || "Not included")}</span></div>
        <div><strong>Virtual environment</strong><span class="path">${escapeHtml(item.venv_path || "Not included")}</span></div>
        <div><strong>Backup size</strong>${escapeHtml(formatBytes(item.size_bytes))}</div>
      ` : `<div><strong>Invalid backup</strong><span class="muted">${escapeHtml(item.error || "The backup could not be read.")}</span></div>`;

      $("restoreCustomNodes").disabled = backupBusy || !item.valid || !item.has_custom_nodes;
      $("restorePythonPackages").disabled = backupBusy || !item.valid || !item.has_python_packages;
      $("restoreCustomNodes").checked = item.valid && item.has_custom_nodes;
      $("restorePythonPackages").checked = item.valid && item.has_python_packages;
      updateBackupButtons();
    }

    function setBackupBusy(busy, status = "") {
      backupBusy = busy;
      $("backupManagerPath").disabled = busy;
      $("backupSelect").disabled = busy;
      $("refreshBackupsBtn").disabled = busy;
      const browseButton = document.querySelector('[data-target="backupManagerPath"]');
      if (browseButton) browseButton.disabled = busy;
      $("backupStatus").textContent = status;
      const item = selectedBackup();
      $("restoreCustomNodes").disabled = busy || !item || !item.valid || !item.has_custom_nodes;
      $("restorePythonPackages").disabled = busy || !item || !item.valid || !item.has_python_packages;
      updateBackupButtons();
    }

    async function loadBackups(preserveSelection = true) {
      const previous = preserveSelection ? $("backupSelect").value : "";
      setBackupBusy(true, "Loading backups...");
      try {
        const result = await postJson("/api/backups/list", {
          backup_path: $("backupManagerPath").value
        });
        backups = result.backups || [];
        if (!backups.length) {
          $("backupSelect").innerHTML = `<option value="">No backups found</option>`;
        } else {
          $("backupSelect").innerHTML = backups.map((item) => {
            const invalid = item.valid ? "" : " (invalid)";
            return `<option value="${escapeHtml(item.name)}">${escapeHtml(backupDateLabel(item.created_at))}${invalid}</option>`;
          }).join("");
          if (previous && backups.some((item) => item.name === previous)) {
            $("backupSelect").value = previous;
          }
        }
        $("backupStatus").textContent = backups.length === 1 ? "1 backup found." : `${backups.length} backups found.`;
        renderBackupSelection();
      } catch (error) {
        backups = [];
        $("backupSelect").innerHTML = `<option value="">Backups unavailable</option>`;
        $("backupDetails").classList.add("hidden");
        $("backupRestoreOptions").classList.add("hidden");
        $("backupOutput").innerHTML = `<div class="notice error">${escapeHtml(error.message)}</div>`;
        $("backupStatus").textContent = "";
      } finally {
        setBackupBusy(false, $("backupStatus").textContent);
      }
    }

    function selectedCleanupItems() {
      return {
        nodePaths: Array.from(document.querySelectorAll(".node-check:checked")).map((box) => box.value),
        pythonPackages: Array.from(document.querySelectorAll(".py-check:checked")).map((box) => box.value)
      };
    }

    function clearSizeEstimate() {
      sizeRequestVersion += 1;
      $("sizeOutput").innerHTML = "";
    }

    function renderScanJob(job) {
      $("scanProgress").classList.remove("hidden");
      $("scanProgressTitle").textContent = `${job.phase || "Scanning"} - ${Math.round(job.progress || 0)}%`;
      $("scanProgressMessage").textContent = job.message || "";
      $("scanProgressMeta").textContent = `Elapsed ${formatDuration(job.elapsed_seconds)} | Remaining ${formatDuration(job.eta_seconds)}`;
      $("scanProgressBar").style.width = `${Math.max(0, Math.min(100, job.progress || 0))}%`;
      const rows = (job.log || []).map((entry) => `
        <div class="scan-log-row">
          <span>${escapeHtml(entry.time || "")}</span>
          <span>${escapeHtml(entry.phase || "")}</span>
          <span>${escapeHtml(entry.message || "")}</span>
        </div>
      `).join("");
      $("scanLog").innerHTML = rows || `<div class="scan-log-row"><span>00:00</span><span>Queued</span><span>Waiting for scan to start.</span></div>`;
      $("scanLog").scrollTop = $("scanLog").scrollHeight;
    }

    function stopScanPolling() {
      if (scanPollTimer) {
        clearTimeout(scanPollTimer);
        scanPollTimer = null;
      }
    }

    async function pollScanJob(jobId) {
      try {
        const job = await getJson(`/api/scan-status?job_id=${encodeURIComponent(jobId)}`);
        renderScanJob(job);
        if (job.status === "complete") {
          stopScanPolling();
          renderScan(job.result);
          setStatus("Scan complete.");
          $("scanBtn").disabled = false;
          return;
        }
        if (job.status === "error") {
          stopScanPolling();
          $("messages").innerHTML = `<div class="notice error">${escapeHtml(job.error || job.message || "Scan failed.")}</div>`;
          setStatus("");
          $("scanBtn").disabled = false;
          return;
        }
        scanPollTimer = setTimeout(() => pollScanJob(jobId), 1000);
      } catch (error) {
        stopScanPolling();
        $("messages").innerHTML = `<div class="notice error">${escapeHtml(error.message)}</div>`;
        setStatus("");
        $("scanBtn").disabled = false;
      }
    }

    async function applyComfyDefaults() {
      const comfyPath = $("comfyPath").value.trim();
      if (!comfyPath) return;
      try {
        const defaults = await postJson("/api/default-paths", {
          comfyui_path: comfyPath
        });

        if (!$("workflowPath").value.trim() || autoFilledPath.workflowPath) {
          $("workflowPath").value = defaults.workflows_path || "";
          autoFilledPath.workflowPath = Boolean(defaults.workflows_path);
        }

        if (!$("venvPath").value.trim() || autoFilledPath.venvPath) {
          $("venvPath").value = defaults.venv_path || "";
          autoFilledPath.venvPath = Boolean(defaults.venv_path);
        }
      } catch (error) {
        $("messages").innerHTML = `<div class="notice warn">${escapeHtml(error.message)}</div>`;
      }
    }

    ["venvPath", "workflowPath"].forEach((id) => {
      $(id).addEventListener("input", () => {
        autoFilledPath[id] = false;
      });
    });

    $("comfyPath").addEventListener("change", applyComfyDefaults);
    $("comfyPath").addEventListener("blur", applyComfyDefaults);

    document.querySelectorAll(".browse-btn").forEach((button) => {
      button.addEventListener("click", async () => {
        const targetId = button.getAttribute("data-target");
        if (!targetId) return;
        button.disabled = true;
        const originalText = button.textContent;
        button.textContent = "Selecting...";
        try {
          const result = await postJson("/api/pick-path", {
            title: button.getAttribute("data-title") || "Select folder",
            initial_path: $(targetId).value
          });
          if (result.path) {
            $(targetId).value = result.path;
            if (targetId === "venvPath" || targetId === "workflowPath") {
              autoFilledPath[targetId] = false;
            }
            if (targetId === "comfyPath") {
              await applyComfyDefaults();
            }
            if (targetId === "backupManagerPath") {
              await loadBackups(false);
            }
          }
        } catch (error) {
          $("messages").innerHTML = `<div class="notice error">${escapeHtml(error.message)}</div>`;
        } finally {
          button.textContent = originalText;
          button.disabled = false;
        }
      });
    });

    $("refreshBackupsBtn").addEventListener("click", () => loadBackups());
    $("backupManagerPath").addEventListener("change", () => loadBackups(false));
    $("backupSelect").addEventListener("change", renderBackupSelection);
    $("restoreCustomNodes").addEventListener("change", updateBackupButtons);
    $("restorePythonPackages").addEventListener("change", updateBackupButtons);

    $("restoreBackupBtn").addEventListener("click", async () => {
      const item = selectedBackup();
      if (!item || !item.valid) return;
      const restoreNodes = $("restoreCustomNodes").checked;
      const restorePython = $("restorePythonPackages").checked;
      const components = [restoreNodes ? "custom nodes" : "", restorePython ? "Python packages" : ""].filter(Boolean);
      if (!components.length) return;
      const ok = window.confirm(`Restore ${components.join(" and ")} from ${item.name}? ComfyUI should be stopped during restoration.`);
      if (!ok) return;

      setBackupBusy(true, "Restoring backup...");
      $("backupOutput").innerHTML = `<div class="notice">Restoration is running.</div>`;
      try {
        const result = await postJson("/api/backups/restore", {
          backup_path: $("backupManagerPath").value,
          backup_name: item.name,
          restore_custom_nodes: restoreNodes,
          restore_python_packages: restorePython
        });
        $("backupStatus").textContent = "Restore complete. Restart ComfyUI before using the restored components.";
        $("backupOutput").innerHTML = `<pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>`;
      } catch (error) {
        $("backupStatus").textContent = "Restore failed.";
        $("backupOutput").innerHTML = `<div class="notice error">${escapeHtml(error.message)}</div>`;
      } finally {
        setBackupBusy(false, $("backupStatus").textContent);
      }
    });

    $("deleteBackupBtn").addEventListener("click", async () => {
      const item = selectedBackup();
      if (!item) return;
      const ok = window.confirm(`Permanently delete backup ${item.name}? This cannot be undone.`);
      if (!ok) return;

      setBackupBusy(true, "Deleting backup...");
      try {
        await postJson("/api/backups/delete", {
          backup_path: $("backupManagerPath").value,
          backup_name: item.name
        });
        await loadBackups(false);
        $("backupStatus").textContent = "Backup deleted.";
        $("backupOutput").innerHTML = `<div class="notice">Backup deleted.</div>`;
      } catch (error) {
        $("backupStatus").textContent = "Deletion failed.";
        $("backupOutput").innerHTML = `<div class="notice error">${escapeHtml(error.message)}</div>`;
      } finally {
        setBackupBusy(false, $("backupStatus").textContent);
      }
    });

    $("scanBtn").addEventListener("click", async () => {
      stopScanPolling();
      const missing = [];
      if (!$("comfyPath").value.trim()) missing.push("ComfyUI installation path");
      if (!$("venvPath").value.trim()) missing.push("Virtual environment path");
      if (!$("workflowPath").value.trim()) missing.push("Workflows path");
      if (missing.length) {
        $("messages").innerHTML = `<div class="notice error">Set the following path(s) before scanning: ${escapeHtml(missing.join(", "))}.</div>`;
        setStatus("");
        return;
      }
      $("scanBtn").disabled = true;
      setStatus("Scanning...");
      $("cleanOutput").innerHTML = "";
      $("results").classList.add("hidden");
      try {
        const job = await postJson("/api/scan", {
          comfyui_path: $("comfyPath").value,
          venv_path: $("venvPath").value,
          workflows_path: $("workflowPath").value
        });
        renderScanJob(job);
        pollScanJob(job.job_id);
      } catch (error) {
        $("messages").innerHTML = `<div class="notice error">${escapeHtml(error.message)}</div>`;
        setStatus("");
        $("scanBtn").disabled = false;
      }
    });

    $("clearBtn").addEventListener("click", () => {
      document.querySelectorAll(".node-check, .py-check").forEach((box) => { box.checked = false; });
      syncDependentPythonChoices();
      clearSizeEstimate();
    });

    $("selectNodesBtn").addEventListener("click", () => {
      document.querySelectorAll(".node-check").forEach((box) => { box.checked = true; });
      syncDependentPythonChoices();
      clearSizeEstimate();
    });

    $("deselectNodesBtn").addEventListener("click", () => {
      document.querySelectorAll(".node-check").forEach((box) => { box.checked = false; });
      syncDependentPythonChoices();
      clearSizeEstimate();
    });

    $("selectPyBtn").addEventListener("click", () => {
      document.querySelectorAll(".py-check:not(:disabled)").forEach((box) => { box.checked = true; });
      clearSizeEstimate();
    });

    $("deselectPyBtn").addEventListener("click", () => {
      document.querySelectorAll(".py-check").forEach((box) => { box.checked = false; });
      clearSizeEstimate();
    });

    $("unusedNodes").addEventListener("change", (event) => {
      if (event.target.matches(".node-check")) {
        syncDependentPythonChoices();
        clearSizeEstimate();
      }
    });

    $("pythonPackages").addEventListener("change", (event) => {
      if (event.target.matches(".py-check")) clearSizeEstimate();
    });

    $("sizeBtn").addEventListener("click", async () => {
      if (!currentScan) return;
      const {nodePaths, pythonPackages} = selectedCleanupItems();
      if (!nodePaths.length && !pythonPackages.length) {
        $("sizeOutput").innerHTML = `<div class="notice warn">Select at least one item.</div>`;
        return;
      }

      const requestVersion = ++sizeRequestVersion;
      $("sizeBtn").disabled = true;
      $("cleanBtn").disabled = true;
      $("sizeOutput").innerHTML = `<div class="notice">Calculating selected file sizes...</div>`;
      try {
        const result = await postJson("/api/calculate-size", {
          scan_id: currentScan.scan_id,
          custom_node_paths: nodePaths,
          python_packages: pythonPackages
        });
        if (requestVersion !== sizeRequestVersion) return;
        const warning = (result.warnings || []).length
          ? `<div class="notice warn">${escapeHtml(result.warnings.join(" "))}</div>`
          : "";
        const fileCount = Number(result.total_file_count || 0);
        const fileLabel = fileCount === 1 ? "file" : "files";
        $("sizeOutput").innerHTML = `
          <div class="notice">
            <strong>Estimated removable size: ${escapeHtml(formatBytes(result.total_bytes))}</strong>
            (${fileCount.toLocaleString()} ${fileLabel}).
            Custom nodes: ${escapeHtml(formatBytes(result.custom_nodes.bytes))}.
            Python packages: ${escapeHtml(formatBytes(result.python_packages.bytes))}.
          </div>
          ${warning}
        `;
      } catch (error) {
        if (requestVersion === sizeRequestVersion) {
          $("sizeOutput").innerHTML = `<div class="notice error">${escapeHtml(error.message)}</div>`;
        }
      } finally {
        $("sizeBtn").disabled = false;
        $("cleanBtn").disabled = false;
      }
    });

    $("cleanBtn").addEventListener("click", async () => {
      if (!currentScan) return;
      const {nodePaths, pythonPackages} = selectedCleanupItems();
      if (!nodePaths.length && !pythonPackages.length) {
        $("cleanStatus").textContent = "Select at least one item.";
        return;
      }
      const ok = window.confirm("Clean the selected items?");
      if (!ok) return;
      $("cleanBtn").disabled = true;
      $("sizeBtn").disabled = true;
      $("cleanStatus").textContent = "Cleaning...";
      try {
        const result = await postJson("/api/clean", {
          scan_id: currentScan.scan_id,
          custom_node_paths: nodePaths,
          python_packages: pythonPackages,
          backup_enabled: $("backupEnabled").checked,
          backup_path: $("backupPath").value
        });
        clearSizeEstimate();
        $("cleanStatus").textContent = result.ok ? "Cleanup complete." : "Cleanup completed with errors.";
        $("cleanOutput").innerHTML = `<pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>`;
        if (result.backup && result.backup.ok) {
          $("backupManagerPath").value = $("backupPath").value;
          await loadBackups(false);
        }
      } catch (error) {
        $("cleanStatus").textContent = "";
        $("cleanOutput").innerHTML = `<div class="notice error">${escapeHtml(error.message)}</div>`;
      } finally {
        $("cleanBtn").disabled = false;
        $("sizeBtn").disabled = false;
      }
    });

    $("shutdownBtn").addEventListener("click", async () => {
      const ok = window.confirm("Shut down ComfyUI Cleaner? The browser page will stop communicating with the local server.");
      if (!ok) return;
      $("shutdownBtn").disabled = true;
      $("shutdownBtn").textContent = "Shutting down...";
      setStatus("Server is shutting down.");
      $("messages").innerHTML = `<div class="notice">ComfyUI Cleaner is shutting down. You can close this browser tab after the button stops changing.</div>`;
      try {
        await new Promise((resolve) => setTimeout(resolve, 250));
        await postJson("/api/shutdown", {});
        stopScanPolling();
        setStatus("Server has been shut down.");
        $("messages").innerHTML = `<div class="notice">ComfyUI Cleaner has shut down. You can close this browser tab.</div>`;
        $("shutdownBtn").textContent = "Shut down";
      } catch (error) {
        setStatus("Shutdown was not completed.");
        $("messages").innerHTML = `<div class="notice error">${escapeHtml(error.message)}</div>`;
        $("shutdownBtn").textContent = "Shut down";
        $("shutdownBtn").disabled = false;
      }
    });

    loadBackups(false);
  </script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ComfyUICleaner/1.0"
    app_server: ThreadingHTTPServer | None = None

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def validate_post_request(self) -> tuple[int, str] | None:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            return 415, "Requests must use the application/json content type."

        try:
            content_length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            return 400, "Invalid Content-Length header."
        if content_length < 0:
            return 400, "Invalid Content-Length header."
        if content_length > MAX_REQUEST_BODY_BYTES:
            return 413, "Request body is too large."

        origin = self.headers.get("Origin")
        if origin:
            parsed_origin = urllib.parse.urlparse(origin)
            try:
                origin_port = parsed_origin.port
            except ValueError:
                return 403, "Cross-origin requests are not allowed."
            if (
                parsed_origin.scheme != "http"
                or parsed_origin.hostname not in {"127.0.0.1", "localhost"}
                or origin_port != APP_PORT
            ):
                return 403, "Cross-origin requests are not allowed."
        return None

    def send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/health":
            self.send_json({"ok": True, "app": "comfyui-cleaner"})
            return
        if parsed.path == "/api/scan-status":
            params = urllib.parse.parse_qs(parsed.query)
            job_id = (params.get("job_id") or [""])[0]
            snapshot = scan_job_snapshot(job_id)
            if not snapshot:
                self.send_json({"error": "Scan job was not found."}, 404)
                return
            self.send_json(snapshot)
            return
        if parsed.path not in {"/", "/index.html"}:
            self.send_json({"error": "Not found"}, 404)
            return
        encoded = HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:
        validation_error = self.validate_post_request()
        if validation_error:
            status, message = validation_error
            self.send_json({"error": message}, status)
            return
        try:
            payload = self.read_json()
            if not isinstance(payload, dict):
                self.send_json({"error": "Request body must be a JSON object."}, 400)
                return
            if self.path == "/api/scan":
                result = start_scan_job(
                    str(payload.get("comfyui_path") or ""),
                    str(payload.get("venv_path") or ""),
                    str(payload.get("workflows_path") or ""),
                )
                self.send_json(result, 200 if result.get("ok", True) else 409)
                return
            if self.path == "/api/backups/list":
                result = list_backups(str(payload.get("backup_path") or "").strip() or None)
                self.send_json(result, 200 if result.get("ok") else 400)
                return
            if self.path == "/api/backups/restore":
                block_reason = begin_exclusive_operation("Backup restore")
                if block_reason:
                    self.send_json({"ok": False, "error": block_reason}, 409)
                    return
                try:
                    result = restore_backup(payload)
                finally:
                    end_exclusive_operation()
                self.send_json(result, 200 if result.get("ok") else 400)
                return
            if self.path == "/api/backups/delete":
                block_reason = begin_exclusive_operation("Backup deletion")
                if block_reason:
                    self.send_json({"ok": False, "error": block_reason}, 409)
                    return
                try:
                    result = delete_backup(
                        str(payload.get("backup_path") or "").strip() or None,
                        str(payload.get("backup_name") or ""),
                    )
                finally:
                    end_exclusive_operation()
                self.send_json(result, 200 if result.get("ok") else 400)
                return
            if self.path == "/api/calculate-size":
                with SCAN_LOCK:
                    active_operation = ACTIVE_OPERATION
                if active_operation:
                    self.send_json({"ok": False, "error": f"Wait for {active_operation.lower()} to finish before calculating size."}, 409)
                    return
                result = calculate_cleanup_size(payload)
                self.send_json(result, 200 if result.get("ok") else 400)
                return
            if self.path == "/api/clean":
                block_reason = begin_cleanup()
                if block_reason:
                    self.send_json({"ok": False, "error": block_reason}, 409)
                    return
                try:
                    result = run_clean(payload)
                finally:
                    end_cleanup()
                self.send_json(result, 200 if result.get("ok") else 400)
                return
            if self.path == "/api/default-paths":
                result = default_paths_for_comfy(str(payload.get("comfyui_path") or ""))
                self.send_json(result, 200 if result.get("ok") else 400)
                return
            if self.path == "/api/pick-path":
                result = pick_local_path(
                    str(payload.get("title") or "Select folder"),
                    str(payload.get("initial_path") or ""),
                )
                self.send_json(result, 200 if result.get("ok") else 400)
                return
            if self.path == "/api/shutdown":
                block_reason = shutdown_block_reason()
                if block_reason:
                    self.send_json({"ok": False, "error": block_reason}, 409)
                    return
                self.send_json({"ok": True, "message": "Server is shutting down."})

                def shutdown_server() -> None:
                    time.sleep(1.0)
                    server = type(self).app_server
                    if server:
                        server.shutdown()

                threading.Thread(target=shutdown_server, daemon=True).start()
                return
            self.send_json({"error": "Not found"}, 404)
        except json.JSONDecodeError:
            self.send_json({"error": "Request body is not valid JSON."}, 400)
        except Exception as exc:
            traceback.print_exc()
            self.send_json(
                {"error": f"Internal server error: {exc}"},
                500,
            )


def main() -> None:
    server = ThreadingHTTPServer((APP_HOST, APP_PORT), Handler)
    Handler.app_server = server
    print(f"ComfyUI Cleaner: http://{APP_HOST}:{APP_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
