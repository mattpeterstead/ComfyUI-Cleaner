# ComfyUI Cleaner

A local WebGUI for cleaning up a ComfyUI installation.

## Startup

On Windows, you can start the application directly:

```powershell
.\start.bat
```

It opens a visible server window and opens the browser at `http://127.0.0.1:8765/`.

Use the `Shutdown` button in the WebGUI to stop the local server. You can also stop it from the visible server window by pressing `Ctrl+C` or closing that window. Closing only the browser tab does not stop the server.

Alternatively:

```powershell
python app.py
```

Open in your browser:

```text
http://127.0.0.1:8765
```

## What The Application Does

- Paths can be typed manually or selected with the `Browse` buttons, which open the system folder picker dialog.
- The ComfyUI installation, virtual environment, and workflows paths must all be set before scanning.
- When the ComfyUI installation path is set, the workflows path is filled automatically as `ComfyUI\user\default\workflows` if the field has not been set manually.
- The application also checks common venv paths such as `ComfyUI\venv`, `ComfyUI\.venv`, `..\venv`, and `..\.venv`, and fills the virtual environment path if a suitable Python interpreter is found.
- Reads ComfyUI workflow JSON files and embedded `workflow`/`prompt` metadata from PNG files. Bypassed and muted nodes still count as used.
- Reads package directories and standalone Python nodes under `ComfyUI/custom_nodes`.
- Resolves static `NODE_CLASS_MAPPINGS` assignments, dictionary constructors, merges, updates, and key assignments.
- Marks a custom node package as unused only when its mapping is complete, every workflow file was read successfully, and no scanned workflow uses its node types. Dynamic or incomplete mappings remain `unknown`.
- Reads installed Python packages from the selected virtual environment.
- Compares Python packages against regular and literal dynamic imports, Python module/command invocations, recursive requirements files, `pyproject.toml`, `setup.cfg`, `setup.py`, installed dependency metadata, startup hooks, and plugin entry points.
- Reports confidence and evidence for removal candidates. Unresolved active dynamic loading downgrades affected Python results to `review` confidence.
- Shows scan progress, a phase log, elapsed time, and an estimated remaining time while scanning.
- Provides per-list select and deselect controls and can estimate the total file size of the current cleanup selection.
- Runs only one scan or cleanup operation at a time and prevents shutdown while one is active.

## Cleanup

Before cleanup, the application creates a backup by default. If the backup folder is left empty, the backup is created in the application's own `backups` folder.

Custom node packages are moved from the active `custom_nodes` folder to quarantine outside the active custom node search path:

```text
ComfyUI/_comfyui_cleaner_removed/<timestamp>/
```

Python packages are removed from the selected virtual environment with:

```powershell
python -m pip uninstall -y <packages>
```

Python packages categorized as required only by unused custom nodes remain locked until every related custom node package is also selected for removal. The server validates this relationship again before cleanup.

Static analysis is conservative: uncertain custom nodes are not removable, while Python packages with no detected use are explicitly labeled as review candidates rather than proven unnecessary.

## Backups

The backup folder contains:

- `custom_nodes.zip`, containing the selected custom node folders or standalone files.
- `pip-freeze-before.txt`, containing the virtual environment's Python packages before cleanup.
- `selected-python-packages.txt`, containing the selected Python packages with versions.
- `manifest.json`, containing paths, selections, and restore information.

The WebGUI's **Backup management** section lists backups from the selected backup folder. A backup can restore custom nodes, Python packages, or both. Custom nodes are restored to the original `custom_nodes` path and existing files are never overwritten. Python packages are reinstalled into the virtual environment recorded in `manifest.json`.

Backups can also be permanently deleted from the same section. Deletion is limited to managed `comfyui-cleaner-backup-*` folders that contain a manifest.

The equivalent manual Python package restore command is:

```powershell
python -m pip install -r selected-python-packages.txt
```

## Tests

Run the focused safety tests with:

```powershell
python -m unittest -v
```
