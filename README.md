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
- The selected ComfyUI folder is validated by checking for `main.py`; a Windows Portable parent folder is normalized to its nested `ComfyUI` folder.
- When the ComfyUI installation path is set, the workflows path is filled automatically as `ComfyUI\user\default\workflows` if the field has not been set manually.
- The application also checks common venv paths such as `ComfyUI\venv`, `ComfyUI\.venv`, `..\venv`, and `..\.venv`, and fills the virtual environment path if a suitable Python interpreter is found.
- Reads ComfyUI workflow JSON files and embedded `workflow`/`prompt` metadata from PNG files. Bypassed and muted nodes still count as used.
- Reads package directories and standalone Python nodes under `ComfyUI/custom_nodes`.
- Resolves legacy V1 `NODE_CLASS_MAPPINGS` assignments and modern V3 `comfy_entrypoint` / `get_node_list` / `Schema(node_id=...)` registrations.
- Marks a custom node package as unused only when its mapping is complete, every workflow file was read successfully, and no scanned workflow uses its node types. Dynamic or incomplete mappings remain `unknown`.
- Reads installed Python packages from the selected virtual environment.
- Compares Python packages against regular and literal dynamic imports, Python module/command invocations, recursive requirements files, `pyproject.toml`, `setup.cfg`, `setup.py`, installed dependency metadata, startup hooks, and plugin entry points.
- Reports confidence and evidence for removal candidates. Unresolved active dynamic loading downgrades affected Python results to `review` confidence.
- Shows scan progress, a phase log, elapsed time, and an estimated remaining time while scanning.
- Provides per-list select and deselect controls and can estimate the total file size of the current cleanup selection.
- Runs only one scan or cleanup operation at a time and prevents shutdown while one is active.
- Recognizes a Windows Portable root containing `ComfyUI` and its sibling `python_embeded` directory.

## Reset Settings

Use **Preview reset** to inspect the selected profile's `comfy.settings.json`, then stop ComfyUI, close its tabs, and choose **Back up and reset settings**. The profile defaults to `default`; specify a user directory when using ComfyUI's `--user-directory` option. Backups use the folder selected in Backup management.

Reset affects Settings-menu preferences, including extension preferences stored in that file. It does not clear browser storage, workflows, models, outputs, or separate custom-node configuration files. A missing settings file already uses defaults. Changed files require a new preview, and backup failures prevent reset.

Settings backups appear in **Backup management**. Select **Settings** and **Restore selected** with the original installation, user directory and profile selected. Restoration backs up current settings before replacing them. Keep ComfyUI stopped during restoration.

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

Unknown custom node packages can be selected manually. The first selection on each page load asks you to acknowledge that unknown does not mean unused and removal may break workflows or extensions. Cancelling leaves the package unselected. The unused-package Select all button excludes unknown packages. Manual selections participate in size calculation, backup, quarantine, and restoration. Their Python dependencies remain protected by the existing dependency analysis.

Compatibility checked against ComfyUI v0.37.0 (2026-09-27), including V1 and V3 registration and declared Python requirements. Python source files are read using Python's encoding detection, including UTF-8 BOM and encoding declarations. Python packages with no detected use remain review candidates rather than proven unnecessary.

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

## License

Licensed under the [MIT License](LICENSE).
