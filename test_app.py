import json
import shutil
import tempfile
import threading
import unittest
import urllib.request
import zipfile
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

import app


class SettingsResetTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).parent / f".path-test-{app.uuid.uuid4().hex}"
        self.root.mkdir()
        self.addCleanup(shutil.rmtree, self.root)
        (self.root / "main.py").touch()
        self.target = self.root / "user" / "default" / "comfy.settings.json"
        self.target.parent.mkdir(parents=True)
        self.original = b'{"Comfy.Test": true}'
        self.target.write_bytes(self.original)
        self.payload = {"comfyui_path": str(self.root), "backup_path": str(self.root / "backups"), "confirmed_stopped": True}

    def test_reset_and_restore_preserve_workflows_and_back_up_replaced_settings(self):
        workflow = self.target.parent / "workflows" / "example.json"
        workflow.parent.mkdir()
        workflow.write_text("workflow")
        preview = app.reset_settings(self.payload, preview=True)
        self.assertEqual(self.target.read_bytes(), self.original)
        reset = app.reset_settings({**self.payload, "sha256": preview["sha256"]})
        self.assertEqual(json.loads(self.target.read_bytes()), {})
        self.assertEqual(workflow.read_text(), "workflow")
        listing = app.list_backups(self.payload["backup_path"])
        self.assertTrue(listing["backups"][0]["has_settings"])
        self.target.write_bytes(b'{"new": 1}')
        restored = app.restore_backup({**self.payload, "restore_settings": True, "backup_name": Path(reset["backup_dir"]).name})
        self.assertTrue(restored["ok"], restored)
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertEqual((Path(restored["safety_backup"]) / "settings.bin").read_bytes(), b'{"new": 1}')

    def test_changed_settings_cancel_reset(self):
        preview = app.reset_settings(self.payload, preview=True)
        self.target.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "Settings changed"):
            app.reset_settings({**self.payload, "sha256": preview["sha256"]})
        self.assertEqual(self.target.read_bytes(), b"changed")

    def test_backup_failure_leaves_settings_unchanged(self):
        preview = app.reset_settings(self.payload, preview=True)
        with patch("app.settings_backup", side_effect=OSError("Disk full")):
            with self.assertRaises(OSError):
                app.reset_settings({**self.payload, "sha256": preview["sha256"]})
        self.assertEqual(self.target.read_bytes(), self.original)

    def test_profile_traversal_and_unconfirmed_reset_are_rejected(self):
        with self.assertRaises(ValueError):
            app.reset_settings({**self.payload, "profile": "../other"}, preview=True)
        with self.assertRaises(ValueError):
            app.reset_settings({**self.payload, "confirmed_stopped": False})

    def test_corrupt_backup_cannot_overwrite_settings(self):
        preview = app.reset_settings(self.payload, preview=True)
        reset = app.reset_settings({**self.payload, "sha256": preview["sha256"]})
        backup = Path(reset["backup_dir"])
        (backup / "settings.bin").write_bytes(b"tampered")
        result = app.restore_backup({**self.payload, "restore_settings": True, "backup_name": backup.name})
        self.assertFalse(result["ok"])
        self.assertEqual(json.loads(self.target.read_bytes()), {})


class ServerLifecycleTests(unittest.TestCase):
    def test_shutdown_endpoint_stops_the_server(self) -> None:
        server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            host, port = server.server_address
            request = urllib.request.Request(
                f"http://{host}:{port}/api/shutdown",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                result = json.load(response)

            self.assertTrue(result["ok"])
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class PythonPackageSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.node_path = str(Path(tempfile.gettempdir()) / "custom_nodes" / "example-node")
        self.custom_package = app.CustomNodePackage(
            name="example-node",
            path=self.node_path,
            status="unused",
            requirements={"example-lib"},
        )
        self.venv_info = {
            "packages": {
                "example-lib": {"name": "example-lib", "version": "1.0"},
                "example-dependency": {"name": "example-dependency", "version": "2.0"},
            },
            "requires": {
                "example-lib": ["example-dependency>=2"],
                "example-dependency": [],
            },
            "top_level_to_dists": {},
        }

    def test_unused_node_dependencies_include_requiring_node_paths(self) -> None:
        summary = app.summarize_python_packages(set(), set(), [self.custom_package], self.venv_info)

        candidates = {
            item["normalized_name"]: item
            for item in summary["only_unused_custom_nodes"]
        }
        self.assertEqual(
            candidates["example-dependency"]["required_by_custom_node_paths"],
            [self.node_path],
        )

    def test_python_dependency_is_blocked_until_node_is_selected(self) -> None:
        summary = app.summarize_python_packages(set(), set(), [self.custom_package], self.venv_info)
        scan = {"python_packages": summary}

        blocked = app.validate_python_selection(["example-lib"], set(), scan)
        allowed = app.validate_python_selection(["example-lib"], {self.node_path}, scan)

        self.assertFalse(blocked["allowed"])
        self.assertEqual(len(blocked["blocked"]), 1)
        self.assertEqual(allowed["allowed"], ["example-lib"])
        self.assertFalse(allowed["blocked"])

    def test_unresolved_active_loading_downgrades_python_confidence(self) -> None:
        unknown_package = app.CustomNodePackage(
            name="dynamic-loader",
            path=str(Path(self.node_path).parent / "dynamic-loader"),
            status="unknown",
            usage_uncertain=True,
        )
        summary = app.summarize_python_packages(
            set(),
            set(),
            [self.custom_package, unknown_package],
            self.venv_info,
        )

        self.assertTrue(summary["active_usage_uncertain"])
        self.assertTrue(
            all(item["confidence"] == "review" for item in summary["only_unused_custom_nodes"])
        )

    def test_cleanup_rejects_unsafe_python_selection_before_side_effects(self) -> None:
        summary = app.summarize_python_packages(set(), set(), [self.custom_package], self.venv_info)
        scan_id = "cleanup-safety-test"
        scan = {
            "scan_id": scan_id,
            "paths": {"custom_nodes": str(Path(self.node_path).parent), "venv": ""},
            "custom_nodes": [
                {"name": self.custom_package.name, "path": self.node_path, "status": "unused"}
            ],
            "python_packages": summary,
        }
        with app.SCAN_LOCK:
            app.SCAN_CACHE[scan_id] = scan
        try:
            result = app.run_clean(
                {
                    "scan_id": scan_id,
                    "custom_node_paths": [],
                    "python_packages": ["example-lib"],
                    "backup_enabled": False,
                }
            )
        finally:
            with app.SCAN_LOCK:
                app.SCAN_CACHE.pop(scan_id, None)

        self.assertFalse(result["ok"])
        self.assertIn("safety checks", result["error"])
        self.assertIsNone(result["backup"])


class UnknownNodeRemovalTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).parent / f".path-test-{app.uuid.uuid4().hex}"
        self.node = self.root / "custom_nodes" / "unknown-package"
        self.node.mkdir(parents=True)
        (self.node / "__init__.py").write_bytes(b"# dynamic registration\n")
        self.addCleanup(shutil.rmtree, self.root)
        self.scan_id = app.uuid.uuid4().hex
        self.scan = {
            "paths": {"custom_nodes": str(self.node.parent), "venv": ""},
            "custom_nodes": [{"path": str(self.node), "name": self.node.name, "status": "unknown", "confidence": "low"}],
            "python_packages": {},
        }
        app.SCAN_CACHE[self.scan_id] = self.scan
        self.addCleanup(app.SCAN_CACHE.pop, self.scan_id)
        self.payload = {"scan_id": self.scan_id, "custom_node_paths": [str(self.node)],
                        "backup_path": str(self.root / "backups")}

    def test_unknown_requires_boolean_acknowledgment_before_side_effects(self):
        for acknowledgment in (None, False, "true"):
            payload = {**self.payload, "acknowledge_unknown_nodes": acknowledgment}
            self.assertFalse(app.run_clean(payload)["ok"])
            self.assertFalse(app.calculate_cleanup_size(payload)["ok"])
            self.assertTrue(self.node.exists())
            self.assertFalse((self.root / "backups").exists())

    def test_acknowledged_unknown_size_backup_quarantine_and_restore(self):
        payload = {**self.payload, "acknowledge_unknown_nodes": True}
        size = app.calculate_cleanup_size(payload)
        self.assertTrue(size["ok"], size)
        self.assertEqual(size["total_bytes"], len(b"# dynamic registration\n"))
        result = app.run_clean(payload)
        self.assertTrue(result["ok"], result)
        self.assertFalse(self.node.exists())
        restored = app.restore_backup({"backup_path": self.payload["backup_path"],
            "backup_name": Path(result["backup"]["backup_dir"]).name,
            "restore_custom_nodes": True, "restore_python_packages": False})
        self.assertTrue(restored["ok"], restored)
        self.assertEqual((self.node / "__init__.py").read_bytes(), b"# dynamic registration\n")

    def test_acknowledgment_does_not_allow_used_or_unscanned_nodes(self):
        self.scan["custom_nodes"][0]["status"] = "used"
        self.assertFalse(app.run_clean({**self.payload, "acknowledge_unknown_nodes": True})["ok"])
        result = app.validate_cleanup_selection(self.scan, {str(self.root / "other")}, [], True)
        self.assertTrue(result["invalid_node_paths"])

    def test_python_bom_and_declared_encoding_preserve_dependencies(self):
        source = self.node / "__init__.py"
        for data in (b'\xef\xbb\xbfimport trimesh\nNODE_CLASS_MAPPINGS = {"MeshNode": object}\n',
                     b'# coding: latin-1\n# caf\xe9\nimport trimesh\nNODE_CLASS_MAPPINGS = {"MeshNode": object}\n'):
            source.write_bytes(data)
            result = app.parse_python_file(source)
            self.assertTrue(result.parse_ok)
            self.assertIn("trimesh", result.imports)
            self.assertEqual(result.node_types, {"MeshNode"})

    def test_third_party_syntax_warnings_do_not_spam_scan_console(self):
        source = self.node / "__init__.py"
        source.write_text('import trimesh\npattern = "\\s"\n', encoding="utf-8")
        with app.warnings.catch_warnings(record=True) as captured:
            app.warnings.simplefilter("always")
            result = app.parse_python_file(source)
        self.assertTrue(result.parse_ok)
        self.assertIn("trimesh", result.imports)
        self.assertEqual(captured, [])
        source.write_text('def broken(:\n', encoding="utf-8")
        self.assertFalse(app.parse_python_file(source).parse_ok)


class ScanValidationTests(unittest.TestCase):
    def test_bypassed_and_muted_nodes_are_counted_as_used(self) -> None:
        workflow = {
            "nodes": [
                {"type": "BypassedNode", "mode": 4},
                {"type": "MutedNode", "mode": 2},
            ]
        }

        self.assertEqual(
            app.extract_workflow_node_types(workflow),
            {"BypassedNode", "MutedNode"},
        )

    def test_workflow_v1_and_nested_subgraph_nodes_are_counted(self) -> None:
        workflow = {
            "version": 1,
            "state": {"lastNodeId": 1},
            "nodes": [{"id": 1, "type": "TopLevelNode", "mode": 0}],
            "definitions": {
                "subgraphs": [
                    {"nodes": [{"id": "nested", "type": "NestedNode", "mode": 4}]}
                ]
            },
        }

        self.assertEqual(
            app.extract_workflow_node_types(workflow),
            {"TopLevelNode", "NestedNode"},
        )

    def test_png_workflow_metadata_is_read(self) -> None:
        embedded = '{"nodes":[{"type":"EmbeddedNode","mode":4}]}'
        with patch("app.png_text_metadata", return_value={"workflow": embedded}):
            documents = app.workflow_documents(Path("example.png"))

        self.assertEqual(app.extract_workflow_node_types(documents), {"EmbeddedNode"})

    def test_invalid_png_workflow_metadata_makes_scan_incomplete(self) -> None:
        workflow_path = Path(__file__).parent / "tests" / "fixtures" / "workflows" / "broken.png"
        with patch("app.png_text_metadata", return_value={"workflow": "{invalid"}):
            result = app.scan_workflows(workflow_path)

        self.assertEqual(result["files_failed"], 1)
        self.assertEqual(result["files_skipped"], 0)

    def test_nonexistent_paths_stop_before_scanning(self) -> None:
        missing = Path(__file__).parent / "__nonexistent_scan_test_path__"
        self.assertFalse(missing.exists())
        result = app.run_scan(str(missing), str(missing), str(missing))

        self.assertEqual(len(result["errors"]), 3)
        self.assertEqual(result["workflow"]["files_scanned"], 0)
        self.assertEqual(result["custom_nodes"], [])


class CurrentComfyUIPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).parent / f".path-test-{app.uuid.uuid4().hex}"
        self.comfyui = self.root / "ComfyUI"
        self.comfyui.mkdir(parents=True)
        (self.comfyui / "main.py").write_text("", encoding="utf-8")
        (self.comfyui / "comfyui_version.py").write_text('__version__ = "0.34.0"\n', encoding="utf-8")
        embedded_python = self.root / "python_embeded" / "python.exe"
        embedded_python.parent.mkdir(parents=True)
        embedded_python.write_text("placeholder", encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_portable_root_resolves_comfyui_and_embedded_python(self) -> None:
        result = app.default_paths_for_comfy(str(self.root))

        self.assertTrue(result["ok"])
        self.assertEqual(result["comfyui_path"], str(self.comfyui.resolve()))
        self.assertEqual(result["venv_path"], str((self.root / "python_embeded").resolve()))
        self.assertEqual(
            result["workflows_path"],
            str((self.comfyui / "user" / "default" / "workflows").resolve()),
        )

    def test_current_comfyui_version_file_is_read_without_importing_it(self) -> None:
        self.assertEqual(app.detect_comfyui_version(self.comfyui), "0.34.0")

    def test_existing_non_comfyui_folder_is_rejected(self) -> None:
        workflows = self.root / "workflows"
        workflows.mkdir()

        result = app.run_scan(str(workflows), str(self.root / "python_embeded"), str(workflows))

        self.assertIn("The selected ComfyUI path is invalid: main.py was not found.", result["errors"])


class DetectionCertaintyTests(unittest.TestCase):
    @property
    def fixture_root(self) -> Path:
        return Path(__file__).parent / "tests" / "fixtures" / "analysis"

    def test_dynamic_node_mapping_is_incomplete(self) -> None:
        analysis = app.parse_python_file(self.fixture_root / "dynamic_mapping.py")

        self.assertTrue(analysis.mapping_declared)
        self.assertFalse(analysis.mapping_complete)
        self.assertEqual(analysis.node_types, set())

    def test_dict_constructor_node_mapping_is_complete(self) -> None:
        analysis = app.parse_python_file(self.fixture_root / "standalone_node.py")

        self.assertTrue(analysis.mapping_declared)
        self.assertTrue(analysis.mapping_complete)
        self.assertEqual(analysis.node_types, {"StandaloneCleanerNode"})

    def test_literal_dynamic_imports_are_detected(self) -> None:
        analysis = app.parse_python_file(self.fixture_root / "dynamic_import.py")

        self.assertTrue({"importlib", "PIL", "yaml"}.issubset(analysis.imports))
        self.assertIn("installer-only", analysis.declared_requirements)
        self.assertIn("external-tool", analysis.invoked_commands)

    def test_non_cli_entry_point_provider_is_not_a_removal_candidate(self) -> None:
        venv_info = {
            "packages": {
                "plugin-provider": {"name": "plugin-provider", "version": "1"},
                "startup-hook": {"name": "startup-hook", "version": "1"},
                "command-provider": {"name": "command-provider", "version": "1"},
                "plain-package": {"name": "plain-package", "version": "1"},
            },
            "requires": {},
            "top_level_to_dists": {},
            "entry_point_groups": {"plugin-provider": ["example.plugins"]},
            "startup_hook_dists": ["startup-hook"],
            "console_scripts": {"external-tool": ["command-provider"]},
        }

        summary = app.summarize_python_packages(set(), set(), [], venv_info, {"external-tool"})
        candidates = {item["normalized_name"] for item in summary["no_detected_use"]}

        self.assertNotIn("plugin-provider", candidates)
        self.assertNotIn("startup-hook", candidates)
        self.assertNotIn("command-provider", candidates)
        self.assertIn("plain-package", candidates)

    def test_supported_project_manifests_are_collected(self) -> None:
        requirements = app.collect_requirements(self.fixture_root)

        self.assertTrue(
            {
                "requests",
                "example-extra",
                "project-runtime",
                "project-optional",
                "poetry-runtime",
                "cfg-runtime",
                "cfg-extra",
                "setup-runtime",
                "setup-extra",
            }.issubset(requirements)
        )

    def test_standalone_custom_node_is_scanned(self) -> None:
        packages = app.scan_custom_nodes(self.fixture_root, set())
        standalone = next(package for package in packages if package.name == "standalone_node")

        self.assertEqual(standalone.status, "unused")
        self.assertEqual(standalone.source_kind, "standalone_python")
        self.assertEqual(standalone.confidence, "high")

    def test_failed_workflow_scan_prevents_unused_classification(self) -> None:
        custom_nodes = Path(__file__).parent / "tests" / "fixtures" / "comfyui" / "custom_nodes"
        packages = app.scan_custom_nodes(custom_nodes, set(), workflow_scan_complete=False)

        self.assertEqual(packages[0].status, "unknown")
        self.assertIn("one or more workflow files could not be read", packages[0].evidence)

    def test_bypassed_node_type_keeps_owning_package_used(self) -> None:
        custom_nodes = Path(__file__).parent / "tests" / "fixtures" / "comfyui" / "custom_nodes"
        workflow_types = app.extract_workflow_node_types(
            {"nodes": [{"type": "CleanerTestExample", "mode": 4}]}
        )
        packages = app.scan_custom_nodes(custom_nodes, workflow_types)

        self.assertEqual(packages[0].status, "used")
        self.assertEqual(packages[0].confidence, "high")

    def test_v3_extension_is_resolved_across_package_files(self) -> None:
        custom_nodes = Path(__file__).parent / "tests" / "fixtures" / "v3_comfyui" / "custom_nodes"
        packages = app.scan_custom_nodes(custom_nodes, {"CleanerV3Example"})
        package = next(item for item in packages if item.name == "v3_example")

        self.assertEqual(package.status, "used")
        self.assertEqual(package.confidence, "high")
        self.assertEqual(package.node_types, {"CleanerV3Example"})
        self.assertIn("static V3 extension registration", package.evidence)

    def test_v3_schema_positional_node_id_is_supported(self) -> None:
        source = """
class PositionalNode:
    @classmethod
    def define_schema(cls):
        return io.Schema(\"PositionalV3Node\")
"""
        tree = app.ast.parse(source)
        class_node = next(node for node in tree.body if isinstance(node, app.ast.ClassDef))

        self.assertEqual(app.v3_schema_node_ids(class_node), ({"PositionalV3Node"}, True))

    def test_unused_static_v3_extension_is_high_confidence(self) -> None:
        custom_nodes = Path(__file__).parent / "tests" / "fixtures" / "v3_comfyui" / "custom_nodes"
        packages = app.scan_custom_nodes(custom_nodes, set())
        package = next(item for item in packages if item.name == "v3_example")

        self.assertEqual(package.status, "unused")
        self.assertEqual(package.confidence, "high")

    def test_dynamic_v3_extension_is_never_removable(self) -> None:
        custom_nodes = Path(__file__).parent / "tests" / "fixtures" / "v3_comfyui" / "custom_nodes"
        packages = app.scan_custom_nodes(custom_nodes, set())
        package = next(item for item in packages if item.name == "dynamic_v3")

        self.assertEqual(package.status, "unknown")
        self.assertEqual(package.confidence, "low")
        self.assertIn("dynamic or unresolved V3 extension registration", package.evidence)

    def test_disabled_custom_node_package_is_skipped_like_comfyui(self) -> None:
        custom_nodes = Path(__file__).parent / "tests" / "fixtures" / "v3_comfyui" / "custom_nodes"
        packages = app.scan_custom_nodes(custom_nodes, set())

        self.assertNotIn("ignored.disabled", {item.name for item in packages})


class BackupManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).parent / f".backup-test-{app.uuid.uuid4().hex}"
        self.backup_name = f"{app.BACKUP_PREFIX}test"
        self.backup_dir = self.root / "backups" / self.backup_name
        self.custom_nodes = self.root / "ComfyUI" / "custom_nodes"
        self.venv = self.root / "venv"
        self.backup_dir.mkdir(parents=True)
        self.custom_nodes.mkdir(parents=True)
        python_exe = self.venv / "Scripts" / "python.exe"
        python_exe.parent.mkdir(parents=True)
        python_exe.write_text("placeholder", encoding="utf-8")
        manifest = {
            "created_at": "2026-07-22T12:00:00",
            "paths": {
                "custom_nodes": str(self.custom_nodes),
                "venv": str(self.venv),
            },
            "selected_custom_node_paths": [str(self.custom_nodes / "example_node")],
            "selected_python_packages": ["example-lib"],
        }
        (self.backup_dir / "manifest.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )
        (self.backup_dir / "selected-python-packages.txt").write_text(
            "example-lib==1.2.3\n",
            encoding="utf-8",
        )
        with zipfile.ZipFile(self.backup_dir / "custom_nodes.zip", "w") as archive:
            archive.writestr("example_node/__init__.py", "NODE = True\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    @property
    def backup_root(self) -> str:
        return str(self.backup_dir.parent)

    def test_backup_listing_reports_restorable_components(self) -> None:
        result = app.list_backups(self.backup_root)

        self.assertTrue(result["ok"])
        self.assertEqual(len(result["backups"]), 1)
        self.assertEqual(result["backups"][0]["custom_node_count"], 1)
        self.assertEqual(result["backups"][0]["python_package_count"], 1)

    def test_custom_nodes_are_restored_without_overwriting(self) -> None:
        restored = app.restore_backup(
            {
                "backup_path": self.backup_root,
                "backup_name": self.backup_name,
                "restore_custom_nodes": True,
                "restore_python_packages": False,
            }
        )
        restored_file = self.custom_nodes / "example_node" / "__init__.py"
        self.assertTrue(restored["ok"])
        self.assertEqual(restored_file.read_text(encoding="utf-8"), "NODE = True\n")

        restored_file.write_text("existing\n", encoding="utf-8")
        blocked = app.restore_backup(
            {
                "backup_path": self.backup_root,
                "backup_name": self.backup_name,
                "restore_custom_nodes": True,
                "restore_python_packages": False,
            }
        )
        self.assertFalse(blocked["ok"])
        self.assertIn("overwrite", blocked["error"])
        self.assertEqual(restored_file.read_text(encoding="utf-8"), "existing\n")

    def test_unsafe_zip_member_is_rejected(self) -> None:
        with zipfile.ZipFile(self.backup_dir / "custom_nodes.zip", "w") as archive:
            archive.writestr("../outside.py", "unsafe\n")

        result = app.restore_backup(
            {
                "backup_path": self.backup_root,
                "backup_name": self.backup_name,
                "restore_custom_nodes": True,
                "restore_python_packages": False,
            }
        )

        self.assertFalse(result["ok"])
        self.assertIn("Unsafe path", result["error"])
        self.assertFalse((self.root / "outside.py").exists())

    def test_python_packages_are_restored_with_saved_venv(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout="installed", stderr="")
        with patch("app.subprocess.run", return_value=completed) as run:
            result = app.restore_backup(
                {
                    "backup_path": self.backup_root,
                    "backup_name": self.backup_name,
                    "restore_custom_nodes": False,
                    "restore_python_packages": True,
                }
            )

        self.assertTrue(result["ok"])
        command = run.call_args.args[0]
        self.assertEqual(command[0], str(self.venv / "Scripts" / "python.exe"))
        self.assertEqual(command[-1], str(self.backup_dir / "selected-python-packages.txt"))

    def test_python_restore_rejects_pip_options(self) -> None:
        (self.backup_dir / "selected-python-packages.txt").write_text(
            "--extra-index-url https://example.invalid\n",
            encoding="utf-8",
        )
        with patch("app.subprocess.run") as run:
            result = app.restore_backup(
                {
                    "backup_path": self.backup_root,
                    "backup_name": self.backup_name,
                    "restore_custom_nodes": False,
                    "restore_python_packages": True,
                }
            )

        self.assertFalse(result["ok"])
        self.assertIn("Unsupported Python restore requirement", result["error"])
        run.assert_not_called()

    def test_only_managed_backup_can_be_deleted(self) -> None:
        blocked = app.delete_backup(self.backup_root, "../not-a-backup")
        deleted = app.delete_backup(self.backup_root, self.backup_name)

        self.assertFalse(blocked["ok"])
        self.assertTrue(deleted["ok"])
        self.assertFalse(self.backup_dir.exists())


class SizeCalculationTests(unittest.TestCase):
    def test_directory_size_counts_fixture_files(self) -> None:
        fixture = Path(__file__).parent / "tests" / "fixtures" / "comfyui" / "custom_nodes" / "example_node"
        result = app.directory_file_size(fixture)

        self.assertTrue(result["ok"])
        self.assertGreater(result["bytes"], 0)
        self.assertEqual(result["file_count"], 1)

    def test_cleanup_size_uses_validated_selected_node_folder(self) -> None:
        project_path = Path(__file__).parent.resolve()
        scan_id = "size-calculation-test"
        scan = {
            "scan_id": scan_id,
            "paths": {
                "custom_nodes": str(project_path.parent),
                "venv": "",
            },
            "custom_nodes": [
                {"name": project_path.name, "path": str(project_path), "status": "unused", "confidence": "high"}
            ],
            "python_packages": {
                "no_detected_use": [],
                "only_unused_custom_nodes": [],
            },
        }
        with app.SCAN_LOCK:
            app.SCAN_CACHE[scan_id] = scan
        try:
            result = app.calculate_cleanup_size(
                {
                    "scan_id": scan_id,
                    "custom_node_paths": [str(project_path)],
                    "python_packages": [],
                }
            )
        finally:
            with app.SCAN_LOCK:
                app.SCAN_CACHE.pop(scan_id, None)

        self.assertTrue(result["ok"])
        self.assertGreater(result["total_bytes"], 0)
        self.assertEqual(result["total_bytes"], result["custom_nodes"]["bytes"])
        self.assertEqual(result["python_packages"]["bytes"], 0)


class ScanProgressTests(unittest.TestCase):
    def test_completed_scan_reports_zero_remaining_time(self) -> None:
        job_id = "completed-progress-test"
        now = app.time.time()
        with app.SCAN_LOCK:
            app.SCAN_JOBS[job_id] = {
                "progress": 50.0,
                "started_at": now - 2,
                "updated_at": now,
                "log": [],
            }
        try:
            app.update_scan_job(job_id, progress=100, status="complete", append_log=False)
            snapshot = app.scan_job_snapshot(job_id)
        finally:
            with app.SCAN_LOCK:
                app.SCAN_JOBS.pop(job_id, None)

        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot["eta_seconds"], 0.0)


if __name__ == "__main__":
    unittest.main()
