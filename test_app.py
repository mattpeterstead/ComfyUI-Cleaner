import json
import shutil
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

import app


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
