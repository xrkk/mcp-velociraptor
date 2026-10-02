"""Real isolated file trees, pinned normative/bootstrap originals, no VM calls.

PC026_BOOTSTRAP_FIXTURE_ROOT supplies the already verified 448+4 originals at
their approved repository-relative coordinates. It is a test input only; the
production reader has no environment-selected roots or policy overrides.
"""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

from tests import p05_pc020_evidence as ev
from tests import p05_pc026_governance as gov

TIME = "2026-10-02T00:00:00Z"
PRINCIPAL = "S-1-5-21-1-2-3-1001"


def write(root, path, value):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(ev.canonical_json(value))
    return reference(root, path)


def reference(root, path):
    data = (root / path).read_bytes()
    return {"path": path, "size": len(data), "sha256": ev._sha(data)}


def inventory(root):
    return {p.relative_to(root).as_posix(): (p.lstat().st_mode, p.lstat().st_ino,
                os.readlink(p) if p.is_symlink() else ev._sha(p.read_bytes()))
            for p in root.rglob("*") if p.is_symlink() or p.is_file()}


class ApprovalFixture:
    """Writes only a newly created isolated test root, never production paths."""
    def __init__(self, root, bootstrap):
        self.root = root
        self.refs = {}
        self.approval = {}
        for path in (gov.CONTRACT, gov.NATIVE_CONTRACT, gov.HANDOFF_CONTRACT, gov.NORMATIVE):
            self.copy(gov.REPOSITORY / path, path)
        normative = json.loads((root / gov.NORMATIVE).read_bytes())
        self.normative = {row["path"]: row for row in gov.nested_refs(normative)}
        for path in self.normative:
            self.copy(gov.REPOSITORY / path, path)
        bootstrap_doc = json.loads((root / gov.BOOTSTRAP).read_bytes())
        self.bootstrap = {row["relative_path"]: {"path": row["relative_path"],
            "size": row["size"], "sha256": row["sha256"]} for row in bootstrap_doc["members"]}
        for path in self.bootstrap:
            self.copy(bootstrap / path, path)
        self.freeze = {}
        # Explicit reviewed closure only; no broad .py copy masking missing deps.
        for path in gov.ENTRIES | gov.LOCAL_MODULES:
            self.copy(gov.REPOSITORY / path, path)
            self.freeze[path] = reference(root, path)
        for path in gov.RESOURCES:
            self.copy(gov.REPOSITORY / path, path)
            self.freeze[path] = reference(root, path)
        self.copy(bootstrap / (gov.EVIDENCE + "/bootstrap-pc020/epoch7/epoch7-canonical.json"), gov.CANONICAL)
        # Canonical is mutable guest-owned state, outside the publication list.
        self.refs.pop(gov.CANONICAL)
        self.refresh()

    def copy(self, source, path):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        self.refs[path] = reference(self.root, path)

    def refresh(self, *, archive_mutation=None, receipt_mutation=None, approval_mutation=None):
        root = self.root
        freeze = {"schema_version": 1, "kind": "pc026-implementation-freeze-v1", "profile_id": gov.PROFILE,
            "workflow_id": ev.WORKFLOW_ID, "normative_manifest": reference(root, gov.NORMATIVE),
            "members": [self.freeze[path] for path in sorted(self.freeze)], "status": "FROZEN"}
        self.refs[gov.FREEZE] = write(root, gov.FREEZE, freeze)
        deployment = {"schema_version": 1, "kind": "pc026-deployment-configuration-v1",
            "profile_id": gov.PROFILE, "workflow_id": ev.WORKFLOW_ID,
            "host_project_root": str(root), "guest_deployment_base": r"C:\controlled",
            "guest_project_coordinate": "project", "guest_canonical_coordinate": gov.CANONICAL,
            "vm_uuid": gov.VM_UUID, "guest_principal_sid": PRINCIPAL}
        self.refs[gov.DEPLOYMENT] = write(root, gov.DEPLOYMENT, deployment)
        mapping = {"host_governance_root": gov.EVIDENCE, "guest_project_coordinate": "project",
            "guest_evidence_root": gov.EVIDENCE, "guest_canonical_coordinate": gov.CANONICAL,
            "deployment_configuration": self.refs[gov.DEPLOYMENT]}
        members = dict(self.normative | self.freeze | self.bootstrap)
        members.update({path: self.refs[path] for path in (gov.NORMATIVE, gov.FREEZE, gov.BOOTSTRAP, gov.DEPLOYMENT)})
        rows, archive = [], []
        for index, path in enumerate(sorted(members)):
            _, _, host = gov._read(root / path)
            # Actual POSIX ACL bytes. Guest SD is deliberately synthetic and
            # never presented as a native Windows API or service observation.
            fd = os.open(root / path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                host_acl = gov._acl(fd, os.fstat(fd))
            finally:
                os.close(fd)
            parts = [int(value) for value in PRINCIPAL.split("-")[2:]]
            owner = bytes((1, len(parts) - 1)) + parts[0].to_bytes(6, "big") + b"".join(
                value.to_bytes(4, "little") for value in parts[1:])
            guest_acl = struct.pack("<BBHIIII", 1, 0, 0x8004, 20, 0, 0, 20 + len(owner)) + owner + struct.pack("<BBHHH", 2, 0, 8, 0, 0)
            guest = {"platform": "windows", "volume_serial": "0" * 16,
                "file_id": f"{index:032x}", "owner_sid": PRINCIPAL,
                "principal_sid": PRINCIPAL, "acl_sha256": ev._sha(guest_acl)}
            row = {"relative_path": path, "size": members[path]["size"], "sha256": members[path]["sha256"],
                "host_identity": host, "guest_identity": guest}
            rows.append(row)
            for endpoint, identity, acl in (("host", host, host_acl), ("guest", guest, guest_acl)):
                prefix = gov.EVIDENCE + f"/publication-observations/{index:04d}-{endpoint}"
                acl_path = prefix + ".acl"
                target = root / acl_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(acl)
                self.refs[acl_path] = reference(root, acl_path)
                observation = {"schema_version": 1, "kind": "pc026-identity-observation-v1",
                    "relative_path": path, "endpoint": endpoint, "identity": identity,
                    "acl_original": self.refs[acl_path], "observed_at": TIME,
                    "method": "posix_fstat_full_acl" if endpoint == "host"
                        else "windows_same_handle_fileid_security_descriptor"}
                observation_ref = write(root, prefix + ".json", observation)
                self.refs[observation_ref["path"]] = observation_ref
                archive.append({"relative_path": path, "endpoint": endpoint, "identity": identity,
                                "observation_ref": observation_ref})
        if archive_mutation:
            archive_mutation(archive)
        archive_path = gov.EVIDENCE + "/publication-identity.json"
        self.refs[archive_path] = write(root, archive_path, {"schema_version": 1,
            "kind": "pc026-identity-evidence-v1", "members": archive})
        receipt = {"schema_version": 1, "kind": "pc026-dual-publication-receipt-v1",
            "publication_id": "f7399e82-67a1-4a37-8109-41f4159f7324",
            "workflow_id": ev.WORKFLOW_ID, "profile_id": gov.PROFILE,
            "normative_manifest": self.refs[gov.NORMATIVE], "implementation_freeze": self.refs[gov.FREEZE],
            "bootstrap_manifest": self.refs[gov.BOOTSTRAP],
            "root_mapping_sha256": ev._sha(ev.canonical_json(mapping)[:-1]), "vm_uuid": gov.VM_UUID,
            "server_instance_id": "synthetic-only", "guest_principal_sid": PRINCIPAL,
            "members": rows, "published_at": TIME, "guest_directory_fsynced_at": TIME,
            "guest_readback_at": TIME, "host_readback_at": TIME, "status": "VERIFIED", "error": None,
            "identity_evidence": self.refs[archive_path]}
        if receipt_mutation:
            receipt_mutation(receipt)
        receipt_path = gov.EVIDENCE + "/publication-receipt.json"
        self.refs[receipt_path] = write(root, receipt_path, receipt)
        self.approval = {"schema_version": 1, "kind": "pc026-controller-approval-v1",
            "approval_id": "c78ea3f9-f2f7-4df7-a5fb-738abec6a9d1", "workflow_id": ev.WORKFLOW_ID,
            "profile_id": gov.PROFILE, "normative_manifest": self.refs[gov.NORMATIVE],
            "implementation_freeze": self.refs[gov.FREEZE], "bootstrap_manifest": self.refs[gov.BOOTSTRAP],
            "root_mapping": mapping, "publication_receipt": self.refs[receipt_path], "status": "READY"}
        if approval_mutation:
            approval_mutation(self.approval)
        self.refs[gov.APPROVAL] = write(root, gov.APPROVAL, self.approval)
        self.runtime()

    def runtime(self, mutation=None):
        value = {"schema_version": 1, "kind": "pc026-controller-runtime-record-v1", "profile_id": gov.PROFILE,
            "workflow_id": ev.WORKFLOW_ID, "contract_ref": self.refs[gov.CONTRACT],
            "approval_ref": self.refs[gov.APPROVAL], "allowed_refs": [self.refs[path] for path in sorted(self.refs)],
            "status": "ADOPTED"}
        if mutation:
            mutation(value)
        write(self.root, gov.RUNTIME, value)
        (self.root / gov.RUNTIME).chmod(0o600)


@unittest.skipUnless(os.name == "posix", "POSIX governance host reader")
class GovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = os.environ.get("PC026_BOOTSTRAP_FIXTURE_ROOT")
        if not source:
            raise RuntimeError("PC026_BOOTSTRAP_FIXTURE_ROOT: verified 448+4 isolated inputs required")
        cls.temp = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        cls.root = Path(cls.temp.name).resolve()
        cls.fixture = ApprovalFixture(cls.root, Path(source))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def load(self):
        return gov._load_at(self.root, synthetic_fixture=True)

    def reject_unchanged(self):
        before = inventory(self.root)
        with self.assertRaises((ValueError, KeyError, TypeError, OSError)):
            self.load()
        self.assertEqual(before, inventory(self.root))

    def test_complete_pinned_bundle_and_historical_initial_selection(self):
        before = inventory(self.root)
        group = self.load()
        self.assertTrue(group.synthetic_fixture)
        canonical = (self.root / gov.CANONICAL).read_bytes()
        bindings = gov.bindings_for(group, canonical)
        from tests.p05_selector_readonly import qualify
        facts = qualify(canonical, bindings=bindings, stage="P05_REPAIR_INITIAL")
        self.assertTrue(facts["content_graph_validated"])
        self.assertTrue(facts["synthetic_fixture"])
        self.assertEqual(before, inventory(self.root))

    def test_isolated_wire_tools_and_governance_load_from_frozen_tree(self):
        # -I ignores PYTHONPATH/cwd; -B prevents loader imports from writing caches.
        # The only inserted project path is the isolated, explicitly frozen tree.
        code = r"""
import sys, json, importlib.util
from pathlib import Path
root = Path(sys.argv[1]).resolve()
original = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(root))
def audit(event, args):
    if event == "open" and isinstance(args[0], (str, bytes)):
        path = Path(args[0]).absolute()
        if path.is_relative_to(original) and not (path.is_relative_to(root)
                or path.is_relative_to(original / ".venv")):
            raise AssertionError("project read escaped isolated tree: " + str(path))
sys.addaudithook(audit)
from tests import p05_pc026_governance as governance
from velo_transfer import wire, adapters, mcp_tools
import mcp_velociraptor_bridge
from mcp.server.mcpserver import MCPServer
schema_path = root / "velo_transfer/transfer_tools_schema.json"
contract = json.loads(schema_path.read_bytes())
assert adapters.SCHEMAS == mcp_tools._CONTRACT == contract
frame = wire.encode({}, b"", "pull_request")
assert wire.decode(frame, "pull_request") == ({}, b"")
server = MCPServer("isolated-resource-closure")
service = mcp_tools.register_transfer_tools(server)
assert set(server._tool_manager._tools) == set(mcp_tools.TRANSFER_TOOL_NAMES)
for name in mcp_tools.TRANSFER_TOOL_NAMES:
    assert server._tool_manager.get_tool(name).fn_metadata.output_schema == contract[name]["outputSchema"]
service.shutdown()
group = governance.load()
assert governance.RESOURCES <= group.freeze_refs.keys()
spec = importlib.util.spec_from_file_location("isolated_selector", root / governance.SELECTOR)
selector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selector)
modules = {}
for name, module in tuple(sys.modules.items()):
    if name == "tests" or name.startswith(("tests.", "velo_transfer" , "velociraptor_")) or name == "mcp_velociraptor_bridge":
        path = Path(module.__file__).resolve()
        assert path.is_relative_to(root), (name, path)
        assert path.relative_to(root).as_posix() in group.freeze_refs, (name, path)
        modules[name] = str(path.relative_to(root))
print(json.dumps({"modules": modules, "resource": str(schema_path.relative_to(root)),
                  "registered_tools": sorted(server._tool_manager._tools), "governance_loaded": True}))
"""
        before = inventory(self.root)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("VELOCIRAPTOR_", "PC026_"))}
        result = subprocess.run([sys.executable, "-I", "-B", "-c", code,
            str(self.root), str(gov.REPOSITORY)], cwd=self.root, env=environment,
            text=True, capture_output=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr)
        facts = json.loads(result.stdout)
        self.assertTrue(facts["governance_loaded"])
        self.assertIn("velo_transfer.wire", facts["modules"])
        self.assertIn("velo_transfer.adapters", facts["modules"])
        self.assertEqual(len(facts["registered_tools"]), 7)
        self.assertEqual(before, inventory(self.root))
        print("isolated load evidence: " + result.stdout.strip(), flush=True)

    def test_rebound_missing_resources_packages_and_dependencies_reject_semantically(self):
        paths = ("velo_transfer/transfer_tools_schema.json", "tests/scenarios/schema-v1.json",
                 "tests/__init__.py", "velo_transfer/__init__.py",
                 "velo_transfer/guest_service.py", "velo_transfer/connection.py",
                 "tests/test_p05_pc020_activation.py", "tests/p05_service_host.py",
                 "tests/p05_service_observation.py", "tests/p05_process_parent.py")
        for path in paths:
            with self.subTest(path=path):
                target = self.root / path
                original = target.read_bytes()
                reference_row = self.fixture.freeze.pop(path)
                self.fixture.refs.pop(path)
                target.unlink()
                try:
                    # Rebuild the entire publication/archive/approval/runtime,
                    # not just freeze hashes: all surviving Ref bindings are valid.
                    self.fixture.refresh()
                    before = inventory(self.root)
                    expected = "required resource: " if path in gov.RESOURCES else "required entry/import: "
                    with self.assertRaisesRegex(gov.GovernanceError,
                            "implementation freeze omits " + expected + path):
                        self.load()
                    self.assertEqual(before, inventory(self.root))
                    print("rebound closure rejection: " + path, flush=True)
                finally:
                    target.write_bytes(original)
                    self.fixture.freeze[path] = reference_row
                    self.fixture.refs[path] = reference_row
                    self.fixture.refresh()

    def test_runtime_approval_hash_and_path_matrix(self):
        runtime = self.root / gov.RUNTIME
        original = runtime.read_bytes()
        mutations = [lambda x: x.update(extra=0), lambda x: x.update(schema_version=True),
            lambda x: x.update(status="READY"), lambda x: x.pop("approval_ref"),
            lambda x: x["approval_ref"].update(sha256="0" * 64),
            lambda x: x["allowed_refs"].append(x["allowed_refs"][0]),
            lambda x: x["allowed_refs"].pop(0)]
        for path in (".tmp/approval.json", "candidate/controller.json", "../escape", "/absolute",
                     "a\\b", "a:b", "a/./b", "a//b", "a\0b"):
            mutations.append(lambda x, path=path: x["allowed_refs"][0].update(path=path))
        try:
            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    self.fixture.runtime(mutation)
                    self.reject_unchanged()
            runtime.write_bytes(original.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'))
            self.reject_unchanged()
        finally:
            runtime.write_bytes(original)

    def test_approval_models_and_bound_receipt_matrix(self):
        self.fixture.refresh(approval_mutation=lambda x: x.update(status="DRAFT"))
        try:
            self.reject_unchanged()
            self.fixture.refresh(approval_mutation=lambda x: x.update(extra=True))
            self.reject_unchanged()
            self.fixture.refresh(approval_mutation=lambda x: x["root_mapping"].update(guest_canonical_coordinate="other.json"))
            self.reject_unchanged()
            for mutation in (lambda x: x.update(root_mapping_sha256="0" * 64),
                lambda x: x["members"][0]["host_identity"].update(platform="windows"),
                lambda x: x["members"][0]["guest_identity"].update(platform="posix"),
                lambda x: x["members"].pop(), lambda x: x["members"].append(x["members"][0])):
                self.fixture.refresh(receipt_mutation=mutation)
                self.reject_unchanged()
            for mutation in (lambda x: x.pop(), lambda x: x.append(x[0]),
                             lambda x: x[0]["identity"].update(acl_sha256="0" * 64)):
                self.fixture.refresh(archive_mutation=mutation)
                self.reject_unchanged()
        finally:
            self.fixture.refresh()

    def test_drift_missing_ref_and_nofollow_without_writes(self):
        target = self.root / gov.APPROVAL
        original = target.read_bytes()
        group = self.load()
        try:
            target.write_bytes(original + b" ")
            self.reject_unchanged()
            with self.assertRaisesRegex(ValueError, "drift"):
                group.recheck()
            target.unlink()
            self.reject_unchanged()
            target.symlink_to(self.root / gov.NORMATIVE)
            self.reject_unchanged()
        finally:
            if target.is_symlink():
                target.unlink()
            target.write_bytes(original)

    def test_required_import_deployment_and_acl_original_semantics(self):
        runtime = self.root / gov.RUNTIME
        originals = {}
        def save(path, document):
            if path not in originals:
                originals[path] = (self.root / path).read_bytes()
            return write(self.root, path, document)
        def relock(paths):
            record = json.loads((self.root / gov.RUNTIME).read_bytes())
            for path in paths:
                row = reference(self.root, path)
                record["allowed_refs"] = [row if value["path"] == path else value
                                          for value in record["allowed_refs"]]
                if path == gov.APPROVAL:
                    record["approval_ref"] = row
            save(gov.RUNTIME, record)
        def restore():
            for path, data in originals.items():
                (self.root / path).write_bytes(data)
            originals.clear()
        try:
            freeze = json.loads((self.root / gov.FREEZE).read_bytes())
            freeze["members"] = [row for row in freeze["members"] if row["path"] != "tests/p05_pc026_profile.py"]
            frozen_ref = save(gov.FREEZE, freeze)
            approval = copy.deepcopy(self.fixture.approval)
            approval["implementation_freeze"] = frozen_ref
            save(gov.APPROVAL, approval); relock((gov.FREEZE, gov.APPROVAL))
            before = inventory(self.root)
            with self.assertRaisesRegex(ValueError, "omits required entry/import"):
                self.load()
            self.assertEqual(before, inventory(self.root)); restore()

            deployment = json.loads((self.root / gov.DEPLOYMENT).read_bytes())
            deployment["host_project_root"] = str(self.root.parent)
            deployment_ref = save(gov.DEPLOYMENT, deployment)
            approval = copy.deepcopy(self.fixture.approval)
            approval["root_mapping"]["deployment_configuration"] = deployment_ref
            save(gov.APPROVAL, approval); relock((gov.DEPLOYMENT, gov.APPROVAL))
            before = inventory(self.root)
            with self.assertRaisesRegex(ValueError, "deployment root/VM/principal"):
                self.load()
            self.assertEqual(before, inventory(self.root)); restore()

            approval = copy.deepcopy(self.fixture.approval)
            receipt_path = approval["publication_receipt"]["path"]
            receipt = json.loads((self.root / receipt_path).read_bytes())
            archive_path = receipt["identity_evidence"]["path"]
            archive = json.loads((self.root / archive_path).read_bytes())
            row = next(row for row in archive["members"] if row["endpoint"] == "guest")
            observation_path = row["observation_ref"]["path"]
            observation = json.loads((self.root / observation_path).read_bytes())
            acl_path = observation["acl_original"]["path"]
            originals[acl_path] = (self.root / acl_path).read_bytes()
            (self.root / acl_path).write_bytes(b"different actual SD bytes")
            observation["acl_original"] = reference(self.root, acl_path)
            row["observation_ref"] = save(observation_path, observation)
            receipt["identity_evidence"] = save(archive_path, archive)
            approval["publication_receipt"] = save(receipt_path, receipt)
            save(gov.APPROVAL, approval)
            relock((acl_path, observation_path, archive_path, receipt_path, gov.APPROVAL))
            before = inventory(self.root)
            with self.assertRaisesRegex(ValueError, "ACL original hash differs"):
                self.load()
            self.assertEqual(before, inventory(self.root))
        finally:
            restore()

    def test_production_missing_record_cwd_env_cannot_override(self):
        self.assertFalse((gov.REPOSITORY / gov.RUNTIME).exists())
        before = inventory(self.root)
        with patch.dict(os.environ, {"PC026_REPOSITORY": str(self.root),
                "PC026_APPROVAL": str(self.root / gov.APPROVAL), "PC026_POLICY": "synthetic"}):
            with self.assertRaises(ValueError):
                gov.load()
        self.assertEqual(before, inventory(self.root))


@unittest.skipUnless(os.name == "posix", "POSIX governance host reader")
class CurrentSelectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.pc026_governance_fixture import build
        source = os.environ.get("PC026_BOOTSTRAP_FIXTURE_ROOT")
        names = ("PC020_ACTIVATION188_FIXTURE", "PC020_PREDECESSOR_FIXTURE",
                 "PC020_BASELINE_DIR_FIXTURE", "PC020_ACTIVATION_DIR_FIXTURE", "PC020_REAL_SOURCE_ROOT")
        values = {name: os.environ.get(name) for name in names}
        if not source or any(not value or not Path(value).exists() for value in values.values()):
            raise RuntimeError("pinned bootstrap and five PC020 fixture inputs required")
        cls.temp = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        cls.root = Path(cls.temp.name).resolve()
        cls.activation = build(cls.root, Path(source), values, gov.REPOSITORY)
        spec = importlib.util.spec_from_file_location("pc026_selector_under_test", gov.REPOSITORY / gov.SELECTOR)
        cls.selector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.selector)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def cli(self, *options, state_path=None, production=False):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(output))
            stack.enter_context(contextlib.redirect_stderr(error))
            stack.enter_context(patch("sys.argv", [self.selector.__file__, "--state",
                str(state_path or self.root / gov.CANONICAL), "--expect-workflow", ev.WORKFLOW_ID, *options]))
            if not production:
                # Only the internal file-tree seam changes; real governed_bindings,
                # bindings_for, selector main and direct consumer all execute.
                stack.enter_context(patch.object(gov, "load",
                    side_effect=lambda: gov._load_at(self.root, synthetic_fixture=True)))
            result = self.selector.main()
        return result, output.getvalue(), error.getvalue()

    def test_real_selector_complete_191_and_fixed_canonical_only(self):
        before = inventory(self.root)
        result, output, error = self.cli("--emit-active")
        self.assertEqual(result, 0, error)
        from tests.p05_pc026_profile import CURRENT
        self.assertEqual(json.loads(output)["snapshot_name"], CURRENT.snapshot)
        self.assertTrue(json.loads(output)["qualification"]["synthetic_fixture"])
        result, output, error = self.cli("--validate-candidate", CURRENT.snapshot)
        self.assertEqual(result, 0, error)
        self.assertEqual(before, inventory(self.root))
        alias = self.root / "foreign-state.json"
        alias.write_bytes((self.root / gov.CANONICAL).read_bytes())
        try:
            before = inventory(self.root)
            result, output, error = self.cli("--emit-active", state_path=alias)
            self.assertEqual((result, output), (2, ""))
            self.assertIn("fixed canonical", error)
            self.assertEqual(before, inventory(self.root))
        finally:
            alias.unlink()

    def test_current_missing_committed_and_drift_fail_without_writes(self):
        receipt = self.activation / "epoch8-transition-receipt.json"
        runtime = self.root / gov.RUNTIME
        original, original_runtime = receipt.read_bytes(), runtime.read_bytes()
        try:
            for changes in ({"status": "TRANSITION_INDETERMINATE", "error": "unknown"},
                            {"schema_version": 2}, {"next_sha256": "0" * 64},
                            {"transition_id": str(uuid.uuid4())}):
                receipt.write_bytes(ev.canonical_json({**json.loads(original), **changes}))
                record = json.loads(original_runtime)
                path = receipt.relative_to(self.root).as_posix()
                record["allowed_refs"] = [reference(self.root, path) if row["path"] == path else row
                                          for row in record["allowed_refs"]]
                runtime.write_bytes(ev.canonical_json(record))
                before = inventory(self.root)
                result, output, error = self.cli("--emit-active")
                self.assertEqual((result, output), (2, "")); self.assertTrue(error)
                self.assertEqual(before, inventory(self.root))
        finally:
            receipt.write_bytes(original); runtime.write_bytes(original_runtime)

    def test_old_189_generation_and_writer_modes_are_refused(self):
        path = self.root / gov.CANONICAL
        original = path.read_bytes()
        state = json.loads(original)
        state["active_snapshot"]["name"] = ev.SNAPSHOT_189
        state["automatic_restore_allowlist"] = [ev.SNAPSHOT_189]
        state["retired_snapshots"] = state["retired_snapshots"][:-2]
        state["activation_evidence"]["source"] = "snapshot189-activation"
        state["activation_evidence"]["evidence_path"] = state["activation_evidence"]["evidence_path"].replace("activation-191/", "activation-189/")
        try:
            path.write_bytes(ev.canonical_json(state))
            before = inventory(self.root)
            result, output, error = self.cli("--emit-active")
            self.assertEqual((result, output), (2, "")); self.assertIn("epoch8 canonical shape", error)
            self.assertEqual(before, inventory(self.root))
        finally:
            path.write_bytes(original)
        before = inventory(self.root)
        for args in (("--emit-next", str(path) + ".next"), ("--adopt-baseline", str(self.activation)),
                     ("--policy", "foreign", "--emit-active"), ("--root", str(self.root), "--emit-active")):
            try:
                result, output, error = self.cli(*args)
            except SystemExit as exc:
                self.assertEqual(exc.code, 2)
            else:
                self.assertEqual((result, output), (2, "")); self.assertTrue(error)
        self.assertEqual(before, inventory(self.root))

    def test_real_production_missing_approval_emits_no_argv(self):
        before = inventory(self.root)
        with patch.dict(os.environ, {"PC026_ROOT": str(self.root), "PC026_POLICY": "fixture"}):
            result, output, error = self.cli("--emit-active", production=True,
                state_path=gov.REPOSITORY / gov.CANONICAL)
        self.assertEqual((result, output), (2, "")); self.assertIn("governance", error)
        self.assertEqual(before, inventory(self.root))


if __name__ == "__main__":
    unittest.main()
