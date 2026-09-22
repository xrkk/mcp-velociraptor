"""Windows-only synthetic positive/negative tests for Snapshot189 activation."""

from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
import unittest
import uuid
from pathlib import Path

from tests import p05_pc020_activation as activation
from tests import p05_pc020_evidence as evidence
from tests import p05_pc021_package as pkg
from tests.pc020_activation_fixture import (
    ActivationFixture, build_issuance_receipt, refresh_ref, write,
)


@unittest.skipUnless(os.name == "nt", "CON002: behavioral tests execute only on Windows")
class Snapshot189ActivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        names = {
            "historical": "PC020_ACTIVATION188_FIXTURE", "predecessor": "PC020_PREDECESSOR_FIXTURE",
            "baseline": "PC020_BASELINE_DIR_FIXTURE", "old_activation": "PC020_ACTIVATION_DIR_FIXTURE",
            "sources": "PC020_REAL_SOURCE_ROOT",
        }
        values = {key: os.environ.get(env) for key, env in names.items()}
        missing = [key for key, value in values.items() if not value or not Path(value).exists()]
        if missing:
            raise RuntimeError(f"required PC020 activation fixtures missing: {missing}")
        cls.temp = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        parent = Path(cls.temp.name).resolve() / "activation-189"
        root = parent / str(uuid.uuid4())
        repo = Path(__file__).resolve().parents[1]
        fixture = ActivationFixture(
            root, Path(values["historical"]), Path(values["predecessor"]).read_bytes(),
            Path(values["baseline"]), Path(values["old_activation"]), Path(values["sources"]), repo,
        )
        cls.base = root
        cls.policy = fixture.policy
        cls.root_policy = fixture.root_policy
        cls.canonical = fixture.canonical_bytes

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def setUp(self) -> None:
        self.case_parent = self.base.parent / str(uuid.uuid4())
        shutil.copytree(self.base, self.case_parent)
        self.path = self.case_parent / "activation-evidence.json"
        self._rebase_download_paths()
        self.refresh_receipt(self.doc())
        self.before = {p.relative_to(self.case_parent).as_posix(): p.read_bytes() for p in self.case_parent.rglob("*") if p.is_file()}

    def doc(self) -> dict:
        return json.loads(self.path.read_bytes())

    def save_root(self, doc: dict) -> None:
        write(self.path, doc)

    def refresh_phase(self, doc: dict, phase: dict, key: str) -> None:
        refresh_ref(self.case_parent, phase[key])
        self.refresh_manifest(phase)
        refresh_ref(self.case_parent, phase["package_manifest"])
        self.save_root(doc)
        self.refresh_receipt(doc)

    def refresh_manifest(self, phase: dict) -> None:
        manifest_path = self.case_parent / phase["package_manifest"]["path"]
        phase_dir = phase["report"]["path"].rsplit("/", 1)[0]
        report = json.loads((manifest_path.parent / "report.json").read_bytes())
        try:
            manifest_doc = pkg.build_phase_manifest(
                phase_root=manifest_path.parent, phase_prefix=phase_dir,
                workflow_id=evidence.WORKFLOW_ID, report=report,
                report_ref_path=f"{phase_dir}/report.json",
            )
        except pkg.PackagePreservationError:
            # deliberately corrupted report bytes: rebuild the member list
            # leniently so the verifier (not this helper) performs the
            # rejection against the exact frozen report
            members = []
            for path in sorted(
                (p for p in manifest_path.parent.rglob("*")
                 if p.is_file() and p != manifest_path),
                key=lambda p: p.relative_to(manifest_path.parent).as_posix().encode(),
            ):
                data = path.read_bytes()
                relative = path.relative_to(manifest_path.parent).as_posix()
                members.append({
                    "path": relative, "size": len(data),
                    "sha256": evidence._sha(data), "origin": f"{phase_dir}/{relative}",
                })
            manifest_doc = {
                "schema_version": 1, "kind": pkg.PHASE_MANIFEST_KIND,
                "workflow_id": evidence.WORKFLOW_ID,
                "created_at": "2026-09-15T04:05:00Z", "members": members,
            }
        manifest_path.write_bytes(evidence.canonical_json(manifest_doc))

    def refresh_receipt(self, doc: dict) -> None:
        write(
            self.case_parent / "issuance-receipt.json",
            build_issuance_receipt(self.case_parent, doc, self.canonical),
        )

    def verify(self):
        return activation.verify_snapshot189_activation(
            self.path, policy=self.policy, epoch7_canonical=self.canonical,
            root_policy=self.root_policy,
        )

    def reset_case(self) -> None:
        shutil.rmtree(self.case_parent)
        shutil.copytree(self.base, self.case_parent)
        self.path = self.case_parent / "activation-evidence.json"
        self._rebase_download_paths()
        self.refresh_receipt(self.doc())

    def _rebase_download_paths(self) -> None:
        doc = self.doc()
        for phase in [doc["initial"], *doc["candidate_cycles"]]:
            report_path = self.case_parent / phase["report"]["path"]
            report = json.loads(report_path.read_bytes())
            for call in report["calls"]:
                if call["tool"] != "download_flow_file":
                    continue
                for structured in (call["structured"], call["mcp_result"]["structuredContent"]):
                    relative = Path(structured["local_path"]).relative_to(self.base)
                    structured["local_path"] = str((self.case_parent / relative).resolve())
            write(report_path, report)
            self.refresh_phase(doc, phase, "report")

    def assertRejected(self, operation, pattern: str) -> None:
        operation()
        with self.assertRaisesRegex(activation.Activation189Error, pattern):
            self.verify()

    def test_complete_three_phase_graph_is_read_only(self) -> None:
        sentinel = self.case_parent / "sentinel.bin"; sentinel.write_bytes(b"unchanged")
        facts = self.verify()
        self.assertEqual((facts["candidate"], facts["phase_count"]), (evidence.SNAPSHOT_189, 3))
        self.assertFalse(facts["operational_ready"]); self.assertFalse(facts["authorizes_p06"])
        self.assertEqual(sentinel.read_bytes(), b"unchanged")
        after = {p.relative_to(self.case_parent).as_posix(): p.read_bytes() for p in self.case_parent.rglob("*") if p.is_file() and p != sentinel}
        self.assertEqual(self.before, after)

    def test_each_phase_requires_a_bound_download_chain(self) -> None:
        doc = self.doc(); phase = doc["initial"]
        report_path = self.case_parent / phase["report"]["path"]
        report = json.loads(report_path.read_bytes())
        report["calls"] = [call for call in report["calls"] if call["step_id"] != "ascii_download"]
        report["steps"] = [step for step in report["steps"] if step["id"] != "ascii_download"]
        for sequence, call in enumerate(report["calls"], start=1):
            call["sequence"] = sequence
        write(report_path, report); self.refresh_phase(doc, phase, "report")
        with self.assertRaisesRegex(activation.Activation189Error, "download"):
            self.verify()

    def test_immediately_finished_flows_are_accepted(self) -> None:
        doc = self.doc()
        for phase in [doc["initial"], *doc["candidate_cycles"]]:
            report_path = self.case_parent / phase["report"]["path"]
            report = json.loads(report_path.read_bytes())
            final_status = {
                call["step_id"]: call
                for call in report["calls"]
                if call["tool"] == "get_flow_status"
            }
            terminal_by_flow = {
                call["structured"]["flow_id"]: call["structured"]["state"]
                for call in final_status.values()
            }
            calls = []
            for call in report["calls"]:
                if call["tool"] == "get_flow_status" and call is not final_status[call["step_id"]]:
                    continue
                call["sequence"] = len(calls) + 1
                if call["tool"] == "get_flow_status":
                    call["attempt"] = 1
                elif call["tool"] in {"collect_file", "collect_forensic_triage"}:
                    state = terminal_by_flow[call["structured"]["flow_id"]]
                    call["structured"]["state"] = state
                    call["mcp_result"]["structuredContent"]["state"] = state
                calls.append(call)
            report["calls"] = calls
            write(report_path, report)
            self.refresh_phase(doc, phase, "report")
        self.verify()

    def test_download_identity_and_retained_bytes_are_bound(self) -> None:
        patterns = {
            "flow": "listed Flow/file identity", "file": "listed Flow/file identity",
            "original": "listed Flow/file identity", "size": "listed Flow/file identity",
            "hash": "size or sha256", "content": "size or sha256",
            "cross-round": "listed Flow/file identity",
        }
        for defect, pattern in patterns.items():
            with self.subTest(defect=defect):
                self.reset_case(); doc = self.doc()
                phase = doc["candidate_cycles"][1]
                report_path = self.case_parent / phase["report"]["path"]
                report = json.loads(report_path.read_bytes())
                download = next(call for call in report["calls"] if call["step_id"] == "ascii_download")
                structured = download["structured"]
                mirrored = download["mcp_result"]["structuredContent"]
                if defect == "flow":
                    other = next(call for call in report["calls"] if call["step_id"] == "collect_utf8")["structured"]["flow_id"]
                    download["arguments"]["flow_id"] = other; structured["flow_id"] = other; mirrored["flow_id"] = other
                elif defect == "file":
                    download["arguments"]["file_id"] = "unknown-file"; structured["file_id"] = "unknown-file"; mirrored["file_id"] = "unknown-file"
                elif defect == "original":
                    structured["original_path"] += ".wrong"; mirrored["original_path"] = structured["original_path"]
                elif defect == "size":
                    structured["size"] += 1; mirrored["size"] = structured["size"]
                elif defect == "hash":
                    structured["sha256"] = "0" * 64; mirrored["sha256"] = structured["sha256"]
                elif defect == "content":
                    Path(structured["local_path"]).write_bytes(b"changed retained bytes")
                else:
                    left = doc["candidate_cycles"][0]
                    left_report = json.loads((self.case_parent / left["report"]["path"]).read_bytes())
                    prior = next(call for call in left_report["calls"] if call["step_id"] == "ascii_download")
                    download["arguments"] = copy.deepcopy(prior["arguments"])
                    for key in ("flow_id", "file_id", "original_path", "size", "sha256"):
                        structured[key] = prior["structured"][key]
                        mirrored[key] = prior["structured"][key]
                write(report_path, report); self.refresh_phase(doc, phase, "report")
                with self.assertRaisesRegex(activation.Activation189Error, pattern):
                    self.verify()

    def test_root_phase_source_and_manifest_boundaries(self) -> None:
        for name in ("extra-root", "extra-phase", "phase-key", "source-set", "marker"):
            with self.subTest(name=name):
                self.reset_case(); doc = self.doc()
                if name == "extra-root": doc["future_receipt"] = {}
                elif name == "extra-phase": doc["candidate_cycles"].append(copy.deepcopy(doc["candidate_cycles"][1]))
                elif name == "phase-key": doc["initial"]["future_gate"] = {}
                elif name == "source-set": doc["source_inputs"].pop()
                else: doc["checkpoint_marker"] = "Win10MalBox-Velo-Snapshot999.vmsn"
                self.save_root(doc)
                with self.assertRaises(activation.Activation189Error): self.verify()

    def test_old188_wrong_stage_and_missing_phase_are_rejected(self) -> None:
        for name in ("old188", "wrong-stage", "missing-phase"):
            with self.subTest(name=name):
                self.reset_case()
                doc = self.doc()
                if name == "old188": doc["kind"] = "snapshot188-activation-evidence-v1"; doc["candidate"] = evidence.SNAPSHOT_188
                elif name == "missing-phase": doc["candidate_cycles"].pop()
                else:
                    phase = doc["candidate_cycles"][0]; p = self.case_parent / phase["snapshot_evidence"]["path"]
                    value = json.loads(p.read_bytes()); value["restore"]["snapshot_stage"] = "P05_REPAIR_INITIAL"; write(p, value)
                    report = self.case_parent / phase["report"]["path"]; r = json.loads(report.read_bytes()); r["snapshot_evidence_sha256"] = evidence._sha(p.read_bytes()); write(report, r)
                    refresh_ref(self.case_parent, phase["snapshot_evidence"]); self.refresh_phase(doc, phase, "report"); continue
                self.save_root(doc)
                with self.assertRaises(activation.Activation189Error): self.verify()

    def test_deep_source_and_exact_recursive_manifest_are_rejected(self) -> None:
        doc = self.doc(); row = next(row for row in doc["source_inputs"] if row["repo_path"] == activation.INDEX)
        path = self.case_parent / row["content"]["path"]; path.write_bytes(path.read_bytes() + b" ")
        refresh_ref(self.case_parent, row["content"]); self.save_root(doc)
        with self.assertRaisesRegex(activation.Activation189Error, "source|frozen|JSON"):
            self.verify()
        self.reset_case()
        doc = self.doc(); phase = doc["initial"]; manifest = self.case_parent / phase["package_manifest"]["path"]
        value = json.loads(manifest.read_bytes()); value["members"].pop(); write(manifest, value); refresh_ref(self.case_parent, phase["package_manifest"]); self.save_root(doc)
        with self.assertRaisesRegex(activation.Activation189Error, "manifest"):
            self.verify()

    def test_cross_phase_session_and_flow_relabel_are_rejected(self) -> None:
        for kind in ("session", "process", "flow", "ready", "restore"):
            with self.subTest(kind=kind):
                self.reset_case()
                doc = self.doc(); left, right = doc["candidate_cycles"]
                if kind == "ready":
                    right["ready"] = copy.deepcopy(left["ready"]); self.save_root(doc)
                    with self.assertRaises(activation.Activation189Error): self.verify()
                    continue
                lp = self.case_parent / left["report"]["path"]; rp = self.case_parent / right["report"]["path"]
                lreport, report = json.loads(lp.read_bytes()), json.loads(rp.read_bytes())
                snapshot_path = self.case_parent / right["snapshot_evidence"]["path"]
                snapshot = json.loads(snapshot_path.read_bytes())
                if kind == "session":
                    report["mcp_session"]["id"] = lreport["mcp_session"]["id"]
                    snapshot["mcp_session_id"] = lreport["mcp_session"]["id"]
                elif kind == "process":
                    report["runner"] = copy.deepcopy(lreport["runner"])
                elif kind == "restore":
                    left_snapshot = json.loads((self.case_parent / left["snapshot_evidence"]["path"]).read_bytes())
                    snapshot["restore"] = copy.deepcopy(left_snapshot["restore"])
                else:
                    old = next(iter(activation._flow_ids(report["calls"])))
                    new = next(iter(activation._flow_ids(lreport["calls"])))
                    def replace(value):
                        if isinstance(value, dict):
                            for key, item in value.items(): value[key] = new if item == old else replace(item)
                        elif isinstance(value, list):
                            for i, item in enumerate(value): value[i] = new if item == old else replace(item)
                        return value
                    replace(report["calls"])
                write(snapshot_path, snapshot); report["snapshot_evidence_sha256"] = evidence._sha(snapshot_path.read_bytes()); write(rp, report)
                refresh_ref(self.case_parent, right["snapshot_evidence"]); self.refresh_phase(doc, right, "report")
                with self.assertRaises(activation.Activation189Error):
                    self.verify()

    def test_ready_dependency_entry_network_and_business_corruption(self) -> None:
        targets = [(0, "ready", "resource"), (1, "dependency_acceptance", "dependency"),
                   (2, "entry_gate", "entry"), (2, "network_evidence", "network"),
                   (0, "report", "triage"), (1, "report", "list"),
                   (2, "report", "terminal")]
        for index, key, defect in targets:
            with self.subTest(phase=index, key=key, defect=defect):
                self.reset_case()
                doc = self.doc(); phase = [doc["initial"], *doc["candidate_cycles"]][index]
                path = self.case_parent / phase[key]["path"]; value = json.loads(path.read_bytes())
                if key == "ready": value["observations"].pop("resources")
                elif key == "dependency_acceptance": value["restore_attempt_id"] = "wrong"
                elif key == "entry_gate": value["cases"].pop("wrong_origin")
                elif key == "network_evidence": value["server_observation_sha256"] = "0" * 64
                elif defect == "triage": value["calls"] = [call for call in value["calls"] if call["tool"] != "collect_forensic_triage"]
                elif defect == "list": value["calls"] = [call for call in value["calls"] if call["tool"] != "list_flow_files"]
                else:
                    final = [call for call in value["calls"] if call["step_id"] == "wait_triage"][-1]
                    final["structured"]["state"] = "ERROR"
                    final["mcp_result"]["structuredContent"]["state"] = "ERROR"
                write(path, value); self.refresh_phase(doc, phase, key)
                with self.assertRaises(activation.Activation189Error): self.verify()

    def test_issued_at_is_real_causal_field(self) -> None:
        for value in (None, "2026-09-15T04:12:00+00:00", "not-a-time"):
            with self.subTest(value=value):
                self.reset_case()
                doc = self.doc(); doc["issued_at"] = value; self.save_root(doc)
                with self.assertRaisesRegex(activation.Activation189Error, "issued_at|chronology"): self.verify()

    def test_causal_order_uses_hash_dag_not_cross_clock_magnitude(self) -> None:
        doc = self.doc(); doc["issued_at"] = "2000-01-01T00:00:00Z"; self.save_root(doc)
        self.refresh_receipt(self.doc()); self.verify()

    def test_issuance_receipt_boundaries(self) -> None:
        for name in ("missing", "kind-v1", "event-order", "issued-at", "epoch7", "cycle2", "root-binding", "source-digests"):
            with self.subTest(name=name):
                self.reset_case()
                receipt_path = self.case_parent / "issuance-receipt.json"
                receipt = json.loads(receipt_path.read_bytes())
                if name == "missing":
                    receipt_path.unlink()
                    with self.assertRaisesRegex(activation.Activation189Error, "receipt"):
                        self.verify()
                    continue
                elif name == "kind-v1":
                    receipt["kind"] = "snapshot189-activation-issuance-receipt-v1"
                elif name == "event-order":
                    receipt["events"][2], receipt["events"][3] = receipt["events"][3], receipt["events"][2]
                elif name == "issued-at":
                    receipt["issued_at"] = "2026-09-15T04:12:00.500000Z"
                elif name == "epoch7":
                    receipt["epoch7"]["canonical_sha256"] = "0" * 64
                elif name == "cycle2":
                    receipt["cycle2"]["run_id"] = "wrong-run"
                elif name == "root-binding":
                    receipt["activation_root"]["sha256"] = "0" * 64
                else:
                    receipt["source"]["source_inputs_sha256"] = "0" * 64
                write(receipt_path, receipt)
                with self.assertRaisesRegex(activation.Activation189Error, "receipt"):
                    self.verify()

    def test_extra_download_call_and_legacy_manifest_rejected(self) -> None:
        self.reset_case()
        doc = self.doc(); phase = doc["initial"]
        report_path = self.case_parent / phase["report"]["path"]
        report = json.loads(report_path.read_bytes())
        donor = next(call for call in report["calls"] if call["step_id"] == "ascii_download")
        clone = copy.deepcopy(donor)
        clone["step_id"] = "ascii_download_again"
        clone["sequence"] = len(report["calls"]) + 1
        report["calls"].append(clone)
        write(report_path, report); self.refresh_phase(doc, phase, "report")
        with self.assertRaisesRegex(activation.Activation189Error, "exactly the two fixture|download"):
            self.verify()
        self.reset_case()
        doc = self.doc(); phase = doc["initial"]
        manifest = self.case_parent / phase["package_manifest"]["path"]
        members = []
        for path in sorted((p for p in manifest.parent.rglob("*") if p.is_file() and p != manifest), key=lambda p: p.name.encode()):
            data = path.read_bytes()
            members.append({"path": path.relative_to(manifest.parent).as_posix(), "size": len(data), "sha256": evidence._sha(data)})
        write(manifest, {"schema_version": 1, "members": members})
        refresh_ref(self.case_parent, phase["package_manifest"]); self.save_root(doc); self.refresh_receipt(self.doc())
        with self.assertRaisesRegex(activation.Activation189Error, "manifest"):
            self.verify()

    def test_normative_sources_must_not_migrate_to_implementation(self) -> None:
        self.reset_case()
        doc = self.doc()
        row = next(row for row in doc["source_inputs"] if row["repo_path"] == activation.INDEX)
        doc["source_inputs"].remove(row)
        doc["implementation_sources"].append(copy.deepcopy(row))
        self.save_root(doc); self.refresh_receipt(self.doc())
        with self.assertRaisesRegex(activation.Activation189Error, "source_inputs|policy"):
            self.verify()

    def test_local_path_is_immutable_assertion_not_dereferenced(self) -> None:
        self.reset_case()
        doc = self.doc(); phase = doc["candidate_cycles"][0]
        report_path = self.case_parent / phase["report"]["path"]
        report = json.loads(report_path.read_bytes())
        for call in report["calls"]:
            if call["tool"] == "download_flow_file":
                for structured in (call["structured"], call["mcp_result"]["structuredContent"]):
                    structured["local_path"] = "C:\\gone\\absent\\source-time-only.bin"
        write(report_path, report); self.refresh_phase(doc, phase, "report")
        self.verify()


if __name__ == "__main__":
    unittest.main(verbosity=2)
