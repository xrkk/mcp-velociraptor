"""Host pull publication and recovery under the existing journal writer.

Staging/extraction, guest release and global completion remain coordinator work.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path

from . import filesystem
from .bundle import _validated_manifest, verify_tree
from .errors import TransferContentError as Error
from .filesystem import publish_directory
from .host_journal import HostJournal, _check_parent_chain
from .manifest import canonical_json, digest_json, directory_identity, safe_chain
from .protocol import (publish_intent, receipt_digest, recover_publication,
                       validate_binding, validate_prepare, validate_publication)
from .request import make_guest_request


class HostPublication:
    """Publish only a previously registered and verified pull stage.

    The caller holds journal.writer throughout. Required journal data:
    binding, guest_request, prepare_receipt, staging, manifest_ref.
    The destination descriptor uses the journal's observed host_identity.
    """

    def __init__(self, journal: HostJournal):
        if not isinstance(journal, HostJournal):
            raise Error("invalid_journal")
        self.journal = journal

    def _load(self):
        self.journal._require_writer(task=True)
        envelope = self.journal.load()
        data = envelope["data"]
        binding = validate_binding(data.get("binding"))
        request = self.journal.request
        guest = data.get("guest_request")
        if (binding["direction"] != "pull" or request.document["direction"] != "pull" or
                binding["transfer_id"] != request.transfer_id or not isinstance(guest, dict)):
            raise Error("publication_binding_conflict")
        destination = Path(request.document["destination_directory"])
        descriptor = {"endpoint": "host", "identity": self.journal.binding["host_identity"],
                      "canonical_path": str(destination)}
        expected = make_guest_request(request, descriptor)
        if (canonical_json(guest) != canonical_json(expected) or
                binding["request_digest"] != expected["request_digest"] or
                any(binding[key] != expected["expected_vm_identity"][key]
                    for key in ("vm_uuid", "boot_identity", "vm_epoch"))):
            raise Error("publication_binding_conflict")
        prepare = data.get("prepare_receipt")
        validate_prepare(prepare, binding)
        stage = data.get("staging")
        if (not isinstance(stage, dict) or set(stage) != {"staging_directory",
                "staging_identity", "parent_identity", "destination_directory"} or
                stage["destination_directory"] != str(destination) or
                not isinstance(stage["staging_directory"], str)):
            raise Error("invalid_staging_ownership")
        stage_path = Path(stage["staging_directory"])
        if (not stage_path.is_absolute() or stage_path.parent != destination.parent or
                not stage_path.name.startswith(".velo-stage-") or stage_path == destination):
            raise Error("invalid_staging_ownership")
        # This validates the two exact directory identity shapes as well.
        template = publish_intent(binding, prepare, descriptor, stage["staging_identity"],
                                  stage["parent_identity"], publication_id="validation-only")
        budget = request.content_budget(envelope["deadline_monotonic"])
        _check_parent_chain(destination.parent)
        safe_chain(destination, destination.parent, allow_missing_leaf=True)
        if directory_identity(destination.parent) != stage["parent_identity"]:
            raise Error("destination_parent_changed")
        manifest = self.journal.read_evidence(data.get("manifest_ref"))
        manifest = _validated_manifest(canonical_json(manifest), budget)
        if digest_json(manifest) != binding["manifest_sha256"]:
            raise Error("manifest_hash_mismatch")
        intent = data.get("publish_intent")
        if intent is not None:
            # Pure validation cannot stand in for physical verification below.
            recovered = recover_publication(intent, binding, prepare, descriptor,
                verified_identity=stage["staging_identity"],
                verified_parent_identity=stage["parent_identity"],
                verified_manifest_sha256=binding["manifest_sha256"])
            if recovered["directory_identity"] != template["publication"]["directory_identity"]:
                raise Error("publication_recovery_conflict")
        receipt = data.get("publication_receipt")
        if receipt is not None:
            validate_publication(receipt, binding, prepare, descriptor)
            if intent is None or canonical_json(receipt) != canonical_json(intent["publication"]):
                raise Error("publication_recovery_conflict")
        return envelope, binding, descriptor, stage, manifest, budget

    def _save(self, **updates):
        envelope = self.journal.load()
        data = envelope["data"]
        data.update(copy.deepcopy(updates))
        return self.journal.save(envelope["revision"], data)

    def _mark_published(self):
        """Record an observed irreversible rename before checking its contents."""
        if self.journal.load()["data"]["published_ever"]:
            return
        try:
            self._save(published_ever=True)
        except Error as exc:
            raise Error(exc.code, published=True) from exc

    def _verify_destination(self, binding, descriptor, stage, manifest, budget):
        destination = Path(descriptor["canonical_path"])
        safe_chain(destination, destination.parent)
        if directory_identity(destination.parent) != stage["parent_identity"]:
            raise Error("destination_parent_changed")
        if directory_identity(destination) != stage["staging_identity"]:
            raise Error("publication_recovery_conflict")
        self._mark_published()
        verified = verify_tree(destination, manifest, budget, stage["staging_identity"])
        if directory_identity(destination.parent) != stage["parent_identity"]:
            raise Error("destination_parent_changed")
        if verified["manifest_sha256"] != binding["manifest_sha256"]:
            raise Error("manifest_hash_mismatch")
        return verified

    def publish(self):
        """P3: persist intent, rename exclusively, or recover that same rename.

        Returns a publication receipt and its immutable evidence reference.
        This is never a guest release request or a global success result.
        """
        envelope, binding, descriptor, stage, manifest, budget = self._load()
        data = envelope["data"]
        destination = Path(descriptor["canonical_path"])
        stage_path = Path(stage["staging_directory"])
        intent = data.get("publish_intent")
        if intent is None:
            if data["published_ever"] or data.get("publication_receipt") is not None:
                raise Error("publication_recovery_conflict")
            if os.path.lexists(destination):
                raise Error("destination_exists")
            verify_tree(stage_path, manifest, budget, stage["staging_identity"])
            intent = publish_intent(binding, data["prepare_receipt"], descriptor,
                                    stage["staging_identity"], stage["parent_identity"])
            self._save(publish_intent=intent)
        if os.path.lexists(destination):
            # Require the registered inode, never merely a matching hash/name.
            verified = self._verify_destination(binding, descriptor, stage, manifest, budget)
            if os.path.lexists(stage_path):
                raise Error("publication_recovery_conflict", published=True)
            # A prior attempt may have renamed successfully but failed the
            # parent sync. A durable receipt needs that step on recovery too.
            try:
                filesystem._fsync_directory(destination.parent)
            except OSError as exc:
                raise Error("post_publish_io_failed", published=True) from exc
            if directory_identity(destination.parent) != stage["parent_identity"]:
                raise Error("destination_parent_changed", published=True)
            if directory_identity(destination) != verified["identity"]:
                raise Error("destination_changed", published=True)
        else:
            if data["published_ever"] or data.get("publication_receipt") is not None:
                raise Error("published_destination_missing", published=True)
            if not os.path.lexists(stage_path):
                # Intent exists, but neither side of the rename remains. We
                # cannot distinguish a lost stage from a later-deleted output.
                raise Error("publication_outcome_unknown", published=None)
            try:
                publish_directory(stage_path, destination, destination.parent, manifest, budget,
                    expected_staging_identity=stage["staging_identity"],
                    expected_parent_identity=stage["parent_identity"])
            except Error as exc:
                if exc.context.get("published") is True:
                    self._mark_published()
                raise
            self._mark_published()
            verified = self._verify_destination(binding, descriptor, stage, manifest, budget)
        receipt = recover_publication(intent, binding, data["prepare_receipt"], descriptor,
            verified_identity=verified["identity"],
            verified_parent_identity=directory_identity(destination.parent),
            verified_manifest_sha256=verified["manifest_sha256"])
        reference = self.journal.write_evidence("publication_receipt", receipt)
        current = self.journal.load()["data"]
        updates = {"published_ever": True, "publication_receipt": receipt,
                   "publication_receipt_ref": reference}
        if current["phase"] not in ("CLEANING", "COMPLETE"):
            updates["phase"] = "PUBLISHED"
        self._save(**updates)
        return copy.deepcopy({"publication_receipt": receipt, "reference": reference})

    def verify_published(self):
        """Fresh local observation for P5; caller must first verify guest release.

        No cached proof or receipt alone authorizes a successful return.
        This method does not persist a COMPLETE or cleanup assertion.
        """
        envelope, binding, descriptor, stage, manifest, budget = self._load()
        receipt = envelope["data"].get("publication_receipt")
        if receipt is None:
            raise Error("publication_unproven")
        verified = self._verify_destination(binding, descriptor, stage, manifest, budget)
        return {"schema": "velo.transfer.host-destination-verification.v1",
                "binding": copy.deepcopy(binding),
                "publication_receipt_sha256": receipt_digest(receipt),
                "directory_identity": copy.deepcopy(verified["identity"]),
                "parent_identity": directory_identity(Path(descriptor["canonical_path"]).parent),
                "manifest_sha256": verified["manifest_sha256"]}
