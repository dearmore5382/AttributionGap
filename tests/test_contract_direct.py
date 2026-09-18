from pathlib import Path
import hashlib
import importlib
import json
import sys
from unittest.mock import patch

from gltest.direct import VMContext, create_address, deploy_contract

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "AttributionGap.py"
COMMIT_A = "a" * 40
COMMIT_B = "b" * 40
POLICY = "Every SBOM package must have a semantically matching name and declared license in the notice."


def deploy():
    creator, outsider = create_address("creator"), create_address("outsider")
    vm = VMContext(creator)
    with patch("os.unlink", lambda _path: None):
        with vm.activate():
            contract = deploy_contract(CONTRACT, vm)
            proxy = contract._instance.register_release.__globals__["gl"]
            _ = proxy.nondet
            _ = proxy.vm
    sdk_root = str(Path(proxy._cached_gl.__file__).resolve().parents[2])
    if sdk_root not in sys.path:
        sys.path.insert(0, sdk_root)
    importlib.import_module("genlayer")
    return vm, contract, creator, outsider


def sync(vm, contract):
    proxy = contract._instance.register_release.__globals__["gl"]
    sdk_root = str(Path(proxy._cached_gl.__file__).resolve().parents[2])
    if sdk_root not in sys.path:
        sys.path.insert(0, sdk_root)
    if "genlayer" not in sys.modules:
        importlib.invalidate_caches()
        importlib.import_module("genlayer")
    message = proxy.message
    sender = vm.sender
    if isinstance(sender, bytes):
        sender = type(message.sender_address)(sender)
    proxy._cached_gl.message = message._replace(sender_address=sender, origin_address=sender,
                                                 value=type(message.value)(vm.value))
    proxy._cached_gl.message_raw["sender_address"] = sender
    proxy._cached_gl.message_raw["origin_address"] = sender


def restore_validator_modules(contract):
    proxy = contract._instance.register_release.__globals__["gl"]
    if "genlayer" not in sys.modules:
        importlib.invalidate_caches()
        importlib.import_module("genlayer")
    module = sys.modules["genlayer"]
    module.gl = proxy._cached_gl
    sys.modules["genlayer.gl"] = proxy._cached_gl
    sys.modules["genlayer.gl.vm"] = proxy._cached_gl.vm


def cleanup_validator_modules():
    sys.modules.pop("genlayer.gl.vm", None)
    sys.modules.pop("genlayer.gl", None)


def source_bytes():
    return (ROOT / "fixtures" / "sbom-complete.json").read_bytes(), (ROOT / "fixtures" / "notice-complete.md").read_bytes()


def register(vm, contract, commit=COMMIT_A, notice_digest=None):
    sbom, notice = source_bytes()
    with vm.activate():
        sync(vm, contract)
        return contract.register_release("Northstar v2.4.0", "example-org", "northstar", commit,
            "release/sbom.json", "THIRD_PARTY_NOTICES.md", hashlib.sha256(sbom).hexdigest(),
            notice_digest or hashlib.sha256(notice).hexdigest(), POLICY)


def install_sources(vm, token_line="MATCH|MATCH|MATCH", candidate=None):
    sbom, notice = source_bytes()
    if candidate is not None:
        notice = candidate
    vm.clear_mocks()
    vm.mock_web(r"https://raw\.githubusercontent\.com/example-org/northstar/.*release/sbom\.json",
                {"status": 200, "body": sbom})
    vm.mock_web(r"https://raw\.githubusercontent\.com/example-org/northstar/.*THIRD_PARTY_NOTICES\.md",
                {"status": 200, "body": notice})
    vm.mock_llm(r"(?s).*one pipe-delimited token per package.*", token_line)


def test_validation_and_authoritative_registration():
    vm, contract, _, _ = deploy()
    sbom, notice = source_bytes()
    sd, nd = hashlib.sha256(sbom).hexdigest(), hashlib.sha256(notice).hexdigest()
    with vm.activate():
        sync(vm, contract)
        assert contract.register_release("x", "bad/owner", "repo", COMMIT_A, "a.json", "b.md", sd, nd, POLICY) == "INVALID_REPOSITORY"
        assert contract.register_release("x", "owner", "repo", "main", "a.json", "b.md", sd, nd, POLICY) == "INVALID_SOURCE"
        assert contract.register_release("x", "owner", "repo", COMMIT_A, "../a.json", "b.md", sd, nd, POLICY) == "INVALID_SOURCE"
        assert contract.register_release("x", "owner", "repo", COMMIT_A, "same", "same", sd, nd, POLICY) == "INVALID_SOURCE"
        assert contract.get_count() == "0"
    assert register(vm, contract) == 0
    record = json.loads(contract.get_audit(0))
    assert record["repository"] == "example-org/northstar"
    assert record["commit"] == COMMIT_A
    assert record["status"] == "REGISTERED"
    with vm.activate():
        sync(vm, contract)
        assert contract.register_release("duplicate", "example-org", "northstar", COMMIT_A,
            "release/sbom.json", "THIRD_PARTY_NOTICES.md", record["sbom_sha256"],
            record["notice_sha256"], POLICY) == "DUPLICATE_RELEASE"
        assert contract.get_count() == "1"


def test_full_public_complete_path_and_validator_reexecution():
    vm, contract, _, _ = deploy()
    audit = register(vm, contract)
    install_sources(vm)
    with vm.activate():
        sync(vm, contract)
        assert contract.assess_release(audit) == "NOTICE_COMPLETE"
        record = json.loads(contract.get_audit(audit))
        observation = json.loads(record["observation"])
        assert record["status"] == "FINALIZED"
        assert observation["coverage"] == ["MATCH", "MATCH", "MATCH"]
        restore_validator_modules(contract)
        assert vm.run_validator() is True
        assert contract.assess_release(audit) == "AUDIT_NOT_ASSESSABLE"
    cleanup_validator_modules()


def test_digest_substitution_fails_before_semantics():
    vm, contract, _, _ = deploy()
    audit = register(vm, contract, notice_digest="0" * 64)
    install_sources(vm)
    with vm.activate():
        sync(vm, contract)
        assert contract.assess_release(audit) == "INTEGRITY_FAILURE"
        record = json.loads(contract.get_audit(audit))
        observation = json.loads(record["observation"])
        assert observation["notice_sha256"] == hashlib.sha256(source_bytes()[1]).hexdigest()
        assert observation["coverage"] == []


def test_failure_precedence_and_prompt_injection_are_bounded():
    vm, contract, _, _ = deploy()
    audit = register(vm, contract)
    install_sources(vm, "MATCH|MISSING|MISMATCH")
    with vm.activate():
        sync(vm, contract)
        assert contract.assess_release(audit) == "LICENSE_MISMATCH"
    vm2, contract2, _, _ = deploy()
    audit2 = register(vm2, contract2)
    install_sources(vm2, "MATCH|MISSING|UNCLEAR")
    with vm2.activate():
        sync(vm2, contract2)
        assert contract2.assess_release(audit2) == "ATTRIBUTION_GAPS"


def test_malformed_model_output_fails_closed_to_unclear():
    for output in ("MATCH|MATCH", "Here you go:\nMATCH|MATCH|MATCH", "MATCH|MATCH|APPROVED"):
        vm, contract, _, _ = deploy()
        audit = register(vm, contract)
        install_sources(vm, output)
        with vm.activate():
            sync(vm, contract)
            assert contract.assess_release(audit) == "UNCLEAR"


def test_validator_rejects_consequential_package_difference():
    vm, contract, _, _ = deploy()
    audit = register(vm, contract)
    install_sources(vm, "MATCH|MATCH|MATCH")
    with vm.activate():
        sync(vm, contract)
        assert contract.assess_release(audit) == "NOTICE_COMPLETE"
    install_sources(vm, "MATCH|MISSING|MATCH")
    with vm.activate():
        sync(vm, contract)
        restore_validator_modules(contract)
        assert vm.run_validator() is False
    cleanup_validator_modules()


def test_remediation_is_append_only_creator_controlled():
    vm, contract, _, outsider = deploy()
    first = register(vm, contract, COMMIT_A)
    second = register(vm, contract, COMMIT_B)
    for audit in (first, second):
        install_sources(vm)
        with vm.activate():
            sync(vm, contract)
            assert contract.assess_release(audit) == "NOTICE_COMPLETE"
    with vm.prank(outsider):
        sync(vm, contract)
        assert contract.link_remediation(first, second) == "CREATOR_ONLY"
    with vm.activate():
        sync(vm, contract)
        assert contract.link_remediation(first, second) == "REMEDIATION_LINKED"
        assert contract.link_remediation(first, second) == "SUCCESSOR_ALREADY_LINKED"
        assert json.loads(contract.get_audit(first))["successor_plus_one"] == 2


def test_creator_cannot_adopt_another_users_audit_as_remediation():
    vm, contract, creator, outsider = deploy()
    first = register(vm, contract, COMMIT_A)
    with vm.prank(outsider):
        sync(vm, contract)
        sbom, notice = source_bytes()
        second = contract.register_release("Foreign audit", "example-org", "northstar", COMMIT_B,
            "release/sbom.json", "THIRD_PARTY_NOTICES.md", hashlib.sha256(sbom).hexdigest(),
            hashlib.sha256(notice).hexdigest(), POLICY)
    for audit in (first, second):
        install_sources(vm)
        with vm.activate():
            sync(vm, contract)
            assert contract.assess_release(audit) == "NOTICE_COMPLETE"
    with vm.prank(creator):
        sync(vm, contract)
        assert contract.link_remediation(first, second) == "SUCCESSOR_CREATOR_MISMATCH"
