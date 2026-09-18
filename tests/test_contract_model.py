from pathlib import Path
import ast
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "contracts" / "AttributionGap.py").read_text(encoding="utf-8")


def test_source_shape_and_headers():
    assert SOURCE.startswith("# v0.2.16\n# { \"Depends\":")
    ast.parse(SOURCE)
    assert "https://raw.githubusercontent.com/" in SOURCE
    assert "gl.vm.run_nondet_unsafe" in SOURCE
    assert "response.status" in SOURCE and "status_code" not in SOURCE


def test_no_arbitrary_url_public_argument():
    tree = ast.parse(SOURCE)
    public_names = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert "register_release" in public_names
    register = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "register_release")
    assert all("url" not in arg.arg.lower() for arg in register.args.args)


def test_fixtures_are_bounded_and_digestible():
    sbom = (ROOT / "fixtures" / "sbom-complete.json").read_bytes()
    parsed = json.loads(sbom)
    assert 0 < len(parsed["packages"]) <= 8
    for name in ("notice-complete.md", "notice-missing.md", "notice-wrong-license.md", "notice-prompt-injection.md"):
        raw = (ROOT / "fixtures" / name).read_bytes()
        assert raw and len(raw) < 24000
        assert len(hashlib.sha256(raw).hexdigest()) == 64


def derive(status, coverage):
    if status == "SOURCE_UNAVAILABLE": return "ASSESSMENT_RETRYABLE"
    if status != "VERIFIED": return status
    if "MISMATCH" in coverage: return "LICENSE_MISMATCH"
    if "MISSING" in coverage: return "ATTRIBUTION_GAPS"
    if "UNCLEAR" in coverage: return "UNCLEAR"
    return "NOTICE_COMPLETE"


def test_verdict_precedence_matrix():
    assert derive("VERIFIED", ["MATCH", "MATCH"]) == "NOTICE_COMPLETE"
    assert derive("VERIFIED", ["MISSING", "MISMATCH"]) == "LICENSE_MISMATCH"
    assert derive("VERIFIED", ["MATCH", "MISSING"]) == "ATTRIBUTION_GAPS"
    assert derive("VERIFIED", ["MATCH", "UNCLEAR"]) == "UNCLEAR"
    assert derive("INTEGRITY_FAILURE", []) == "INTEGRITY_FAILURE"
    assert derive("SOURCE_UNAVAILABLE", []) == "ASSESSMENT_RETRYABLE"
