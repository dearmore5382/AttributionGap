"""Read-only StudioNet source parity, schema and initial-state check."""
import base64
import hashlib
import json
from pathlib import Path

import requests
from genlayer_py.abi import calldata
from genlayer_py.abi.transactions import serialize

ROOT = Path(__file__).resolve().parents[1]
ADDRESS = "0x217A62942c968665f2bbF3478434f4a644369723"
RPC = "https://studio.genlayer.com/api"
EXPECTED = "79c6a76e407f353f35f62a12d43c138dc22ab6acc632790e7acf5482d5b06ede"
SENDER = "0x0000000000000000000000000000000000000001"


def rpc(method, params):
    response = requests.post(RPC, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=45)
    response.raise_for_status()
    data = response.json()
    if "error" in data:
        raise RuntimeError(json.dumps(data["error"]))
    return data["result"]


def view(method, args=None):
    data = serialize([calldata.encode({"method": method, "args": args or []}), b"\x00"])
    raw = rpc("gen_call", [{"type": "read", "to": ADDRESS, "from": SENDER, "value": "0x0", "data": data,
                            "transaction_hash_variant": "latest-final"}])
    return str(calldata.decode(bytes.fromhex(raw.removeprefix("0x"))))


def main():
    deployed = base64.b64decode(rpc("gen_getContractCode", [ADDRESS]))
    local = (ROOT / "contracts" / "AttributionGap.py").read_bytes()
    schema = rpc("gen_getContractSchema", [ADDRESS])
    report = {"network": "StudioNet", "chain_id": int(rpc("eth_chainId", []), 16), "contract": ADDRESS,
              "explorer": "https://explorer-studio.genlayer.com/address/" + ADDRESS,
              "source_sha256": hashlib.sha256(deployed).hexdigest(), "expected_source_sha256": EXPECTED,
              "exact_source_parity": deployed == local, "initial_count": view("get_count"),
              "public_methods": sorted(schema.get("methods", {}).keys()), "schema": schema}
    if report["chain_id"] != 61999: raise RuntimeError("WRONG_CHAIN")
    if report["source_sha256"] != EXPECTED or not report["exact_source_parity"]: raise RuntimeError("SOURCE_PARITY_FAILED")
    if report["initial_count"] != "0": raise RuntimeError("EXPECTED_EMPTY_DEPLOYMENT")
    out = ROOT / "verification" / ("preflight-" + ADDRESS.lower() + ".json")
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "schema"}, indent=2))


if __name__ == "__main__": main()
