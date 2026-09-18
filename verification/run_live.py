"""Checkpointed StudioNet lifecycle; signed writes are never automatically retried."""
import base64
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from genlayer_py import create_account, create_client
from genlayer_py.abi import calldata
from genlayer_py.abi.transactions import serialize
from genlayer_py.chains import studionet

ROOT = Path(__file__).resolve().parents[1]
ADDRESS = "0x217A62942c968665f2bbF3478434f4a644369723"
RPC = "https://studio.genlayer.com/api"
SOURCE_HASH = "79c6a76e407f353f35f62a12d43c138dc22ab6acc632790e7acf5482d5b06ede"
OWNER, REPO = "dearmore5382", "AttributionGap"
FIXTURE_COMMIT = "1b4fa7cd039c3b62d5444c2b06de19d98f6a0158"
REMEDIATION_COMMIT = "687f8a4730b55d6a1bbe4109c89cf6998cfa2bb4"
SBOM = "df2289afe23b32612aba6df607515472d6315bcd83664726ea7b2175c7c3eb92"
COMPLETE = "c8ee3ad54394b38ddf02997116d5c179b9853c35f7da2b8f145b12b1d448c9fb"
MISSING = "2af7837182ca18b79d2d908f3b363cb9c2378e1242df2877aa6e97c3730e9ef3"
WRONG = "3d204d3ef60ac592a1ff879cafa6a047198cde07190b0c9c461c7c91359aac5a"
POLICY = "Every SBOM package must have a semantically matching name and declared license in the notice."
PRIVATE = ROOT / ".private" / ("live-" + ADDRESS.lower() + ".json")
PUBLIC = ROOT / "verification" / ("live-" + ADDRESS.lower() + ".json")
TEST_ENV = ROOT.parent / "DAOProposalContextVerifier" / ".env.lifecycle"


def rpc(method, params):
    last = None
    for attempt in range(5):
        try:
            response = requests.post(RPC, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=45)
            response.raise_for_status()
            data = response.json()
            if "error" in data: raise RuntimeError("RPC_ERROR:" + str(data["error"].get("message")))
            return data["result"]
        except (requests.RequestException, ValueError) as error:
            last = error
            if attempt < 4: time.sleep(3 * (attempt + 1))
    raise RuntimeError("RPC_READ_UNAVAILABLE:" + str(last))


def view(method, args=None, sender="0x0000000000000000000000000000000000000001"):
    data = serialize([calldata.encode({"method": method, "args": args or []}), b"\x00"])
    raw = rpc("gen_call", [{"type": "read", "to": ADDRESS, "from": sender, "value": "0x0", "data": data,
                            "transaction_hash_variant": "latest-final"}])
    return str(calldata.decode(bytes.fromhex(raw.removeprefix("0x"))))


def parity():
    deployed = base64.b64decode(rpc("gen_getContractCode", [ADDRESS]))
    local = (ROOT / "contracts" / "AttributionGap.py").read_bytes()
    if deployed != local or hashlib.sha256(deployed).hexdigest() != SOURCE_HASH: raise RuntimeError("SOURCE_MISMATCH")


def keys():
    values = {}
    for raw in TEST_ENV.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1); values[key.strip()] = value.strip()
    result = [os.environ.get("WALLET_A_PRIVATE_KEY") or values.get("WALLET_A_PRIVATE_KEY"),
              os.environ.get("WALLET_B_PRIVATE_KEY") or values.get("WALLET_B_PRIVATE_KEY")]
    if not all(result): raise RuntimeError("LOCAL_TEST_KEYS_NOT_FOUND")
    return result


def tx_return(tx):
    receipts = (tx.get("consensus_data") or {}).get("leader_receipt") or []
    receipts = [receipts] if isinstance(receipts, dict) else receipts
    leaders = [item for item in receipts if item.get("mode") == "leader"]
    if not leaders or leaders[-1].get("execution_result") != "SUCCESS": raise RuntimeError("LEADER_EXECUTION_FAILED")
    value = leaders[-1].get("result")
    raw = base64.b64decode(value["raw"] if isinstance(value, dict) else value)
    if not raw or raw[0] != 0: raise RuntimeError("CONTRACT_EXECUTION_ERROR")
    return str(calldata.decode(raw[1:]))


def save(record):
    PRIVATE.parent.mkdir(exist_ok=True)
    PRIVATE.write_text(json.dumps(record, indent=2), encoding="utf-8")
    public = json.loads(json.dumps(record)); public.pop("balances", None)
    for step in public["steps"]: step.pop("receipt", None)
    PUBLIC.write_text(json.dumps(public, indent=2) + "\n", encoding="utf-8")


def reg(label, commit, notice_path, notice_digest):
    return [label, OWNER, REPO, commit, "fixtures/sbom-complete.json", notice_path, SBOM, notice_digest, POLICY]


def main():
    secret_keys = keys()
    accounts = [create_account(account_private_key="0x" + key.removeprefix("0x")) for key in secret_keys]
    del secret_keys
    creator, outsider = accounts
    clients = {a.address.lower(): create_client(chain=studionet, account=a) for a in accounts}
    parity()
    balances = {a.address: int(rpc("eth_getBalance", [a.address, "latest"]), 16) for a in accounts}
    plan = [
      {"id":"F1-invalid-commit","actor":creator.address,"method":"register_release","args":["Invalid",OWNER,REPO,"main","fixtures/sbom-complete.json","fixtures/notice-complete.md",SBOM,COMPLETE,POLICY],"allowed":["INVALID_SOURCE"]},
      {"id":"H1-register-complete","actor":creator.address,"method":"register_release","args":reg("Complete release",FIXTURE_COMMIT,"fixtures/notice-complete.md",COMPLETE),"allowed":["0"]},
      {"id":"F2-duplicate-release","actor":creator.address,"method":"register_release","args":reg("Duplicate",FIXTURE_COMMIT,"fixtures/notice-complete.md",COMPLETE),"allowed":["DUPLICATE_RELEASE"]},
      {"id":"H2-assess-complete","actor":outsider.address,"method":"assess_release","args":[0],"allowed":["NOTICE_COMPLETE"]},
      {"id":"F3-assessment-replay","actor":outsider.address,"method":"assess_release","args":[0],"allowed":["AUDIT_NOT_ASSESSABLE"]},
      {"id":"H3-register-missing","actor":creator.address,"method":"register_release","args":reg("Missing attribution",FIXTURE_COMMIT,"fixtures/notice-missing.md",MISSING),"allowed":["1"]},
      {"id":"H4-assess-missing","actor":outsider.address,"method":"assess_release","args":[1],"allowed":["ATTRIBUTION_GAPS"]},
      {"id":"H5-register-wrong-license","actor":creator.address,"method":"register_release","args":reg("Wrong license",FIXTURE_COMMIT,"fixtures/notice-wrong-license.md",WRONG),"allowed":["2"]},
      {"id":"H6-assess-wrong-license","actor":outsider.address,"method":"assess_release","args":[2],"allowed":["LICENSE_MISMATCH"]},
      {"id":"H7-register-false-digest","actor":creator.address,"method":"register_release","args":reg("False digest",FIXTURE_COMMIT,"fixtures/notice-complete.md","0"*64),"allowed":["3"]},
      {"id":"H8-assess-false-digest","actor":outsider.address,"method":"assess_release","args":[3],"allowed":["INTEGRITY_FAILURE"]},
      {"id":"H9-register-dead-source","actor":creator.address,"method":"register_release","args":reg("Unavailable source",FIXTURE_COMMIT,"fixtures/does-not-exist.md",COMPLETE),"allowed":["4"]},
      {"id":"F4-assess-dead-source","actor":outsider.address,"method":"assess_release","args":[4],"allowed":["ASSESSMENT_RETRYABLE"]},
      {"id":"H10-register-remediation","actor":creator.address,"method":"register_release","args":reg("Remediated release",REMEDIATION_COMMIT,"fixtures/notice-complete.md",COMPLETE),"allowed":["5"]},
      {"id":"H11-assess-remediation","actor":outsider.address,"method":"assess_release","args":[5],"allowed":["NOTICE_COMPLETE"]},
      {"id":"F5-outsider-link","actor":outsider.address,"method":"link_remediation","args":[1,5],"allowed":["CREATOR_ONLY"]},
      {"id":"H12-link-remediation","actor":creator.address,"method":"link_remediation","args":[1,5],"allowed":["REMEDIATION_LINKED"]},
      {"id":"F6-link-replay","actor":creator.address,"method":"link_remediation","args":[1,5],"allowed":["SUCCESSOR_ALREADY_LINKED"]},
    ]
    if PRIVATE.exists(): record = json.loads(PRIVATE.read_text(encoding="utf-8"))
    else:
        if view("get_count", sender=creator.address) != "0": raise RuntimeError("EXPECTED_EMPTY_DEPLOYMENT")
        record = {"contract":ADDRESS,"source_sha256":SOURCE_HASH,"fixture_commit":FIXTURE_COMMIT,
                  "started_at":datetime.now(timezone.utc).isoformat(),"wallets":[a.address for a in accounts],
                  "balances":balances,"steps":[],"complete":False}; save(record)
    print(json.dumps({"ready":True,"balances":balances,"completed":len(record["steps"]),"total":len(plan)}),flush=True)
    for index,wanted in enumerate(plan):
        parity()
        if index < len(record["steps"]):
            item=record["steps"][index]
            if item["id"]!=wanted["id"]: raise RuntimeError("PLAN_MISMATCH")
            if item.get("status")=="VERIFIED": continue
            if item.get("status")!="SUBMITTED": raise RuntimeError("UNKNOWN_CHECKPOINT")
        else:
            item=dict(wanted); item["status"]="INTENT_SAVED"; record["steps"].append(item); save(record)
            item["hash"]=str(clients[item["actor"].lower()].write_contract(address=ADDRESS,function_name=item["method"],args=item["args"],value=0,leader_only=False))
            item["status"]="SUBMITTED"; save(record); print(json.dumps({"step":item["id"],"hash":item["hash"]}),flush=True)
        deadline=time.monotonic()+1200
        while time.monotonic()<deadline:
            tx=rpc("eth_getTransactionByHash",[item["hash"]])
            if tx and tx.get("status")=="FINALIZED":
                if tx.get("result_name")!="MAJORITY_AGREE": raise RuntimeError("CONSENSUS_FAILED")
                actual=tx_return(tx)
                if actual not in item["allowed"]: raise RuntimeError("UNEXPECTED:"+actual)
                count=int(view("get_count",sender=creator.address)); readback={"count":count}
                for object_id in range(count): readback["audit"+str(object_id)]=view("get_audit",[object_id],creator.address)
                item.update({"actual":actual,"receipt":tx,"readback":readback,"status":"VERIFIED",
                             "explorer":"https://explorer-studio.genlayer.com/tx/"+item["hash"]}); save(record)
                print(json.dumps({"step":item["id"],"actual":actual}),flush=True); break
            time.sleep(8)
        else: raise RuntimeError("POLL_TIMEOUT_KEEP_HASH")
    record["complete"]=True; record["completed_at"]=datetime.now(timezone.utc).isoformat(); save(record)
    print(json.dumps({"complete":True,"steps":len(plan)}))


if __name__ == "__main__": main()
