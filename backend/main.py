"""
AegisGraph AI — Backend MVP
FastAPI + mock Slither + mock LLM (swap in real Anthropic key to go live)
"""
import uuid, json, time, random
from datetime import datetime
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="AegisGraph API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── in-memory store (replace with Redis/Postgres for prod) ─────────────────
AUDITS: dict = {}

# ── schemas ────────────────────────────────────────────────────────────────
class AuditRequest(BaseModel):
    contract_code: str
    contract_name: str = "MyContract"

# ── mock analysis engine ───────────────────────────────────────────────────
VULN_TEMPLATES = [
    {
        "id": "V001", "severity": "critical",
        "title": "Missing Access Control on setOracle()",
        "function": "setOracle", "contract": "{name}",
        "description": "Anyone can overwrite the oracle address. No onlyOwner modifier.",
        "pre": "Callable by any address",
        "post": "oracleAddress storage slot overwritten",
        "line": 14,
    },
    {
        "id": "V002", "severity": "high",
        "title": "Unchecked Oracle Return Value",
        "function": "getPrice", "contract": "{name}",
        "description": "Return value from external oracle call is not validated.",
        "pre": "oracleAddress points to attacker contract",
        "post": "Collateral check bypassed — price returns 0",
        "line": 28,
    },
    {
        "id": "V003", "severity": "critical",
        "title": "Reentrancy in withdraw()",
        "function": "withdraw", "contract": "{name}",
        "description": "ETH sent before state update allows reentrancy drain.",
        "pre": "Attacker contract implements receive()",
        "post": "Complete asset drain of contract balance",
        "line": 47,
    },
    {
        "id": "V004", "severity": "medium",
        "title": "Integer Overflow in calculateReward()",
        "function": "calculateReward", "contract": "{name}",
        "description": "Unchecked arithmetic can overflow reward calculation.",
        "pre": "User calls with large deposit value",
        "post": "Reward calculation wraps to 0",
        "line": 61,
    },
    {
        "id": "V005", "severity": "low",
        "title": "tx.origin Authentication",
        "function": "adminAction", "contract": "{name}",
        "description": "Uses tx.origin instead of msg.sender for auth check.",
        "pre": "Admin interacts with a phishing contract",
        "post": "Phishing contract gains admin privileges",
        "line": 72,
    },
]

EXPLOIT_CHAIN = {
    "chain_id": "CHAIN-001",
    "severity": "critical",
    "title": "Oracle Manipulation → Collateral Bypass → Full Asset Drain",
    "impact": "Complete loss of all protocol funds. Attacker drains vault in 3 transactions.",
    "recommendation": "1) Add onlyOwner to setOracle(). 2) Validate oracle return values. 3) Apply checks-effects-interactions pattern.",
    "steps": [
        {"order": 1, "fn": "setOracle(maliciousOracle)", "edge": "ENTRY", "desc": "Attacker calls unprotected setter to swap oracle"},
        {"order": 2, "fn": "getPrice() → returns 0", "edge": "ESCALATES_TO", "desc": "Malicious oracle returns 0, bypassing collateral check"},
        {"order": 3, "fn": "withdraw() → drain loop", "edge": "ESCALATES_TO", "desc": "Reentrancy drains entire ETH balance"},
    ]
}

def mock_graph_nodes(name: str):
    return [
        {"id": "n1", "label": "PublicUser", "type": "Actor", "x": 80, "y": 200},
        {"id": "n2", "label": "setOracle()", "type": "Function", "x": 260, "y": 100},
        {"id": "n3", "label": "getPrice()", "type": "Function", "x": 260, "y": 200},
        {"id": "n4", "label": "withdraw()", "type": "Function", "x": 260, "y": 300},
        {"id": "n5", "label": "oracleAddress", "type": "StateVariable", "x": 450, "y": 100},
        {"id": "n6", "label": "balance", "type": "StateVariable", "x": 450, "y": 300},
        {"id": "n7", "label": "MissingAccessControl", "type": "ThreatNode", "x": 640, "y": 80, "severity": "critical"},
        {"id": "n8", "label": "UncheckedReturn", "type": "ThreatNode", "x": 640, "y": 200, "severity": "high"},
        {"id": "n9", "label": "Reentrancy", "type": "ThreatNode", "x": 640, "y": 320, "severity": "critical"},
    ]

def mock_graph_edges():
    return [
        {"from": "n1", "to": "n2", "label": "CALLS"},
        {"from": "n1", "to": "n3", "label": "CALLS"},
        {"from": "n1", "to": "n4", "label": "CALLS"},
        {"from": "n2", "to": "n5", "label": "MODIFIES"},
        {"from": "n3", "to": "n5", "label": "READS"},
        {"from": "n4", "to": "n6", "label": "MODIFIES"},
        {"from": "n2", "to": "n7", "label": "TRIGGERS", "exploit": True},
        {"from": "n7", "to": "n8", "label": "ESCALATES_TO", "exploit": True},
        {"from": "n8", "to": "n9", "label": "ESCALATES_TO", "exploit": True},
    ]

def run_analysis(contract_code: str, contract_name: str):
    """Simulates the 3-phase pipeline. Swap phase B for real Anthropic calls."""
    time.sleep(0.8)  # simulate work

    # detect keywords to make it feel real
    code_lower = contract_code.lower()
    found_vulns = []
    for v in VULN_TEMPLATES:
        fn = v["function"].lower()
        if fn in code_lower or random.random() < 0.6:
            item = v.copy()
            item["contract"] = contract_name
            found_vulns.append(item)

    chain = EXPLOIT_CHAIN.copy()
    chain["steps"] = [s.copy() for s in EXPLOIT_CHAIN["steps"]]

    return {
        "vulnerabilities": found_vulns,
        "exploit_chain": chain,
        "nodes": mock_graph_nodes(contract_name),
        "edges": mock_graph_edges(),
        "stats": {
            "total_nodes": 9,
            "total_edges": 9,
            "total_vulns": len(found_vulns),
            "critical": sum(1 for v in found_vulns if v["severity"] == "critical"),
            "high": sum(1 for v in found_vulns if v["severity"] == "high"),
        }
    }

# ── routes ─────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "AegisGraph API running", "version": "0.1.0"}


@app.post("/api/audit")
def run_audit(req: AuditRequest):
    audit_id = str(uuid.uuid4())[:8]
    started = datetime.utcnow().isoformat()

    result = run_analysis(req.contract_code, req.contract_name)

    audit = {
        "audit_id": audit_id,
        "status": "done",
        "contract_name": req.contract_name,
        "created_at": started,
        "completed_at": datetime.utcnow().isoformat(),
        "phases": [
            {"phase": "A", "label": "Structural Extraction", "status": "done",
             "detail": f"AST compiled. {result['stats']['total_nodes']} nodes, {result['stats']['total_edges']} edges extracted."},
            {"phase": "B", "label": "Multi-Agent LLM Reasoning", "status": "done",
             "detail": f"AUDITOR found {result['stats']['total_vulns']} threat paths. CRITIC validated all chains."},
            {"phase": "C", "label": "Graph Pathfinding", "status": "done",
             "detail": "1 exploit chain confirmed. ESCALATES_TO edges synthesized."},
        ],
        **result,
    }

    AUDITS[audit_id] = audit
    return audit


@app.get("/api/audit/{audit_id}")
def get_audit(audit_id: str):
    if audit_id not in AUDITS:
        return {"error": "not found"}, 404
    return AUDITS[audit_id]


@app.get("/api/audits")
def list_audits():
    return list(AUDITS.values())
