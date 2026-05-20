"""
AegisGraph AI — Frontend MVP (Flask + Jinja2)
"""
import os
import requests
from flask import Flask, render_template, request, redirect, url_for, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")

SAMPLE_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IOracle {
    function getPrice() external returns (uint256);
}

contract VaultProtocol {
    address public owner;
    address public oracleAddress;
    mapping(address => uint256) public balances;

    constructor(address _oracle) {
        owner = msg.sender;
        oracleAddress = _oracle;
    }

    // VULNERABILITY: No access control — anyone can call this
    function setOracle(address _oracle) external {
        oracleAddress = _oracle;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABILITY: Unchecked oracle return value
    function withdraw(uint256 amount) external {
        uint256 price = IOracle(oracleAddress).getPrice();
        uint256 collateral = balances[msg.sender] * price;
        require(collateral >= amount, "Undercollateralized");

        // VULNERABILITY: State update AFTER external call (reentrancy)
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] -= amount;
    }
}
"""


@app.route("/")
def dashboard():
    try:
        resp = requests.get(f"{API_BASE}/api/audits", timeout=3)
        audits = resp.json() if resp.ok else []
    except Exception:
        audits = []
    return render_template("dashboard.html", audits=audits, api_ok=len(audits) >= 0)


@app.route("/audit/new", methods=["GET", "POST"])
def audit_new():
    if request.method == "POST":
        code = request.form.get("contract_code", "")
        name = request.form.get("contract_name", "MyContract")
        try:
            resp = requests.post(
                f"{API_BASE}/api/audit",
                json={"contract_code": code, "contract_name": name},
                timeout=15,
            )
            if resp.ok:
                data = resp.json()
                return redirect(url_for("audit_result", audit_id=data["audit_id"]))
        except Exception as e:
            return render_template("audit_new.html", error=str(e), sample=SAMPLE_CONTRACT)
    return render_template("audit_new.html", sample=SAMPLE_CONTRACT)


@app.route("/audit/<audit_id>")
def audit_result(audit_id):
    try:
        resp = requests.get(f"{API_BASE}/api/audit/{audit_id}", timeout=5)
        audit = resp.json()
    except Exception as e:
        return render_template("error.html", message=str(e))
    return render_template("audit_result.html", audit=audit)


@app.route("/api/proxy/audits")
def proxy_audits():
    try:
        resp = requests.get(f"{API_BASE}/api/audits", timeout=3)
        return jsonify(resp.json())
    except Exception:
        return jsonify([])


if __name__ == "__main__":
    app.run(debug=True, port=5000)
