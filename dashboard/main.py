from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import json

from web3 import Web3

from ids_engine import ids_engine
from blockchain.blockchain_config import GANACHE_RPC, CONTRACT_ADDRESS


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="AI-Powered IDS Dashboard",
    description="Live Intrusion Detection System using ML and Blockchain",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# PATHS
# ============================================================

ABI_FILE = "blockchain/AlertStorage_abi.json"
DASHBOARD_FILE = "dashboard/index.html"


# ============================================================
# BLOCKCHAIN CONNECTION
# ============================================================

w3 = Web3(Web3.HTTPProvider(GANACHE_RPC))

contract = None

try:
    with open(ABI_FILE, "r") as f:
        abi = json.load(f)

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS),
        abi=abi
    )

    print("[DASHBOARD] Blockchain connected.")

except Exception as e:
    print("[DASHBOARD] Blockchain connection failed:", e)
    contract = None


# ============================================================
# DASHBOARD PAGE
# ============================================================

@app.get("/")
def dashboard():
    return FileResponse(DASHBOARD_FILE)


# ============================================================
# API INFORMATION
# ============================================================

@app.get("/api")
def api_info():

    return {
        "message": "AI-Powered IDS API",
        "endpoints": {
            "start": "POST /api/ids/start",
            "stop": "POST /api/ids/stop",
            "status": "GET /api/ids/status",
            "results": "GET /api/ids/results",
            "alerts": "GET /api/ids/alerts",
            "blockchain_alerts": "GET /api/blockchain/alerts",
            "blockchain_latest": "GET /api/blockchain/latest"
        }
    }


# ============================================================
# START LIVE IDS
# ============================================================

@app.post("/api/ids/start")
def start_ids():

    started = ids_engine.start()

    return {
        "success": started,
        "message": "Live IDS started." if started else "IDS is already running.",
        "status": ids_engine.get_status()
    }


# ============================================================
# STOP LIVE IDS
# ============================================================

@app.post("/api/ids/stop")
def stop_ids():

    stopped = ids_engine.stop()

    return {
        "success": stopped,
        "message": "Live IDS stopped.",
        "status": ids_engine.get_status()
    }


# ============================================================
# LIVE IDS STATUS
# ============================================================

@app.get("/api/ids/status")
def ids_status():

    return ids_engine.get_status()


# ============================================================
# LIVE IDS RESULTS
# ============================================================

@app.get("/api/ids/results")
def ids_results():

    return {
        "results": ids_engine.get_results()
    }


# ============================================================
# LIVE SECURITY ALERTS
# ============================================================

@app.get("/api/ids/alerts")
def ids_alerts():

    return {
        "alerts": ids_engine.get_alerts()
    }


# ============================================================
# BLOCKCHAIN ALERT COUNT
# ============================================================

@app.get("/api/blockchain/count")
def blockchain_count():

    if contract is None:
        return {
            "connected": False,
            "count": 0
        }

    try:

        count = contract.functions.alertCount().call()

        return {
            "connected": True,
            "count": count
        }

    except Exception as e:

        return {
            "connected": False,
            "count": 0,
            "error": str(e)
        }


# ============================================================
# ALL BLOCKCHAIN ALERTS
# ============================================================

@app.get("/api/blockchain/alerts")
def blockchain_alerts():

    if contract is None:
        return {
            "connected": False,
            "alerts": []
        }

    try:

        count = contract.functions.alertCount().call()

        alerts = []

        for i in range(1, count + 1):

            alert = contract.functions.getAlert(i).call()

            alerts.append({
                "id": alert[0],
                "hash": alert[1],
                "timestamp": alert[2],
                "src_ip": alert[3],
                "dst_ip": alert[4],
                "src_port": alert[5],
                "dst_port": alert[6],
                "protocol": alert[7],
                "attack_probability": alert[8]
            })

        return {
            "connected": True,
            "alerts": list(reversed(alerts))
        }

    except Exception as e:

        return {
            "connected": False,
            "alerts": [],
            "error": str(e)
        }


# ============================================================
# LATEST BLOCKCHAIN ALERT
# ============================================================

@app.get("/api/blockchain/latest")
def blockchain_latest():

    if contract is None:
        return {
            "connected": False,
            "alert": None
        }

    try:

        count = contract.functions.alertCount().call()

        if count == 0:
            return {
                "connected": True,
                "alert": None
            }

        alert = contract.functions.getAlert(count).call()

        return {
            "connected": True,
            "alert": {
                "id": alert[0],
                "hash": alert[1],
                "timestamp": alert[2],
                "src_ip": alert[3],
                "dst_ip": alert[4],
                "src_port": alert[5],
                "dst_port": alert[6],
                "protocol": alert[7],
                "attack_probability": alert[8]
            }
        }

    except Exception as e:

        return {
            "connected": False,
            "alert": None,
            "error": str(e)
        }