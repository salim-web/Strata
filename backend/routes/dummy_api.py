from fastapi import APIRouter, Request, Depends, Query, Body, HTTPException, status
from typing import Dict, Any
from backend.middleware.jwt_auth import verify_jwt, create_access_token

router = APIRouter(prefix="/api/v1", tags=["Dummy Attacker Targets"])

# In-memory incident log store for dashboard feeding
INCIDENT_LOGS = []

@router.get("/public/ping")
async def ping():
    """Public health check endpoint."""
    return {"status": "ok", "message": "STRATA security core online"}

@router.post("/login")
async def login(credentials: Dict[str, Any] = Body(...)):
    """
    Fake Login Endpoint (Target for Brute-force attacks).
    """
    username = credentials.get("username", "")
    password = credentials.get("password", "")

    # Basic honeypot response
    if username == "admin" and password == "secret123":
        token = create_access_token({"sub": username, "role": "admin"})
        return {"access_token": token, "token_type": "bearer"}

    # Log suspicious attempt if sql injection detected in input
    sql_patterns = ["' OR '1'='1", "UNION SELECT", "DROP TABLE", "--", "';"]
    if any(pattern in username for pattern in sql_patterns) or any(pattern in password for pattern in sql_patterns):
        INCIDENT_LOGS.append({
            "type": "SQL_INJECTION_ATTEMPT",
            "payload": f"username={username}",
            "severity": "CRITICAL"
        })
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malicious syntax detected by WAF engine."
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials"
    )

@router.get("/user/profile")
async def get_profile(payload: dict = Depends(verify_jwt)):
    """Protected Endpoint requiring valid JWT token."""
    return {
        "user_id": 1042,
        "username": payload.get("sub", "user"),
        "role": payload.get("role", "member"),
        "email": "target_user@strata.io"
    }

@router.get("/payment/transfer")
async def transfer_money(
    amount: float = Query(...),
    recipient: str = Query(...),
    payload: dict = Depends(verify_jwt)
):
    """Protected financial endpoint targeted by attackers."""
    return {
        "status": "success",
        "transaction_id": "tx_9981247",
        "amount": amount,
        "recipient": recipient
    }

@router.get("/logs/incidents")
async def get_incident_logs():
    """Retrieve simulated incident logs for ThreatFeed UI."""
    return {"incidents": INCIDENT_LOGS}
