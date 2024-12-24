from fastapi import Request
from typing import Callable
from middleware.database import add_log, add_alert
import re

SQLI_PATTERNS = re.compile(r"(\b(?:OR|AND)\s*\d*\s*(?:=\s*\d*|LIKE)\s*|--\s*|\b(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP|FROM|WHERE|AND)\b)", re.IGNORECASE)
XSS_PATTERNS = re.compile(r'(<\s*script\s*.*?>.*?</\s*script\s*>)|(\bon\w+\s*=\s*["\'].*?["\'])', re.IGNORECASE)

def wafCheck(payload: str):
    """
    Checks for SQL Injection or XSS patterns in the request body (payload).
    """
    if SQLI_PATTERNS.search(payload):
        return "SQL Injection"
    
    if XSS_PATTERNS.search(payload):
        return "XSS"
    
    return None


async def logger(request: Request, call_next: Callable):
    """
    Middleware to log incoming requests.
    """
    client_ip = request.client.host
    path = request.url.path
    method = request.method
    body = await request.body()
    payload = body.decode("utf-8") if body else ""

    if method == "POST":
        attack = wafCheck(payload)
        if attack:
            add_alert(client_ip=client_ip, path=path, method=method, payload=payload, attack=attack)

    add_log(client_ip=client_ip, path=path, method=method, payload=payload)

    response = await call_next(request)
    return response
