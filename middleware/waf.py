from fastapi import Request
from typing import Callable
from middleware.database import add_log, add_alert
import re

SQLI_PATTERNS = re.compile(r'\b(?:OR\s*\d*\s*=\s*\d*|--|;|UNION\s+SELECT|(?:AND|OR)\s*[\w\s][=<>]+\s*[\w\s\'])\b|\b(?:SELECT|UNION|INSERT|UPDATE|DELETE|FROM|WHERE)\b', re.IGNORECASE)
XSS_PATTERNS = re.compile(r'(<\s*script\s*.*?>.*?</\s*script\s*>)|(\bon\w+\s*=\s*["\'].*?["\'])', re.IGNORECASE)

def wafCheck(request):
    if SQLI_PATTERNS.search(request):
        return "SQL Injection"
    
    if XSS_PATTERNS.search(request):
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
    payload = body.decode("utf-8") if body else None

    attack = wafCheck(request.url.path)
    if attack:
        add_alert(client_ip=client_ip, path=path, method=method, payload=payload, attack=attack)

    add_log(client_ip=client_ip, path=path, method=method, payload=payload)

    response = await call_next(request)
    return response
