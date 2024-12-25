import base64
import binascii
import re
import urllib.parse
from fastapi import Request
from typing import Callable
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from middleware.database import add_log, add_alert

templates = Jinja2Templates(directory="templates")

SQLI_PATTERNS = re.compile(r"(\b(?:OR|AND)\s*\d*\s*(?:=\s*\d*|LIKE|IN\s*\(\s*\d*\s*\))\s*|--\s*|\b(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP|FROM|WHERE|AND|EXEC|TRUNCATE|HAVING|NULL|SLEEP)\b)", re.IGNORECASE)

XSS_PATTERNS = re.compile(
    r'<\s*script.*?>.*?</\s*script\s*>'  
    r'|\bon\w+\s*=\s*["\'][^"\']*["\']'  
    r'|javascript\s*:\s*[^"\'>]*'  
    r'|data\s*:\s*[^"\'>]*base64,.*?' 
    r'|<\s*(iframe|object|embed|form|input)\b.*?>.*?</\s*\1\s*>'  
    r'|on\w+\s*=\s*["\'][^"\']*["\']', 
    re.IGNORECASE
)

def is_base64_encoded(data: str) -> bool:
    try:
        base64.b64decode(data, validate=True)
        return True
    except (base64.binascii.Error, ValueError):
        return False

def is_url_encoded(data: str) -> bool:
    try:
        decoded = urllib.parse.unquote(data)
        return decoded != data
    except:
        return False

def is_hex_encoded(data: str) -> bool:
    try:
        binascii.unhexlify(data)
        return True
    except binascii.Error:
        return False

def wafCheck(payload: str):
    """
    Checks for SQL Injection or XSS patterns in the request body (payload).
    """
    if SQLI_PATTERNS.search(payload):
        return "SQL Injection"
    
    if XSS_PATTERNS.search(payload):
        return "XSS"
    
    if is_base64_encoded(payload):
        try:
            decoded_payload = base64.b64decode(payload).decode('utf-8', errors='ignore')
            if XSS_PATTERNS.search(decoded_payload):
                return "Base64-encoded XSS detected"
            if SQLI_PATTERNS.search(decoded_payload):
                return "Base64-encoded SQL Injection detected"
        except (binascii.Error, ValueError):
            pass 

    if is_url_encoded(payload):
        decoded_payload = urllib.parse.unquote(payload)
        if XSS_PATTERNS.search(decoded_payload):
            return "URL-encoded XSS detected"
        if SQLI_PATTERNS.search(decoded_payload):
            return "URL-encoded SQL Injection detected"

    if is_hex_encoded(payload):
        decoded_payload = bytearray.fromhex(payload).decode('utf-8', errors='ignore')
        if XSS_PATTERNS.search(decoded_payload):
            return "Hex-encoded XSS detected"
        if SQLI_PATTERNS.search(decoded_payload):
            return "Hex-encoded SQL Injection detected"
        
    return None

async def logger(request: Request, call_next: Callable):
    """
    Middleware to log incoming requests and check for attacks.
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
