from fastapi import Request
from collections import deque
from typing import Callable

MAX_LOGS = 1000
logs = deque(maxlen=MAX_LOGS)

async def logger(request: Request, call_next: Callable):
    client_ip = request.client.host
    path = request.url.path
    method = request.method

    response = await call_next(request)
    status_code = response.status_code

    log_entry = {
        "client_ip": client_ip,
        "path": path,
        "method": method,
        "status_code": status_code,
    }
    logs.append(log_entry)
    return response

def get_logs(limit: int = 10):
    return list(logs)[-limit:]
