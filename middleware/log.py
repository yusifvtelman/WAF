from fastapi import Request
from typing import Callable
from middleware.database import add_log

async def logger(request: Request, call_next: Callable):
    """
    Middleware to log incoming requests.
    """

    client_ip = request.client.host
    path = request.url.path
    method = request.method

    body = await request.body()
    payload = body.decode("utf-8") if body else None


    add_log(client_ip=client_ip, path=path, method=method, payload=payload)

    response = await call_next(request)
    return response
