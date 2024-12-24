from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from middleware import logger, get_logs
import uvicorn

app = FastAPI()
app.middleware("http")(logger)
templates = Jinja2Templates(directory="templates")

@app.get("/logs")
async def fetch_logs(limit: int = 10):
    """
    Fetch recent logs.
    :param limit: Number of logs to fetch.
    """
    return get_logs(limit=limit)

@app.get("/", response_class=HTMLResponse)
async def homePage(request: Request):
    return RedirectResponse(url = request.url_for("loginPage"))

@app.get("/login", response_class=HTMLResponse)
async def loginPage(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == "admin" and password == "admin":
        return {"message": "Login Successful"}
    return {"error": "Invalid Credentials"}

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
