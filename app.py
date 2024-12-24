from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from middleware.database import get_db, User, init_db , get_logs
from middleware.log import logger
import uvicorn

app = FastAPI()
app.middleware("http")(logger)

templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def homePage(request: Request):
    """
    Redirect to the login page.
    """
    return RedirectResponse(url=request.url_for("loginPage"))

@app.get("/login", response_class=HTMLResponse)
async def loginPage(request: Request):
    """
    Render the login page.
    """
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    """
    Process login attempts.
    """
    user = db.query(User).filter(User.username == username).first()
    
    if user and user.password == password:
        return {"message": "Login Successful"}
    
    return {"message": "Login Failed"}


@app.get("/logs")
async def fetch_logs(limit: int = 10):
    """
    Fetch recent logs.
    :param limit: Number of logs to fetch.
    """
    return get_logs(limit=limit)

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
