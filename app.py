from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from middleware.database import get_db, User, init_db , get_logs, get_alerts
from middleware.waf import logger, wafCheck
import uvicorn

app = FastAPI()
app.middleware("http")(logger)

templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def homePage(request: Request):
    """
    Render the homepage.
    """
    return templates.TemplateResponse("homepage.html", {"request": request})

@app.get("/register")
async def register(request: Request):
    """
    Render the registration form.
    """
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register_user(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    """
    Handle registration of a new user.
    """
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Username already exists."})
    
    new_user = User(username=username, password=password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return templates.TemplateResponse("login.html", {"request": request, "message": "Registration successful. Please log in."})


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
        return templates.TemplateResponse("userpage.html", {"request": request, "user": user})
    
    return templates.TemplateResponse("login.html", {"request": request, "error": "Login Failed. Please try again."})
    
@app.get("/logs")
async def fetch_logs(limit: int = 10):
    """
    Fetch recent logs.
    :param limit: Number of logs to fetch.
    """
    return get_logs(limit=limit)

@app.get("/alerts", response_class=HTMLResponse)
async def fetch_alerts(request: Request,limit: int = 10):
    """
    Fetch recent alerts.
    :param limit: Number of alerts to fetch.
    """

    alerts = get_alerts(limit=limit)

    return templates.TemplateResponse("alerts.html", {"request": request, "alerts": alerts})

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
