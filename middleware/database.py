from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DB_URL = "sqlite:///./waf.db"

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    client_ip = Column(String)
    path = Column(String)
    method = Column(String)
    payload = Column(String, nullable=True)
    suspicious = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=func.now())

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    client_ip = Column(String)
    path = Column(String)
    method = Column(String)
    attack = Column(String)
    payload = Column(String, nullable=True)
    timestamp = Column(DateTime, default=func.now())

def init_db():
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def add_log(client_ip: str, path: str, method: str, payload: str):
    with SessionLocal() as session:
        log = Log(client_ip=client_ip, path=path, method=method, payload=payload)
        session.add(log)
        session.commit()

def add_alert(client_ip: str, path: str, method: str, payload: str, attack: str):
    with SessionLocal() as session:
        alert = Alert(client_ip=client_ip, path=path, method=method, payload=payload, attack=attack)
        session.add(alert)
        session.commit()

def get_logs(limit: int = 10):
    with SessionLocal() as session:
        logs = session.query(Log).order_by(Log.timestamp.desc()).limit(limit).all()
        return logs

def get_alerts(limit: int = 10):
    with SessionLocal() as session:
        alerts = session.query(Alert).order_by(Alert.timestamp.desc()).limit(limit).all()
        return alerts

if __name__ == "__main__":
    init_db()