import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# If running on Vercel or in a serverless read-only container, use /tmp
if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    DB_PATH = "/tmp/detecto.db"
else:
    DATA_DIR = os.path.join(CURRENT_DIR, "..", "data")
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        DB_PATH = os.path.abspath(os.path.join(DATA_DIR, "detecto.db"))
    except OSError:
        DB_PATH = "/tmp/detecto.db"

SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
