from sqlalchemy import create_engine
from models import Base
import os

# Database configuration
DATABASE_URL = "postgresql://usuario:Mpd758HNO3GUIcLz5DZctA@localhost/nombre_db"

def init_db():
    print(f"Connecting to database...")
    engine = create_engine(DATABASE_URL)
    
    print("Creating tables...")
    Base.metadata.create_all(bind=engine)
    print("Tables created successfully!")

if __name__ == "__main__":
    init_db()
