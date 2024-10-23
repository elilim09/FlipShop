# app/database.py
from databases import Database
from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import os

# SQLALCHEMY_DATABASE_URL = "mysql+aiomysql://root:0p0p0p0P!!@svc.sel5.cloudtype.app:32764/flipdb"

# database = Database(SQLALCHEMY_DATABASE_URL)
# metadata = MetaData()

# engine = create_engine(SQLALCHEMY_DATABASE_URL)


DATABASE_URL = os.environ.get('DATABASE_URL', 'mysql+aiomysql://root:YOUR_PASSWORD@svc.sel5.cloudtype.app:32764/flipdb')

engine = create_async_engine(DATABASE_URL, echo=True)
AsyncSessionLocal = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
metadata = MetaData()