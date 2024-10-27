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


SQLALCHEMY_DATABASE_URL = "mysql+aiomysql://root:0p0p0p0P!!@svc.sel5.cloudtype.app:32764/flipdb"

# 메타데이터 객체 생성
metadata = MetaData()

# 비동기 엔진 생성
engine = create_async_engine(SQLALCHEMY_DATABASE_URL, echo=True)

# 세션 생성기
AsyncSessionLocal = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

# 데이터베이스 세션 제공 함수
async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session