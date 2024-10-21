# app/database.py
from databases import Database
from sqlalchemy import create_engine, MetaData

SQLALCHEMY_DATABASE_URL = "mysql+aiomysql://root:0p0p0p0P!!@svc.sel5.cloudtype.app:32764/flipdb"

database = Database(SQLALCHEMY_DATABASE_URL)
metadata = MetaData()

engine = create_engine(SQLALCHEMY_DATABASE_URL)