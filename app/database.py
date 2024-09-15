# app/database.py
from databases import Database
from sqlalchemy import create_engine, MetaData

DATABASE_URL = "mysql://root:0p0p0p0P!!@svc.sel5.cloudtype.app:32764/flipdb"

database = Database(DATABASE_URL)
metadata = MetaData()

engine = create_engine(DATABASE_URL)