# app/models.py
from sqlalchemy import Table, Column, Integer, String, MetaData, ForeignKey, Boolean, Float, DateTime
from app.database import metadata
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, unique=True, index=True),
    Column("password", String),
)

items = Table(
    "items",
    Base.metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("name", String, index=True),
    Column("description", String),
    Column("owner_id", Integer, ForeignKey("users.id")),
    Column("price_per_day", Float),
    Column("available", Boolean, default=True),
    Column("image_url", String),
    Column("item_date", DateTime)
)

rentals = Table(
    "rentals",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("item_id", Integer, ForeignKey("items.id")),
    Column("borrower_id", Integer, ForeignKey("users.id")),
    Column("start_date", DateTime),
    Column("end_date", DateTime),
    Column("total_price", Float),
)