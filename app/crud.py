# app/crud.py
from app.models import users, items, rentals
from app.database import database
from typing import List, Optional

# Users
async def create_user(username: str, password: str):
    query = users.insert().values(username=username, password=password)
    await database.execute(query)

async def get_user(username: str):
    query = users.select().where(users.c.username == username)
    return await database.fetch_one(query)

# Items
async def create_item(owner_id: int, name: str, description: str, price_per_day: float, image_urls: Optional[List[str]] = None):
    query = items.insert().values(owner_id=owner_id, name=name, description=description, price_per_day=price_per_day, image_urls=image_urls)
    item_id = await database.execute(query)
    return item_id

async def get_item(item_id: int):
    query = items.select().where(items.c.id == item_id)
    return await database.fetch_one(query)

# Rentals
async def create_rental(item_id: int, borrower_id: int, start_date: str, end_date: str, total_price: float):
    query = rentals.insert().values(item_id=item_id, borrower_id=borrower_id, start_date=start_date, end_date=end_date, total_price=total_price)
    await database.execute(query)

async def get_rental(rental_id: int):
    query = rentals.select().where(rentals.c.id == rental_id)
    return await database.fetch_one(query)