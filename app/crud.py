# app/crud.py
from app.models import users, items, rentals
from app.database import database
from sqlalchemy import insert, select, update, delete

# Users
async def create_user(username: str, password: str):
    query = users.insert().values(username=username, password=password)
    await database.execute(query)

async def get_user(username: str):
    query = users.select().where(users.c.username == username)
    return await database.fetch_one(query)

async def update_user_password(username: str, new_password: str):
    query = update(users).where(users.c.username == username).values(password=new_password)
    await database.execute(query)

async def delete_user(username: str):
    query = delete(users).where(users.c.username == username)
    await database.execute(query)

# Items
async def create_item(owner_id: int, name: str, description: str, price_per_day: float, image_url: str):
    query = insert(items).values(
        owner_id=owner_id,
        name=name,
        description=description,
        price_per_day=price_per_day,
        image_url=image_url
    ).returning(items.c.id)
    result = await database.execute(query)
    return result

async def get_item(item_id: int):
    query = select(items).where(items.c.id == item_id)
    result = await database.fetch_one(query)
    return result

async def update_item(item_id: int, **kwargs):
    query = update(items).where(items.c.id == item_id).values(**kwargs)
    await database.execute(query)

async def delete_item(item_id: int):
    query = delete(items).where(items.c.id == item_id)
    await database.execute(query)

# Rentals
async def create_rental(item_id: int, borrower_id: int, start_date: str, end_date: str, total_price: float):
    query = insert(rentals).values(
        item_id=item_id,
        borrower_id=borrower_id,
        start_date=start_date,
        end_date=end_date,
        total_price=total_price
    ).returning(rentals.c.id)
    result = await database.execute(query)
    return result

async def get_rental(rental_id: int):
    query = select(rentals).where(rentals.c.id == rental_id)
    result = await database.fetch_one(query)
    return result

async def update_rental(rental_id: int, **kwargs):
    query = update(rentals).where(rentals.c.id == rental_id).values(**kwargs)
    await database.execute(query)

async def delete_rental(rental_id: int):
    query = delete(rentals).where(rentals.c.id == rental_id)
    await database.execute(query)