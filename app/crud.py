# app/crud.py
from app.models import users, items, rentals
from app.database import database
from sqlalchemy import insert, select

# Users
async def create_user(username: str, password: str):
    query = users.insert().values(username=username, password=password)
    await database.execute(query)

async def get_user(username: str):
    query = users.select().where(users.c.username == username)
    return await database.fetch_one(query)

# Items
async def create_item(_owner_id: int, _name: str, _description: str, _price_per_day: float, _image_url: str):
    query = insert(items).values(
        owner_id=_owner_id,
        name=_name,
        description=_description,
        price_per_day=_price_per_day,
        image_url=_image_url
    ).returning(items.c.id)
    result = await database.engine.execute("SHOW DATABASES")
    return result

async def get_item(item_id: int):
    query = select([items]).where(items.c.id == item_id)
    result = await database.fetch_one(query)
    return result

#Rentals
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
    query = select([rentals]).where(rentals.c.id == rental_id)
    result = await database.fetch_one(query)
    return result