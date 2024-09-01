# app/schemas.py
from pydantic import BaseModel, Field

class ItemBase(BaseModel):
    name: str
    description: str
    price_per_day: float
    owner_id: int

class ItemCreate(ItemBase):
    image_url: str

class Item(ItemBase):
    id: int
    image_url: str
    available: bool

    class Config:
        orm_mode = True