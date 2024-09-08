# app/schemas.py
from pydantic import BaseModel, Field, condecimal

class ItemBase(BaseModel):
    name: str
    description: str
    price_per_day: condecimal(max_digits=10, decimal_places=2) # type: ignore
    owner_id: int
    
class ItemCreate(ItemBase):
    image_url: str

class Item(ItemBase):
    id: int
    image_url: str
    available: bool

    class Config:
        orm_mode = True