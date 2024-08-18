# app/schemas.py
from pydantic import BaseModel, Field

class ItemCreate(BaseModel):
    owner_id: int
    name: str
    description: str
    price_per_day: float = Field(..., gt=0)

class Item(ItemCreate):
    id: int
    available: bool

    class Config:
        orm_mode = True