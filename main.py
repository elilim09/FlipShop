from fastapi import FastAPI, HTTPException, Depends, status, Request, Form, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from datetime import timedelta
from app.database import database
from app import crud
from app.auth import create_access_token, verify_password, get_password_hash, decode_access_token, Token
from app.schemas import ItemCreate, Item
from pydantic import BaseModel, condecimal
import httpx

ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 토큰 만료 시간 설정
IMG_API_KEY = "03793201bec72665258582109933dc9e"

class Item(BaseModel):
    name: str
    description: str
    price_per_day: condecimal(max_digits=10, decimal_places=2) # type: ignore
    owner_id: int
    image_url: str = None


templates = Jinja2Templates(directory="app/templates")
app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.get("/")
async def read_root():
    return {"message": "Welcome to FlipShop API"}

# Users
@app.post("/users/", response_model=dict)
async def create_user(username: str, password: str):
    user = await crud.get_user(username)
    if user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(password)
    await crud.create_user(username, hashed_password)
    return {"username": username}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await crud.get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

#items
@app.post("/items/", response_model=Item)
async def create_item(
    name: str = Form(...),
    description: str = Form(...),
    price_per_day: condecimal(max_digits=10, decimal_places=2) = Form(...),
    owner_id: int = Form(...),
    file: UploadFile = File(...)
):
    # 파일 타입 확인 (JPEG, PNG만 허용)
    if file.content_type not in ['image/jpeg', 'image/png']:
        raise HTTPException(status_code=400, detail="Invalid file type. Only JPEG and PNG files are allowed.")

    # 파일 내용 읽기 및 처리
    file_content = await file.read()

    # imgbb로 파일 업로드
    imgbb_url = "https://api.imgbb.com/1/upload"
    async with httpx.AsyncClient() as client:
        response = await client.post(
            imgbb_url,
            params={"key": IMG_API_KEY},
            files={"image": (file.filename, file_content, file.content_type)}
        )

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to upload image to imgbb")

    data = response.json()
    image_url = data["data"]["url"]

    # 데이터베이스에 저장
    item_id = await crud.create_item(owner_id, name, description, price_per_day, image_url)

    if item_id is None:
        raise HTTPException(status_code=500, detail="Item ID was not generated correctly.")

    return {"id": item_id, "name": name, "description": description, "price_per_day": price_per_day, "owner_id": owner_id, "image_url": image_url, "available": True}

@app.get("/create_item")
async def create_item_page(request: Request):
    return templates.TemplateResponse("create_item.html", {'request': request})

@app.get("/items/{item_id}")
async def read_item(item_id: int, request: Request):
    item = await crud.get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return templates.TemplateResponse("item_detail.html", {"request": request, "item": item})

# Rentals
@app.post("/rentals/", response_model=dict)
async def create_rental(item_id: int, borrower_id: int, start_date: str, end_date: str, total_price: float):
    await crud.create_rental(item_id, borrower_id, start_date, end_date, total_price)
    return {"item_id": item_id}

@app.get("/rentals/{rental_id}", response_model=dict)
async def read_rental(rental_id: int):
    rental = await crud.get_rental(rental_id)
    if not rental:
        raise HTTPException(status_code=404, detail="Rental not found")
    return rental