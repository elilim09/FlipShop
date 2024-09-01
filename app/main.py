from fastapi import FastAPI, HTTPException, Depends, status, Request, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from datetime import timedelta
from typing import List, Optional
import requests
from app.database import database
from app import crud
from app.auth import create_access_token, verify_password, get_password_hash, decode_access_token, Token
from app.schemas import ItemCreate, Item

ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 토큰 만료 시간 설정
CLOUDTYPE_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiIzMnVwZHp0MmFscG8xMWcxcCIsImlhdCI6MTcyNDU0OTEzMX0.5ErRKcQgk5DIEs5on8dLvnNLwzrezZ9hyiChGi62GZ0"

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

# Items
@app.post("/items/", response_model=Item)
async def create_item(item: ItemCreate):
    # 이미지가 없을 경우 빈 리스트로 처리
    image_urls = item.images if item.images else []
    item_id = await crud.create_item(item.owner_id, item.name, item.description, item.price_per_day, image_urls)
    if item_id is None:
        raise HTTPException(status_code=500, detail="Item ID was not generated correctly.")
    return {"id": item_id, **item.dict(), "available": True}

@app.get("/create_item")
async def create_item_page(request: Request):
    return templates.TemplateResponse("create_item.html", {'request': request})

@app.post("/upload_image/")
async def upload_image(images: List[UploadFile] = File(None)):  # 파일이 없을 수 있음을 허용
    image_urls = []

    if images:
        for image in images:
            contents = await image.read()
            # 클라우드타입 API로 이미지 업로드
            response = requests.post(
                "https://api.cloudtype.io/upload",
                headers={"Authorization": f"Bearer {CLOUDTYPE_API_KEY}"},
                files={"file": contents},
            )

            if response.status_code != 200:
                print("Error:", response.status_code, response.text)
                raise HTTPException(status_code=500, detail="Image upload failed")

            # 업로드된 이미지의 URL 얻기
            image_url = response.json().get("url")
            image_urls.append(image_url)
    
    return {"image_urls": image_urls}

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