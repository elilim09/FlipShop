from sqlite3 import IntegrityError
from fastapi import FastAPI, HTTPException, Depends, status, Request, Form, File, UploadFile,Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from datetime import timedelta, datetime
from sqlalchemy.orm import sessionmaker, Session
from app.database import database
from app import crud
from sqlalchemy import create_engine, Column, Integer, String, Text, TIMESTAMP, func, DateTime
from app.auth import create_access_token, verify_password, get_password_hash, decode_access_token, Token
from app.schemas import ItemCreate, Item, ItemBase
from pydantic import BaseModel, condecimal
import httpx
import dropbox
from dropbox.files import WriteMode
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, ForeignKey, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.models import users, items, rentals
from app.database import database
from sqlalchemy import insert, select, desc


Base = declarative_base()

ACCESS_TOKEN_EXPIRE_MINUTES = 43200  # 토큰 만료 시간 설정
DROP_API_KEY = "sl.B-r4vU7LPBpj-Ww-tUC3cD8L-8fz4Ea-JAW7r_GAq4zMVe8Ffp7ez3xmmGTHxI-X8o0xuUknvi9aqUy8nsPYB0us4Gq8wpTjpuzNYwhUUA4WCGJnNOQYtoaaepPP9QLy1fljTDZWdrJdIwJESb2HepY"
dbx = dropbox.Dropbox(DROP_API_KEY)
SQLALCHEMY_DATABASE_URL="mysql://root:0p0p0p0P!!@svc.sel5.cloudtype.app:32764/flipdb"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
class Item(BaseModel):
    name: str
    description: str
    price_per_day: condecimal(max_digits=10, decimal_places=2) # type: ignore
    owner_id: int
    image_url: str = None
    category: str
class UserCreateSchema(BaseModel):
    username: str
    password: str
    confirm_password: str

    def validate_passwords(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")

templates = Jinja2Templates(directory="app/templates")
app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.get("/")
@app.get("/index")
async def home(request: Request):
    query = select(items).order_by(desc(items.c.item_date))
    result = await database.fetch_all(query)
    return templates.TemplateResponse("home.html", {'request': request, 'items': result})

@app.get("/login")
async def login(request: Request):
    return templates.TemplateResponse("login.html", {'request': request})
@app.get("/signup")
async def signup(request: Request):
    return templates.TemplateResponse("signup ver2.html", {'request': request})
@app.post("/login")
async def postlogin(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
    ):
    user = db.query(UserModel).filter(
        (UserModel.username == form_data.username)
    ).first()

    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": user.username,
            "username": user.username,
        },
        expires_delta=access_token_expires
    )
    
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=access_token_expires,
        expires=access_token_expires,
        secure=True,  # HTTPS가 아닌 경우 False로 설정
        samesite="Strict"  # 필요에 따라 조정
    )

    return {"msg": "Login successful"}

@app.post("/signup")
async def postsignup(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    # 사용자 등록 데이터 검증
    user_data = UserCreateSchema(
        username=username,
        password=password,
        confirm_password=confirm_password
    )

    # 비밀번호 검증
    try:
        user_data.validate_passwords()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # 중복된 사용자 확인
    existing_username = db.query(UserModel).filter(UserModel.username == user_data.username).first()
    if existing_username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nickname already registered")
    # 사용자 생성
    hashed_password = get_password_hash(user_data.password)
    db_user = UserModel(
        username=user_data.username,
        password=hashed_password
    )

    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database integrity error")

    return templates.TemplateResponse("login.html", {"request": request})
    
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
@app.get("/create_item")
async def create_item_page(request: Request):
    return templates.TemplateResponse("create_item.html", {'request': request})

@app.post("/create_item/")
async def create_item(
    name: str = Form(...),
    category: str = Form(...),
    description: str = Form(...),
    price_per_day: float = Form(...),
    owner_id: int = Form(...),
    file: UploadFile = File(...)
):
    item_date = datetime.utcnow()

    if file.content_type not in ['image/jpeg', 'image/png']:
        raise HTTPException(status_code=400, detail="Invalid file type. Only JPEG and PNG files are allowed.")
    file_content = await file.read()
    
    if len(file_content) == 0:
        return {"msg": "File was empty, post created without file"}
    try:
        folder_path = f'/{owner_id}-{file.filename}'
            # Create folder if it doesn't exist
        try:
            dbx.files_get_metadata(folder_path)
        except dropbox.exceptions.ApiError as e:
            if e.error.is_path() and e.error.get_path().is_not_found():
                dbx.files_create_folder_v2(folder_path)
            else:
                raise HTTPException(status_code=500, detail=f"Failed to check or create folder: {str(e)}")
        file_path = f'{folder_path}/{file.filename}'
        dbx.files_upload(file_content, file_path, mode=WriteMode("overwrite"))
        link_response = dbx.sharing_create_shared_link_with_settings(file_path)
        shared_link = link_response.url
        image_url=shared_link
        image_url = shared_link.replace("dl=0", "raw=1")


    except Exception as e:
        raise HTTPException(status_code=500, detail=f"실패: {str(e)}")
    
    # 데이터베이스에 삽입 쿼리 작성
    query = """
    INSERT INTO items (owner_id, name, category, description, price_per_day, image_url, available, item_date)
    VALUES (:owner_id, :name, :category, :description, :price_per_day, :image_url, 1, :item_date)
    """
    values = {
        "owner_id": owner_id,
        "name": name,
        "category": category,
        "description": description,
        "price_per_day": price_per_day,
        "image_url": image_url,
        "item_date": item_date
    }

    # 데이터베이스에 쿼리 실행
    try:
        await database.execute(query=query, values=values)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to insert item into database. Error: " + str(e))

    return {
        "name": name,
        "category": category,
        "description": description,
        "price_per_day": price_per_day,
        "owner_id": owner_id,
        "image_url": image_url,
        "available": True
    }

@app.get("/items/{item_id}")
async def item_detail(item_id: int, request: Request):
    query = select(items).where(items.c.id == item_id)
    item = await database.fetch_one(query)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return templates.TemplateResponse("item_detail.html", {"request": request, "item": item})