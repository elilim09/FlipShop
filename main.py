from sqlite3 import IntegrityError
from fastapi import FastAPI, HTTPException, Depends, status, Request, Form, File, UploadFile, Response, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from datetime import timedelta, datetime
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, Integer, String, Text, ForeignKey, select, or_, desc, DateTime
from sqlalchemy.ext.declarative import declarative_base
from app.auth import create_access_token, verify_password, get_password_hash, decode_access_token, Token
from pydantic import BaseModel, validator
import dropbox
from dropbox.files import WriteMode
from fastapi.middleware.cors import CORSMiddleware  # CORS 미들웨어 추가
from fastapi.responses import RedirectResponse
import jwt

Base = declarative_base()

ACCESS_TOKEN_EXPIRE_MINUTES = 43200  # 토큰 만료 시간 설정
DROP_API_KEY = "sl.B-r4vU7LPBpj-Ww-tUC3cD8L-8fz4Ea-JAW7r_GAq4zMVe8Ffp7ez3xmmGTHxI-X8o0xuUknvi9aqUy8nsPYB0us4Gq8wpTjpuzNYwhUUA4WCGJnNOQYtoaaepPP9QLy1fljTDZWdrJdIwJESb2HepY"
dbx = dropbox.Dropbox(DROP_API_KEY)
SQLALCHEMY_DATABASE_URL = "mysql+aiomysql://root:0p0p0p0P!!@svc.sel5.cloudtype.app:32764/flipdb"
engine = create_async_engine(SQLALCHEMY_DATABASE_URL, echo=True)
AsyncSessionLocal = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
SECRET_KEY = 'dktprtmgkrhtlvek'

class ItemSchema(BaseModel):
    name: str
    description: str
    price_per_day: float
    owner_id: int
    image_url: str = None
    category: str

class UserCreateSchema(BaseModel):
    username: str
    password: str
    confirm_password: str

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

    class Config:
        orm_mode = True

templates = Jinja2Templates(directory="app/templates")
app = FastAPI()

# CORS 설정 추가
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 실제 서비스에서는 허용할 도메인으로 제한하기!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    password = Column(String(255))

class ItemModel(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey('users.id'))
    name = Column(String(255))
    category = Column(String(255))
    description = Column(Text)
    price_per_day = Column(Integer)
    image_url = Column(String(255))
    available = Column(Integer)
    item_date = Column(DateTime)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@app.get("/")
@app.get("/index")
async def home(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    result = await db.execute(select(ItemModel).order_by(desc(ItemModel.item_date)))
    items_list = result.scalars().all()
    return templates.TemplateResponse("home.html", {'request': request, 'items': items_list})

@app.get("/login")
async def login(request: Request):
    return templates.TemplateResponse("login.html", {'request': request})

@app.get("/signup")
async def signup(request: Request):
    return templates.TemplateResponse("signup_ver2.html", {'request': request})

@app.post("/login")
async def postlogin(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.username == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
        },
        expires_delta=access_token_expires
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=int(access_token_expires.total_seconds()),
        expires=int(access_token_expires.total_seconds()),
        secure=False,
        samesite="Lax"
    )

    return RedirectResponse(url="/", status_code=302)

@app.post("/signup")
async def postsignup(
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    # 사용자 등록 데이터 검증
    try:
        user_data = UserCreateSchema(
            username=username,
            password=password,
            confirm_password=confirm_password
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # 중복된 사용자 확인
    result = await db.execute(select(UserModel).where(UserModel.username == user_data.username))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")

    # 사용자 생성
    hashed_password = get_password_hash(user_data.password)
    db_user = UserModel(
        username=user_data.username,
        password=hashed_password
    )

    try:
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database integrity error")

    return {"msg": "Signup successful"}

@app.get("/mypage")
async def mypage(request: Request, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="인증 정보가 없습니다.")

    try:
        # JWT 디코딩
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        current_time = datetime.utcnow().timestamp()
        exp_time = payload.get("exp")

        if exp_time is not None and current_time > exp_time:
            raise HTTPException(status_code=401, detail="토큰이 만료되었습니다.")

        username = payload.get("username")
        if username is None:
            raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")

        # 데이터베이스에서 사용자 정보 불러오기
        result = await db.execute(select(UserModel).where(UserModel.username == username))
        user = result.scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

        # 템플릿에 사용자 정보 전달 및 user_is_authenticated 설정
        return templates.TemplateResponse("mypage.html", {"request": request, "user": user, "user_is_authenticated": True})

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="토큰이 만료되었습니다.")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")

@app.get("/logout")
async def logout(request: Request, response: Response):
    response.delete_cookie(key="access_token", path="/")
    return RedirectResponse(url="/login")

@app.get("/validate_token")
async def validate_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = decode_access_token(token)
        if payload:
            return {"valid": True}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# Items
@app.get("/create_item")
async def create_item_page(request: Request):
    return templates.TemplateResponse("create_item.html", {'request': request})

@app.post("/create_item")
async def create_item(
    name: str = Form(...),
    category: str = Form(...),
    description: str = Form(...),
    price_per_day: float = Form(...),
    owner_id: int = Form(...),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db)
):
    item_date = datetime.utcnow()

    if file.content_type not in ['image/jpeg', 'image/png']:
        raise HTTPException(status_code=400, detail="Invalid file type. Only JPEG and PNG files are allowed.")
    file_content = await file.read()

    if len(file_content) == 0:
        return {"msg": "File was empty, post created without file"}
    try:
        folder_path = f'/{owner_id}-{file.filename}'
        # 폴더가 없으면 생성
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
        image_url = shared_link.replace("dl=0", "raw=1")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")

    # 데이터베이스에 아이템 정보 삽입
    new_item = ItemModel(
        owner_id=owner_id,
        name=name,
        category=category,
        description=description,
        price_per_day=price_per_day,
        image_url=image_url,
        available=1,
        item_date=item_date
    )

    # 데이터베이스에 쿼리 실행
    try:
        db.add(new_item)
        await db.commit()
        await db.refresh(new_item)
    except Exception as e:
        await db.rollback()
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
async def item_detail(item_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ItemModel).where(ItemModel.id == item_id))
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return templates.TemplateResponse("item_detail.html", {"request": request, "item": item})

@app.get("/search/")
async def search(
    request: Request,
    target: str = Query(..., description="검색할 키워드"),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(ItemModel)
        .where(or_(ItemModel.name.like(f"%{target}%"), ItemModel.description.like(f"%{target}%")))
        .order_by(ItemModel.item_date)
        .limit(10)
    )
    items_list = result.scalars().all()
    if not items_list:
        raise HTTPException(status_code=404, detail="검색 결과가 없습니다.")

    return templates.TemplateResponse("home.html", {"request": request, "items": items_list})

if __name__ == "__main__":  # 이 코드가 직접 실행되었는가?
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)  # ASGI 실행 함수.

# app/auth.py
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel

SECRET_KEY = 'dktprtmgkrhtlvek'
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Token(BaseModel):
    access_token: str
    token_type: str

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)  # 기본 15분
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return payload

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)