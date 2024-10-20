from sqlite3 import IntegrityError
from fastapi import FastAPI, HTTPException, Depends, status, Request, Form, File, UploadFile, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from datetime import timedelta, datetime
from sqlalchemy.orm import sessionmaker, Session
from app.database import database
from app import crud
from sqlalchemy import create_engine, Column, Integer, String, Text, TIMESTAMP, func, DateTime
from app.auth import create_access_token, verify_password, get_password_hash, decode_access_token, Token
from app.schemas import ItemCreate, Item, ItemBase
from pydantic import BaseModel, condecimal, validator
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
from fastapi.middleware.cors import CORSMiddleware  # CORS 미들웨어 추가
from fastapi.responses import RedirectResponse, JSONResponse
import jwt
Base = declarative_base()

ACCESS_TOKEN_EXPIRE_MINUTES = 43200  # 토큰 만료 시간 설정
DROP_API_KEY = "sl.B-r4vU7LPBpj-Ww-tUC3cD8L-8fz4Ea-JAW7r_GAq4zMVe8Ffp7ez3xmmGTHxI-X8o0xuUknvi9aqUy8nsPYB0us4Gq8wpTjpuzNYwhUUA4WCGJnNOQYtoaaepPP9QLy1fljTDZWdrJdIwJESb2HepY"
dbx = dropbox.Dropbox(DROP_API_KEY)
SQLALCHEMY_DATABASE_URL="mysql://root:0p0p0p0P!!@svc.sel5.cloudtype.app:32764/flipdb"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
SECRET_KEY='dktprtmgkrhtlvek'
class Item(BaseModel):
    name: str
    description: str
    price_per_day: condecimal(max_digits=10, decimal_places=2)  # type: ignore
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

templates = Jinja2Templates(directory="app/templates")
app = FastAPI()

# CORS 설정 추가
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 실제 서비스에서는 허용할 도메인으로 제한하세요
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
async def home(request: Request, response: Response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    query = select(items).order_by(desc(items.c.item_date))
    result = await database.fetch_all(query)
    return templates.TemplateResponse("home.html", {'request': request, 'items': result})

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
            "sub": user.id,
            "username": user.username,
        },
        expires_delta=access_token_expires
    )
    
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=False,
        max_age=access_token_expires.total_seconds(),
        expires=access_token_expires.total_seconds(),
        secure=False,
        samesite="Strict"
    )

    return RedirectResponse(url="/", status_code=302)


@app.post("/signup")
async def postsignup(
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
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
    existing_user = db.query(UserModel).filter(UserModel.username == user_data.username).first()
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
        db.commit()
        db.refresh(db_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database integrity error")

    return {"msg": "Signup successful"}

# Users
@app.post("/users", response_model=dict)
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

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt

@app.get("/mypage")
async def mypage(request: Request, db: Session = Depends(get_db)):
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
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if user is None:
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
        
        # 템플릿에 사용자 정보 전달
        return templates.TemplateResponse("mypage.html", {"request": request, "user": user})

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


if __name__ == "__main__": #이 코드가 직접 실행되었는가?
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) #ASGI실행 함수.
# 스크립트가 직접 실행될 때만 서버를 시작합니다.
# 다른 스크립트에서 이 모듈을 임포트할 때는 서버가 자동으로 시작되지 않게 합니다.
# 개발 중에 편리하게 서버를 실행할 수 있게 합니다.