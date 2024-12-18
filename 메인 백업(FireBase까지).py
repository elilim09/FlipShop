from sqlite3 import IntegrityError
from fastapi import FastAPI, HTTPException, Depends, status, Request, Form, File, UploadFile, Response, Query, Cookie
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from datetime import datetime as dt
from datetime import timedelta as td
import datetime
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, Integer, String, Text, ForeignKey, select, or_, desc, DateTime
from sqlalchemy.ext.declarative import declarative_base
from app.auth import create_access_token, verify_password, get_password_hash, decode_access_token, Token
from pydantic import BaseModel, validator, EmailStr
import dropbox
from dropbox.files import WriteMode
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, Response
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError
import json
import os

import time
from fastapi import FastAPI, HTTPException, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.future import select
from app.models import ChatModel  # ChatModel 가져오기
from typing import List

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
import firebase_admin
from firebase_admin import credentials, auth
from google.cloud import vision
import googlemaps
from datetime import datetime, timedelta
import jwt

Base = declarative_base()

ACCESS_TOKEN_EXPIRE_MINUTES = 43200  # 토큰 만료 시간 설정
SECRET_KEY = 'dkgkqrurgkrhtlvek' #os.environ.get('SECRET_KEY', 'dkgkqrurgkrhtlvek')
ALGORITHM = "HS256"

DROP_API_KEY = "sl.B_ivWy2MbVQbAhETFXJAe0774dEmm2-AYzQl1VAHS7jhSZhj1-hKHiY5UpwBXfI6U-hVQI03zyHCIlpgW_sKIYiy2MRlfwXivY9NeG-KVJ-FcwxY0i_r6lEwS6jh-9hhfeolLAoMGo0OJWHYLr-fmWQ"  # 실제 키로 대체하세요
dbx = dropbox.Dropbox(DROP_API_KEY)
SQLALCHEMY_DATABASE_URL = "mysql+aiomysql://root:0p0p0p0P!!@svc.sel5.cloudtype.app:32764/flipdb"  # 실제 URL로 대체하세요
engine = create_async_engine(SQLALCHEMY_DATABASE_URL, echo=True)
AsyncSessionLocal = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

# Firebase 초기화
cred = credentials.Certificate("app/config/flipshop-438500-firebase-adminsdk-c2uus-7de82c527f.json")
firebase_admin.initialize_app(cred)

class ItemSchema(BaseModel):
    name: str
    description: str
    price_per_day: float
    owner_id: int
    image_url: str = None
    category: str

class UserCreateSchema(BaseModel):
    email: EmailStr
    name: str
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
    allow_origins=["http://127.0.0.1:8000"],  # 실제 프론트엔드 도메인으로 변경
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(254), unique=True, index=True)
    name = Column(String(20))
    fireid = Column(String(28), unique=True, index=True)

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

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    db = AsyncSessionLocal()
    try:
        yield db
    finally:
        await db.close()

@app.get("/")
@app.get("/index")
async def home(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    # 로그인 상태 확인
    token = request.cookies.get("access_token")
    user_is_authenticated = False  # 기본값은 False로 설정

    if token:
        try:
            # JWT 디코딩
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email = payload.get("email")
            if email:
                # 토큰이 유효하고 사용자명이 있으면 인증된 것으로 각시
                user_is_authenticated = True
        except ExpiredSignatureError:
            # 토큰이 만료됨
            pass
        except JWTError:
            # 유효하지 않은 토큰
            pass

    # 클라이언트 컨념캐스트에 인증 상태 저장 (localStorage 활용 스크립트 추가)
    script = """
    <script>
        localStorage.setItem('user_is_authenticated', JSON.stringify(%s));
    </script>
    """ % json.dumps(user_is_authenticated)

    result = await db.execute(select(ItemModel).order_by(desc(ItemModel.item_date)))
    items_list = result.scalars().all()
    return templates.TemplateResponse("home.html", {
        'request': request,
        'items': items_list,
        'user_is_authenticated': user_is_authenticated,
        'script': script
    })

@app.get("/login")
async def login(request: Request):
    return templates.TemplateResponse("login.html", {'request': request})

@app.get("/signup")
async def signup(request: Request):
    return templates.TemplateResponse("signup_ver2.html", {'request': request})

@app.post("/login")
async def postlogin(
    response: Response,
    token: str = Form(...),  # 클라이언트에서 Firebase ID 토큰을 받음
    db: AsyncSession = Depends(get_db)
):
    try:
        # Firebase 토큰 검증
        decoded_token = auth.verify_id_token(token)
        fireid = decoded_token.get('uid')

        # 데이터베이스에서 사용자 찾기
        result = await db.execute(select(UserModel).where(UserModel.fireid == fireid))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found in database")

        # JWT 토큰 생성
        access_token_expires = td(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user.id), "email": user.email},
            expires_delta=access_token_expires
        )

        # 쿠키에 토큰 설정
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=False,
            max_age=int(access_token_expires.total_seconds()),
            path="/",
            samesite="lax",
            secure=False,
        )
        return response

    except firebase_admin.exceptions.FirebaseError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

@app.post("/signup")
async def postsignup(
    email: str = Form(...),
    name: str = Form(...),
    token: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    try:
        # Firebase ID 토큰 검증
        decoded_token = auth.verify_id_token(token)
        fireid = decoded_token.get('uid')
    except firebase_admin.exceptions.FirebaseError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    # 이메일 중복 확인
    existing_user = await db.execute(select(UserModel).where(UserModel.email == email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="이메일이 이미 사용 중입니다.")

    try:
        # 데이터베이스에 사용자 정보 저장
        db_user = UserModel(
            email=email,
            name=name,
            fireid=fireid  # Firebase UID
        )

        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
        return {"msg": "회원가입이 성공적으로 완료되었습니다."}

    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="데이터베이스에 이미 존재하는 이메일입니다.")

    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"서버 오류: {str(e)}")

@app.get("/mypage")
async def mypage(request: Request, db: AsyncSession = Depends(get_db)):
    # 쿠키에서 토큰 가져오기
    token = request.cookies.get("access_token")
    
    # 디버깅을 위한 로그
    print(f"Received token in mypage: {token[:20] if token else 'No token'}")
    
    if not token:
        print("No token found in cookies")
        return RedirectResponse(url="/login", status_code=307)

    try:
        # JWT 디코딩
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        
        if not email:
            print("No email in token payload")
            return RedirectResponse(url="/login", status_code=307)

        # 사용자 정보 조회
        result = await db.execute(
            select(UserModel).where(UserModel.email == email)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            print(f"No user found for email: {email}")
            return RedirectResponse(url="/login", status_code=307)

        return templates.TemplateResponse(
            "mypage.html", 
            {
                "request": request, 
                "user": user, 
                "user_is_authenticated": True
            }
        )

    except ExpiredSignatureError:
        print("Token has expired")
        return RedirectResponse(url="/login", status_code=307)
    except JWTError as e:
        print(f"JWT Error: {str(e)}")
        return RedirectResponse(url="/login", status_code=307)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return RedirectResponse(url="/login", status_code=307)
    
@app.get("/logout")
async def logout(request: Request, response: Response):
    # 새로운 응답 객체 생성
    response = RedirectResponse(url="/", status_code=302)
    
    # 쿠키 삭제
    response.delete_cookie(
        key="access_token",
        path="/",
        secure=False,
        httponly=False,
        samesite="lax"
    )
    
    # localStorage 클리언러를 위한 스크립트 트리거
    response.headers["HX-Trigger"] = json.dumps({
        "clearAuth": True,
    })
    
    print("Logout successful - Cookie deleted")
    return response

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
    item_date = dt.now(datetime.timezone.utc)

    if file.content_type not in ['image/jpeg', 'image/png']:
        raise HTTPException(status_code=400, detail="Invalid file type. Only JPEG and PNG files are allowed.")
    file_content = await file.read()

    if len(file_content) == 0:
        return {"msg": "File was empty, post created without file"}
    try:
        folder_path = f'/{owner_id}-{file.filename}'
        # 포더가 없으면 생성
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

    # 데이터베이스에 쿠리 실행
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

@app.get("/category/")
async def search(
    request: Request,
    target: str = Query(..., description="검색할 키워드"),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(ItemModel)
        .where(or_(ItemModel.category.like(f"%{target}%"), ItemModel.description.like(f"%{target}%")))
        .order_by(ItemModel.item_date)
        .limit(10)
    )
    items_list = result.scalars().all()
    if not items_list:
        raise HTTPException(status_code=404, detail="검색 결과가 없습니다.")

    return templates.TemplateResponse("home.html", {"request": request, "items": items_list})


#Chatting 코드
@app.post("/chat")
async def create_chat(
    request: Request,
    item_id: int = Form(...),
    buyer_id: int = Form(...),  # 구매자의 ID (로그인 사용자)
    db: AsyncSession = Depends(get_db)
):
    # 아이템 정보 가져오기
    result = await db.execute(select(ItemModel).where(ItemModel.id == item_id))
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    # 기존 채팅방이 있는지 확인
    existing_chat = await db.execute(
        select(ChatModel).where(
            ChatModel.user1_id == item.owner_id,
            ChatModel.user2_id == buyer_id,
            ChatModel.chatname == item.name
        )
    )
    if existing_chat.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Chat room already exists")

    # 채팅방 이름은 아이템 이름으로 설정
    chatname = item.name

    # 새로운 채팅방 생성
    new_chat = ChatModel(
        user1_id=item.owner_id,   # 판매자 (아이템 소유자)
        user2_id=buyer_id,        # 구매자 (현재 로그인한 사용자)
        chatname=chatname,
        message="",               # 최소 메시지는 빈값으로 초기화
        sent_at=dt.now()          # 현재 시간으로 설정
    )

    # 데이터베이스에 채팅방 정보 삽입
    try:
        db.add(new_chat)
        await db.commit()
        await db.refresh(new_chat)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create chat. Error: " + str(e))

    return {"chat_id": new_chat.id, "chatname": new_chat.chatname}

# 새로운 메시지 추가
@app.post("/chat/{chat_id}/messages")
async def add_message(chat_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    data = await request.json()
    user_id = data.get("user_id")
    message = data.get("message")

    if not user_id or not message:
        raise HTTPException(status_code=400, detail="User ID and message are required")

    # 데이터베이스의 sent_at 필드는 기본값이 current_timestamp()이라서 다른 설정할 필요 없음
    new_message = ChatModel(
        user1_id=user_id if user_id == 1 else None,  # 실제 사용자의 식별자로 조정 필요
        user2_id=user_id if user_id == 2 else None,
        chatname=f"chat_{chat_id}",
        message=message
    )
    db.add(new_message)
    await db.commit()
    return {"message": "Message added successfully"}

# 채팅방의 모든 메시지 가져오기
@app.get("/chat/{chat_id}/messages", response_model=List[dict])
async def get_messages(chat_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ChatModel).where(ChatModel.chatname == f"chat_{chat_id}").order_by(ChatModel.sent_at))
    messages = result.scalars().all()
    return [
        {
            "user_id": msg.user1_id if msg.user1_id else msg.user2_id,
            "message": msg.message,
            "sent_at": msg.sent_at  # timestamp 값 반환
        }
        for msg in messages
    ]

@app.get("/chat/{owner_id}")
async def chat_page(owner_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.id == owner_id))
    owner = result.scalar_one_or_none()
    if not owner:
        raise HTTPException(status_code=404, detail="Owner not found")

    return templates.TemplateResponse("chat.html", {"request": request, "owner": owner})

if __name__ == "__main__":  # 이 코드가 지금 접속 실행되었는가?
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)