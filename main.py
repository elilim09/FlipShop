from sqlite3 import IntegrityError
from fastapi import FastAPI, HTTPException, Depends, status, Request, Form, File, UploadFile, Response, Query, Cookie, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from datetime import timezone
from datetime import datetime as dt
from datetime import timedelta as td
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy import Column, Integer, String, Text, ForeignKey, select, and_, or_, desc, DateTime, func, UniqueConstraint, delete
from sqlalchemy.ext.declarative import declarative_base
from app.auth import create_access_token, verify_password, get_password_hash, decode_access_token, Token
from pydantic import BaseModel, validator, EmailStr
import dropbox
from dropbox.files import WriteMode
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError
import json
import os

import firebase_admin
from firebase_admin import credentials, auth
from google.cloud import vision
import googlemaps
from typing import List

Base = declarative_base()

ACCESS_TOKEN_EXPIRE_MINUTES = 43200  # 토큰 만료 시간 설정
SECRET_KEY = 'dkgkqrurgkrhtlvek'  # 실제 키로 대체하세요
ALGORITHM = "HS256"

DROP_API_KEY = "sl.B_8hJI2YyIbjrRocA9jZSXusEbKuGYCuQOeQ5ioSLlk6Mis_MpedE6O5lmlfMnB4hENFqXilBMfWQM7bVX2Ih1CJqVHaoh7YkghOj7VZjvMAnGMN89YQQLNFK8hKskVIzcxqiSb7f7gQaNJDNbq2CFA"  # 실제 키로 대체하세요
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
        orm_mode = True  # Pydantic V2 대응: 'from_attributes = True'으로 변경 가능

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
    bookmarks = Column(Text, nullable=True)
    trans = Column(Integer, default=0)
    cheats = Column(Integer, default=0)

    # 관계 설정
    items = relationship("ItemModel", back_populates="owner")

class ItemModel(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey('users.id'))
    owner_name = Column(String(50))  # 새로 추가된 컬럼
    name = Column(String(255))
    category = Column(String(255))
    description = Column(Text)
    price_per_day = Column(Integer)
    image_url = Column(String(255))
    available = Column(Integer)
    item_date = Column(DateTime)

    # 관계 설정 (optional)
    owner = relationship("UserModel", back_populates="items")


class ChatModel(Base):
    __tablename__ = "chat"

    id = Column(Integer, primary_key=True, index=True)
    item_id = Column(Integer, ForeignKey('items.id'))  # 이 컬럼이 필요함
    user1_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user2_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    chatname = Column(String(100), nullable=True)
    message = Column(Text, nullable=False)
    sent_at = Column(DateTime, default=dt.now(timezone.utc), nullable=True)

    # 기존 관계 설정
    sender = relationship("UserModel", foreign_keys=[user1_id])
    receiver = relationship("UserModel", foreign_keys=[user2_id])
    item = relationship("ItemModel")  # 아이템과의 관계 설정 (optional)

class EvaluationRequest(BaseModel):
    status: str  # 'success' 또는 'fraud'


@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    async with AsyncSessionLocal() as db:
        yield db

async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> UserModel:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="User not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=401, detail="User not authenticated")
        result = await db.execute(select(UserModel).where(UserModel.email == email))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=401, detail="User not authenticated")
        return user
    except (ExpiredSignatureError, JWTError):
        raise HTTPException(status_code=401, detail="User not authenticated")

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
                # 토큰이 유효하고 사용자명이 있으면 인증된 것으로 간주
                user_is_authenticated = True
        except ExpiredSignatureError:
            # 토큰이 만료됨
            pass
        except JWTError:
            # 유효하지 않은 토큰
            pass

    # 클라이언트 측 localStorage에 인증 상태 저장 (스크립트 추가)
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
            httponly=True,  # 보안을 위해 httponly=True로 설정 권장
            max_age=int(access_token_expires.total_seconds()),
            path="/",
            samesite="lax",
            secure=False,  # 실제 배포 시 HTTPS 환경에서는 True로 설정
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
        secure=False,  # 실제 배포 시 HTTPS 환경에서는 True로 설정
        httponly=True,  # 보안을 위해 httponly=True로 설정 권장
        samesite="lax"
    )
    
    # localStorage 클라이언트를 위한 스크립트 트리거
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
async def create_item_page(
    request: Request, 
    db: AsyncSession = Depends(get_db)
):
    try:
        user = await get_current_user(request, db)
    except HTTPException:
        return RedirectResponse(url="/login", status_code=307)
    
    return templates.TemplateResponse("create_item.html", {
        'request': request, 
        'user_id': user.id  # 템플릿에 사용자 ID 전달 (필요시 삭제 가능)
    })

@app.post("/create_item")
async def create_item(
    name: str = Form(...),
    category: str = Form(...),
    description: str = Form(...),
    price_per_day: float = Form(...),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    item_date = dt.now(timezone.utc)  # 현재 시간을 UTC로 설정

    # 파일 타입 확인
    if file.content_type not in ['image/jpeg', 'image/png']:
        raise HTTPException(status_code=400, detail="Invalid file type. Only JPEG and PNG files are allowed.")

    # 파일 내용 읽기
    file_content = await file.read()
    if len(file_content) == 0:
        raise HTTPException(status_code=400, detail="File is empty.")

    try:
        # Dropbox에 파일 업로드 처리
        folder_path = f'/{current_user.id}-{file.filename}'
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
        owner_id=current_user.id,
        owner_name=current_user.name,  # 로그인된 사용자의 이름 추가
        name=name,
        category=category,
        description=description,
        price_per_day=price_per_day,
        image_url=image_url,
        available=1,
        item_date=item_date
    )

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
        "owner_id": current_user.id,
        "owner_name": current_user.name,  # 반환값에도 추가
        "image_url": image_url,
        "available": True
    }

@app.get("/items/{item_id}")    
async def item_detail(
    item_id: int, 
    request: Request, 
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(ItemModel).where(ItemModel.id == item_id))
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    
    # 현재 사용자 가져오기 (인증되지 않은 경우 None)
    try:
        user = await get_current_user(request, db)
    except HTTPException:
        user = None  # 인증되지 않은 사용자
    
    is_bookmarked = False
    user_id = None
    if user and user.bookmarks:
        try:
            bookmarks = [int(id) for id in json.loads(user.bookmarks)]
            is_bookmarked = item_id in bookmarks
            user_id = user.id  # 현재 사용자 ID
        except json.JSONDecodeError:
            bookmarks = []

    # 아이템 소유자 정보 가져오기 (owner_name 포함)
    result = await db.execute(select(UserModel).where(UserModel.id == item.owner_id))
    owner = result.scalar_one_or_none()
    owner_name = owner.name if owner else "Unknown"

    return templates.TemplateResponse(
        "item_detail.html", 
        {
            "request": request, 
            "item": item,
            "is_bookmarked": is_bookmarked,
            "user_id": user_id,  # 현재 사용자 ID
            "owner_name": owner_name  # 아이템 소유자 이름
        }
    )

@app.post("/bookmark_item")
async def bookmark_item(
    request: Request,
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    data = await request.json()
    item_id = data.get('item_id')
    if not item_id:
        raise HTTPException(status_code=400, detail="Item ID is required")
    item_id = int(item_id)

    # 북마크 리스트 가져오기
    bookmarks = []
    if user.bookmarks:
        try:
            bookmarks = [int(id) for id in json.loads(user.bookmarks)]
        except json.JSONDecodeError:
            bookmarks = []

    if item_id in bookmarks:
        # 북마크 제거
        bookmarks.remove(item_id)
        is_bookmarked = False
    else:
        # 북마크 추가
        bookmarks.append(item_id)
        is_bookmarked = True

    user.bookmarks = json.dumps(bookmarks)
    try:
        db.add(user)
        await db.commit()
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update bookmarks")

    return {'is_bookmarked': is_bookmarked}

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
async def search_category(
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


# Chatting 코드
# 필요한 임포트 추가
from sqlalchemy import and_, or_

# 수정된 create_chat 함수
@app.post("/chat")
async def create_chat(
    item_id: int = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    # 아이템 정보 가져오기
    result = await db.execute(select(ItemModel).where(ItemModel.id == item_id))
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    # 아이템 소유자 (판매자) 정보 가져오기
    seller = await db.get(UserModel, item.owner_id)
    if not seller:
        raise HTTPException(status_code=404, detail="Seller not found")

    # 사용자 ID 정렬하여 chatname 생성
    user_ids = sorted([current_user.id, seller.id])
    chatname = f"{item.id}_{user_ids[0]}_{user_ids[1]}"

    # 이미 채팅방이 존재하는지 확인
    existing_chat = await db.execute(
        select(ChatModel).where(
            ChatModel.item_id == item.id,
            ChatModel.chatname == chatname,
            or_(
                and_(ChatModel.user1_id == seller.id, ChatModel.user2_id == current_user.id),
                and_(ChatModel.user1_id == current_user.id, ChatModel.user2_id == seller.id)
            )
        )
    )
    existing_chat = existing_chat.first()
    if existing_chat:
        # 채팅방이 이미 존재하므로 해당 채팅방의 ID를 반환
        return {"chat_id": existing_chat.id, "chatname": existing_chat.chatname}

    # 새로운 채팅방 생성
    new_chat = ChatModel(
        item_id=item.id,
        user1_id=user_ids[0],
        user2_id=user_ids[1],
        chatname=chatname,
        message="",  # 첫 메시지는 빈 값
        sent_at=dt.now(timezone.utc)
    )

    try:
        db.add(new_chat)
        await db.commit()
        await db.refresh(new_chat)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create chat room. Error: " + str(e))

    return {"chat_id": new_chat.id, "chatname": new_chat.chatname}

# 새로운 메시지 추가
@app.post("/chat/{chat_id}/messages")
async def send_message(
    chat_id: int,
    message: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    # 채팅방 정보 가져오기
    result = await db.execute(select(ChatModel).where(ChatModel.id == chat_id))
    chat = result.scalar_one_or_none()
    if not chat:
        raise HTTPException(status_code=404, detail="Chat room not found")

    # 현재 사용자가 채팅방의 참여자인지 확인
    if current_user.id not in [chat.user1_id, chat.user2_id]:
        raise HTTPException(status_code=403, detail="You are not a participant of this chat room")

    # 메시지 생성
    new_message = ChatModel(
        item_id=chat.item_id,  # item_id 추가
        user1_id=current_user.id,
        user2_id=chat.user2_id if current_user.id == chat.user1_id else chat.user1_id,
        chatname=chat.chatname,
        message=message,
        sent_at=dt.now(timezone.utc)
    )

    try:
        db.add(new_message)
        await db.commit()
        await db.refresh(new_message)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to send message. Error: " + str(e))

    return {"message": "Message sent successfully"}

@app.get("/chat/{chat_id}/messages", response_model=List[dict])
async def get_messages(
    chat_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    # 채팅방 정보 가져오기
    result = await db.execute(select(ChatModel).where(ChatModel.id == chat_id))
    chat = result.scalar_one_or_none()
    if not chat:
        raise HTTPException(status_code=404, detail="Chat room not found")

    # 현재 사용자가 채팅방의 참여자인지 확인
    if current_user.id not in [chat.user1_id, chat.user2_id]:
        raise HTTPException(status_code=403, detail="You are not a participant of this chat room")

    # 채팅방의 모든 메시지 조회
    result = await db.execute(
        select(ChatModel).where(
            ChatModel.chatname == chat.chatname,
            ChatModel.message != ""  # 빈 메시지는 제외
        ).order_by(ChatModel.sent_at)
    )
    messages = result.scalars().all()

    return [
        {
            "sender_id": msg.user1_id,
            "receiver_id": msg.user2_id,
            "message": msg.message,
            "sent_at": msg.sent_at.strftime("%Y-%m-%d %H:%M:%S")
        }
        for msg in messages
    ]

#사용자의 채팅방 목록조회하기
@app.get("/chats", response_model=List[dict])
async def get_user_chats(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    # 사용자가 참여하고 있는 모든 채팅방 조회
    result = await db.execute(
        select(ChatModel).where(
            or_(
                ChatModel.user1_id == current_user.id,
                ChatModel.user2_id == current_user.id
            )
        ).group_by(ChatModel.chatname)
    )
    chats = result.scalars().all()

    # 각 채팅방의 최신 메시지 조회
    chat_list = []
    for chat in chats:
        latest_message = await db.execute(
            select(ChatModel).where(
                ChatModel.chatname == chat.chatname,
                ChatModel.message != ""
            ).order_by(ChatModel.sent_at.desc()).limit(1)
        )
        latest_msg = latest_message.scalar_one_or_none()
        chat_list.append({
            "chat_id": chat.id,
            "chatname": chat.chatname,
            "participant1_id": chat.user1_id,
            "participant2_id": chat.user2_id,
            "latest_message": latest_msg.message if latest_msg else "",
            "sent_at": latest_msg.sent_at.strftime("%Y-%m-%d %H:%M:%S") if latest_msg else chat.sent_at.strftime("%Y-%m-%d %H:%M:%S")
        })

    # 템플릿 렌더링
    return templates.TemplateResponse("chat_list.html", {
        "request": request,
        "chats": chat_list,
        "user_id": current_user.id
    })


#채팅방페이지
@app.get("/chat/{chat_id}")
async def chat_page(chat_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    # 현재 로그인된 사용자 정보 가져오기
    current_user = await get_current_user(request, db)

    # 채팅방 정보 가져오기
    result = await db.execute(select(ChatModel).where(ChatModel.id == chat_id))
    chat = result.scalar_one_or_none()
    if not chat:
        raise HTTPException(status_code=404, detail="Chat room not found")

    # 현재 사용자가 채팅방의 참여자인지 확인
    if current_user.id not in [chat.user1_id, chat.user2_id]:
        raise HTTPException(status_code=403, detail="You are not a participant of this chat room")

    return templates.TemplateResponse("chat.html", {"request": request, "chat_id": chat_id, "user_id": current_user.id})

@app.post("/chat/{chat_id}/evaluate")
async def evaluate_chat(
    chat_id: int,
    evaluation: EvaluationRequest,  # Pydantic 모델로 요청 검증
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    status = evaluation.status

    # 채팅방 정보 가져오기
    result = await db.execute(select(ChatModel).where(ChatModel.id == chat_id))
    chat = result.scalar_one_or_none()
    if not chat:
        raise HTTPException(status_code=404, detail="Chat room not found")

    # 채팅 참여자 확인
    other_user_id = chat.user2_id if chat.user1_id == current_user.id else chat.user1_id

    # 상대방 정보 가져오기
    result = await db.execute(select(UserModel).where(UserModel.id == other_user_id))
    other_user = result.scalar_one_or_none()
    if not other_user:
        raise HTTPException(status_code=404, detail="Other user not found")

    # 거래 평가 반영 (cheats 컬럼 증가 등)
    if status == 'fraud':
        other_user.cheats += 1
    other_user.trans += 1
    current_user.trans += 1

    # 평가 메시지 전송
    evaluation_message = ChatModel(
        item_id=chat.item_id,
        user1_id=current_user.id,
        user2_id=other_user_id,
        chatname=chat.chatname,
        message=f"{current_user.name}님이 거래를 {'성공' if status == 'success' else '사기'}로 평가하였습니다.",
        sent_at=dt.now(timezone.utc)
    )
    db.add(evaluation_message)

    # 평가 완료 여부 확인 및 채팅방 삭제
    if current_user.trans > 0 and other_user.trans > 0:  # 실제 평가 완료 조건에 맞게 수정
        await db.execute(delete(ChatModel).where(ChatModel.id == chat_id))
        await db.commit()
        return {"msg": "채팅방이 평가 완료 후 삭제되었습니다."}

    await db.commit()
    return {"msg": "평가가 완료되었습니다."}


if __name__ == "__main__":  # 이 코드가 지금 접속 실행되었는가?
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)