# app/auth.py
from datetime import timedelta as td
from datetime import datetime as dt
import datetime
from typing import Optional
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError
from passlib.context import CryptContext
from pydantic import BaseModel
import os

# 환경 변수로부터 비밀 키와 알고리즘을 가져옵니다.
SECRET_KEY = 'dkgkqrurgkrhtlvek' #os.environ.get('SECRET_KEY', 'dkgkqrurgkrhtlvek')  # 실제 비밀 키로 대체하세요.
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 43200  # 30일

# 비밀번호 해싱을 위한 설정 (단일 pwd_context 인스턴스)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic 모델 정의
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str

class UserInDB(User):
    hashed_password: str

# 비밀번호 검증 함수
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# 비밀번호 해싱 함수
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# 액세스 토큰 생성 함수
def create_access_token(data: dict, expires_delta: Optional[td] = None) -> str:
    """
    주어진 데이터를 바탕으로 JWT 액세스 토큰을 생성합니다.

    :param data: JWT에 포함될 데이터 (딕셔너리)
    :param expires_delta: 토큰의 만료 기간 (timedelta)
    :return: 생성된 JWT 문자열
    """
    to_encode = data.copy()
    if expires_delta:
        expire = dt.now(datetime.timezone.utc) + expires_delta
    else:
        expire = dt.now(datetime.timezone.utc) + td(minutes=15)  # 기본 만료 시간 15분
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 액세스 토큰 디코딩 함수
def decode_access_token(token: str) -> TokenData:
    """
    주어진 JWT를 디코딩하고, 토큰 데이터를 반환합니다.

    :param token: JWT 문자열
    :return: TokenData 객체
    :raises JWTError: 토큰 검증 실패 시 발생
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise JWTError("No username in token")
        return TokenData(username=username)
    except JWTError:
        raise JWTError("Could not validate token")