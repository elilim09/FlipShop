# app/models.py
from sqlalchemy import Table, Column, Integer, String, MetaData, ForeignKey, Boolean, Float, DateTime, Enum
from app.database import metadata
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Enum
Base = declarative_base()


CategoryEnum = Enum(
    "디지털기기",
    "가구/인테리어",
    "가전",
    "음악",
    "의류",
    "스포츠",
    "게임",
    "책",
    "기타",
    name="category_enum"  # enum 이름
)

# Local Category Enum
LocalCategoryEnum = Enum(
    "서울",
    "부산",
    "대구",
    "인천",
    "광주",
    "대전",
    "울산",
    "세종",
    "수원",
    "성남",
    "고양",
    "용인",
    "부천",
    "안산",
    "안양",
    "남양주",
    "화성",
    "평택",
    "의정부",
    "시흥",
    "파주",
    "김포",
    "광명",
    "광주 (경기도)",
    "군포",
    "오산",
    "이천",
    "안성",
    "의왕",
    "하남",
    "여주",
    "동두천",
    "과천",
    "구리",
    "양주",
    "춘천",
    "원주",
    "강릉",
    "동해",
    "태백",
    "속초",
    "삼척",
    "청주",
    "충주",
    "제천",
    "천안",
    "공주",
    "보령",
    "아산",
    "서산",
    "논산",
    "계룡",
    "당진",
    "전주",
    "군산",
    "익산",
    "정읍",
    "남원",
    "김제",
    "목포",
    "여수",
    "순천",
    "나주",
    "광양",
    "포항",
    "경주",
    "김천",
    "안동",
    "구미",
    "영주",
    "영천",
    "상주",
    "문경",
    "경산",
    "거창",
    "창원",
    "진주",
    "통영",
    "사천",
    "김해",
    "밀양",
    "거제",
    "양산",
    "제주",
    name="local_category_enum"  # enum 이름
)

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, unique=True, index=True),
    Column("password", String),
)
items = Table(
    "items",
    Base.metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("name", String, index=True),
    Column("description", String),
    Column("owner_id", Integer, ForeignKey("users.id")),
    Column("price_per_day", Float),
    Column("available", Boolean, default=True),
    Column("image_url", String),
    Column("category", CategoryEnum),
    Column("local_category", LocalCategoryEnum),
    Column("item_date", DateTime)
)


rentals = Table(
    "rentals",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("item_id", Integer, ForeignKey("items.id")),
    Column("borrower_id", Integer, ForeignKey("users.id")),
    Column("start_date", DateTime),
    Column("end_date", DateTime),
    Column("total_price", Float),
)