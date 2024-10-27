from sqlalchemy import Column, Integer, String, ForeignKey, Float, DateTime, Enum, Text, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

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
    name="category_enum"
)

LocalCategoryEnum = Enum(
    "서울","부산","대구","인천","광주","대전","울산","세종","수원","성남","고양","용인","부천","안산","안양","남양주","화성","평택","의정부","시흥","파주","김포","광명","광주 (경기도)","군포","오산","이천","안성","의왕","하남","여주","동두천","과천","구리","양주","춘천","원주","강릉","동해","태백","속초","삼척","청주","충주","제천","천안","공주","보령","아산","서산","논산","계룡","당진","전주","군산","익산","정읍","남원","김제","목포","여수","순천","나주","광양","포항","경주","김천","안동","구미","영주","영천","상주","문경","경산","거창","창원","진주","통영","사천","김해","밀양","거제","양산","제주",
    name="local_category_enum"
)

class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True, nullable=False)
    password = Column(String(255), nullable=False)

class ItemModel(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    name = Column(String(255), nullable=False)
    category = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    price_per_day = Column(Float, nullable=False)
    image_url = Column(String(255))
    available = Column(Integer, default=1)
    item_date = Column(DateTime, nullable=False)
    bookmark = Column(Integer, default=0)  # 기본값 추가

class RentalModel(Base):
    __tablename__ = "rentals"

    id = Column(Integer, primary_key=True)
    item_id = Column(Integer, ForeignKey("items.id"))
    borrower_id = Column(Integer, ForeignKey("users.id"))
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    total_price = Column(Float)

class ChatModel(Base):
    __tablename__ = "chat"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user1_id = Column(Integer, nullable=False)
    user2_id = Column(Integer, nullable=False)
    chatname = Column(String(100))
    message = Column(String(255), nullable=False)
    sent_at = Column(DateTime, default=func.now())