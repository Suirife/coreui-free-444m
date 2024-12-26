from sqlalchemy.orm import Session
from sqlalchemy import extract
import models, schemas
from passlib.context import CryptContext
import datetime
from datetime import datetime, timedelta, timezone

def get_password_hash(password):
    return pwd_context.hash(password)

def create_wallet(db: Session, wallet: schemas.WalletCreate, user:models.User):
    db_wallet = models.Wallet(
        user_id=user.id, 
        currency=wallet.currency,
        )
    db.add(db_wallet)
    db.commit()
    db.refresh(db_wallet)
    return db_wallet

def registration(db: Session, user: schemas.UserCreate):
    _hashed_password = get_password_hash(user.password)
    db_user = models.User(
        email=user.email, 
        username=user.username, 
        hashed_password=_hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    create_wallet(db, schemas.WalletCreate(currency='USD'), db_user)
    return db_user

def incomes_by_wallet_id_and_month(db: Session, wallet_id: int, month: int, user:models.User):
    return db.query(models.Income.category, sum(models.Income.amount).label('amount')).filter(
        models.Wallet.user_id == user.id,
        models.Income.wallet_id == wallet_id,
        extract('month', models.Income.date) == month
        ).group_by(models.Income.category).all()

def expenses_by_wallet_id_and_month(db: Session, wallet_id: int, month: int, user:models.User):
    return db.query(models.Expense.category, sum(models.Income.amount).label('amount')).filter(
        models.Wallet.user_id == user.id,
        models.Expense.wallet_id == wallet_id,
        extract('month', models.Expense.date) == month
        ).group_by(models.Expense.category).all()

def incomes_by_wallet_id_and_year(db: Session, wallet_id: int, year: int, user:models.User):
    return db.query(extract('year',models.Income.date).label('year'), sum(models.Income.amount).label('amount')).filter(
        models.Wallet.user_id == user.id,
        models.Income.wallet_id == wallet_id,
        extract('year',models.Income.date) == year
        ).group_by(extract('year',models.Income.date)).all()

def expenses_by_wallet_id_and_year(db: Session, wallet_id: int, year: int, user:models.User): 
    return db.query(extract('year',models.Expense.date).label('year'), sum(models.Expense.amount).label('amount')).filter(
        models.Wallet.user_id == user.id,
        models.Expense.wallet_id == wallet_id,
        extract('year', models.Expense.date) == year
        ).group_by(extract('year',models.Expense.date)).all()

#def incomes_by_wallet_id_and_category(db: Session, wallet_id: int, category: str):
   # return db.query(models.Income).filter(models.Income.wallet_id == wallet_id, models.Income.category == category).all()

#def expenses_by_wallet_id_and_category(db: Session, wallet_id: int, category: str):
    #return db.query(models.Expense).filter(models.Expense.wallet_id == wallet_id, models.Expense.category == category).all()

def get_user_by_id( db: Session, user_id: int)-> models.User:
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_user_by_email( db: Session, email: str)-> models.User:
    return db.query(models.User).filter(models.User.email == email).first()

def get_user_by_username( db: Session, username: str)-> models.User:
    return db.query(models.User).filter(models.User.username == username).first()

def get_active_users(db: Session):
    return db.query(models.User).filter(models.User.is_active == True).all()

def get_wallet_by_user(db: Session, user_id: int):
    return db.query(models.Wallet).filter(models.Wallet.user_id == user_id).first()

def get_wallet_by_id(db: Session, wallet_id: int):
    return db.query(models.Wallet).filter(models.Wallet.id == wallet_id).first()

def get_wallet_by_user_id(db: Session, user_id: int):
    return db.query(models.Wallet).filter(models.Wallet.user_id == user_id).first()



pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def login_attempts(db: Session, db_user: models.User):
    if db_user.failed_logins < 5:
        db_user.failed_logins += 1
        db.commit()
    else:
        db_user.is_active = False
        db_user.locked_until = datetime.now() + timedelta(minutes=5)
        db.commit()

def user_unlocked(db: Session, user: schemas.UserLogin):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user.locked_until and db_user.locked_until < datetime.now():
        db_user.is_active = True
        db_user.failed_logins = 0
        db_user.locked_until = None
        db.commit()
    
def get_active_user(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username, models.User.is_active == True).first()

def reset_password(db: Session, db_user: models.User, password: str):
    db_user.hashed_password = get_password_hash(password)
    db.commit()

def get_user_by_token(db: Session, token: str):
    return db.query(models.User).filter(models.User.token == token, models.User.is_active == True).first()

def update_token(db: Session, db_user: models.User, token: str):
    db_user.access_token = token
    db.commit()

def get_user_by_restore_token(db: Session, token: str):
    return db.query(models.User).filter(models.User.restore_token == token).first()

def update_restore_token(db: Session, db_user: models.User, restore_token: str):
    db_user.restore_token = restore_token
    db.commit()

def get_all_users(db: Session):
    return db.query(models.User).all()