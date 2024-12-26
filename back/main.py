from fastapi import FastAPI, Depends, HTTPException, status
from database import SessionLocal, engine
import models, schemas, crud
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import jwt
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
import os
from dotenv import load_dotenv
from typing import Optional
from fastapi.security import (
    APIKeyHeader,
)

load_dotenv()

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

SECRET_KEY = "02b11ec3ea564e5372ca7be5bee87afd6bcb181974d8f5d058f1c18abc042848"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

api_key_header = APIKeyHeader(name="Token", auto_error=False)

async def get_user_by_token(token: Annotated[str, Depends(oauth2_scheme)]):
    db = next(get_db())
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = crud.get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user



async def user_auth(api_key: Optional[APIKeyHeader] = Depends(api_key_header)):
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token not found",
        )

    user = await get_user_by_token(api_key)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    return user


def verify_token(token: str, SECRET_KEY):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    

# Отредактировано
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Отредактировано
def authenticate_user(db: Session, username: str, password: str):
    user = crud.get_user_by_username(db, username)
    if not user:
        return None
    if not crud.verify_password(password, user.hashed_password):
        crud.login_attempts(db, user)
        return None
    return user

# Отредактировано
@app.post("/login", response_model=schemas.Token)
def login(user1: schemas.UserLogin, db: Session = Depends(get_db)):
    crud.user_unlocked(db, user1)
    user = authenticate_user(db, user1.username, user1.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
            )
    current_user = crud.get_active_user(db, user.username)
    if not current_user:
        raise HTTPException(status_code=404, detail="User is not active")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token1 = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    crud.update_token(db, user, access_token1)
    return schemas.Token(access_token=access_token1, token_type="bearer")
     
# Отредактировано
@app.post("/registration")
def registration(user: schemas.UserCreate, db: Session = Depends(get_db)):
    if not user.username:
        raise HTTPException(status_code=400, detail="Username is required")
    if not user.email:
        raise HTTPException(status_code=400, detail="Email is required")
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    registered_user = crud.registration(db=db, user=user)
    return {"User successfully registered!"}

# Отредактировано
@app.post("/wallet", response_model=schemas.WalletCreate)
def create_wallet(wallet: schemas.WalletCreate, db: Session = Depends(get_db)):
    user = Depends(user_auth)
    return crud.create_wallet(db=db, wallet=wallet, user=user)

@app.get("/users/me/", response_model=schemas.User)
async def read_users_me(current_user: Annotated[schemas.User, Depends(user_auth)]):
    return current_user


@app.post("/forgot_password")
async def forgot_password(email: str, db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, email=email)
    if not user:
        raise HTTPException(status_code=404, detail="Incorrect email address")
    restore_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    restore_token = create_access_token(
        data={"sub": user.username}, expires_delta=restore_token_expires
    )
    crud.update_restore_token(db, user, restore_token) 
    return {"message": "Email sent successfully"}

@app.get("/get_all_users")
async def get_all_users(db: Session = Depends(get_db)):
    return crud.get_all_users(db)

@app.post("/reset_password")
async def reset_password(UserResetPassword: schemas.UserResetPassword, db: Session = Depends(get_db)):
    user = crud.get_user_by_restore_token(db, UserResetPassword.restore_token)
    crud.reset_password(db, user, UserResetPassword.reset_password)
    return {"message": "Password reset successfully"}

@app.get("/incomes_by_month", response_model=schemas.IncomesByMonth)
async def get_incomes_month(wallet_id: schemas.IncomesByMonth, month: schemas.IncomesByMonth, db: Session = Depends(get_db)):
    user = Depends(user_auth)
    return crud.incomes_by_wallet_id_and_month(db, wallet_id, month, user)

@app.get("/expenses_by_month", response_model=schemas.ExpensesByMonth)
async def get_expenses_month(wallet_id: schemas.ExpensesByMonth, month: schemas.ExpensesByMonth, db: Session = Depends(get_db)):
    user = Depends(user_auth)
    return crud.expenses_by_wallet_id_and_month(db, wallet_id, month, user)

@app.get("/incomes_by_year", response_model=schemas.IncomesByYear)
async def get_incomes_year(wallet_id: schemas.IncomesByYear, year: schemas.IncomesByYear, db: Session = Depends(get_db)):
    user = Depends(user_auth)
    return crud.incomes_by_wallet_id_and_year(db, wallet_id, year, user)

@app.get("/expenses_by_year", response_model=schemas.ExpensesByYear)
async def get_expenses_year(wallet_id: schemas.ExpensesByYear, year: schemas.ExpensesByYear, db: Session = Depends(get_db)):
    user = Depends(user_auth)
    return crud.expenses_by_wallet_id_and_year(db, wallet_id, year, user)

#@app.get("/incomes_by_category", response_model=schemas.IncomesByCategory)
#async def get_incomes_category(wallet_id: schemas.IncomesByCategory, category: schemas.IncomesByCategory, db: Session = Depends(get_db)):
   # user = Depends(get_current_user)
   # return crud.incomes_by_wallet_id_and_category(db, wallet_id, category, user)

#@app.get("/expenses_by_category", response_model=schemas.ExpensesByCategory)
#async def get_expenses_category(wallet_id: schemas.ExpensesByCategory, category: schemas.ExpensesByCategory, db: Session = Depends(get_db)):
   # user = Depends(get_current_user)
    #return crud.expenses_by_wallet_id_and_category(db, wallet_id, category, user)


