from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from typing import List, Optional
from datetime import datetime, timedelta
import jwt
import pymongo
from bson import ObjectId
from fastapi.middleware.cors import CORSMiddleware

# MongoDB connection
client = pymongo.MongoClient("mongodb+srv://myAtlasDBUser:Sai123@myatlasclusteredu.qifwasp.mongodb.net/loanmanagment?retryWrites=true&w=majority")
db = client.loan_app
users_collection = db.users
loans_collection = db.loans

# FastAPI instance
app = FastAPI()

# Security setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")
SECRET_KEY = "your_jwt_secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic Models
class User(BaseModel):
    name: str
    email: str
    password: str
    role: str = "user"  

class LoanApplication(BaseModel):
    loan_amount: float
    loan_purpose: str

class LoanStatus(BaseModel):
    loan_id: str
    status: str

class Loan(BaseModel):
    id: str
    user_id: str
    loan_amount: float
    loan_purpose: str
    status: str = "pending"
    applied_at: datetime = datetime.utcnow()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)

# Helper functions
def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_from_db(email: str):
    return users_collection.find_one({"email": email})

def get_user_by_id(user_id: str):
    return users_collection.find_one({"_id": ObjectId(user_id)})

def get_loan_by_user(user_id: str):
    return loans_collection.find_one({"user_id": user_id, "status": "pending"})

# Routes

@app.get("/")
async def read_root():
    return {"message": "Welcome to the Loan Application API"}
@app.post("/users/register")
async def register_user(user: User):
    if get_user_from_db(user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = {"name": user.name, "email": user.email, "password_hash": hashed_password, "role": user.role}
    result = users_collection.insert_one(new_user)
    return {"id": str(result.inserted_id), "name": user.name, "email": user.email}

@app.post("/users/login")
async def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_from_db(form_data.username)
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user["email"]}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/loans/apply")
async def apply_loan(loan: LoanApplication, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if user_email is None:
            raise credentials_exception
        user = get_user_from_db(user_email)
        if user is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    loan_data = {
        "user_id": str(user["_id"]),
        "loan_amount": loan.loan_amount,
        "loan_purpose": loan.loan_purpose,
        "status": "pending",
        "applied_at": datetime.utcnow()
    }
    result = loans_collection.insert_one(loan_data)
    return {"loan_id": str(result.inserted_id), "status": "pending"}

@app.get("/loans/status")
async def loan_status(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if user_email is None:
            raise credentials_exception
        user = get_user_from_db(user_email)
        if user is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    loan = get_loan_by_user(str(user["_id"]))
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")

    return Loan(id=str(loan["_id"]), user_id=str(loan["user_id"]), loan_amount=loan["loan_amount"], 
                loan_purpose=loan["loan_purpose"], status=loan["status"], applied_at=loan["applied_at"])

@app.post("/loans/approve")
async def approve_loan(loan: LoanStatus, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if user_email is None:
            raise credentials_exception
        user = get_user_from_db(user_email)
        if user is None or user["role"] != "admin":
            raise HTTPException(status_code=403, detail="Not authorized")
    except jwt.PyJWTError:
        raise credentials_exception

    loan_data = loans_collection.find_one({"_id": ObjectId(loan.loan_id)})
    if not loan_data:
        raise HTTPException(status_code=404, detail="Loan not found")

    loan_data["status"] = loan.status
    loans_collection.update_one({"_id": ObjectId(loan.loan_id)}, {"$set": {"status": loan.status}})
    return {"loan_id": loan.loan_id, "status": loan.status}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
