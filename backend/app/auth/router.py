from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from typing import List, Any
from datetime import timedelta
from pydantic import BaseModel

from app.auth.security import verify_password, get_password_hash, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from app.auth.deps import get_current_user, require_admin
from app.database import user_repository

router = APIRouter()
VALID_ROLES = {"Admin", "Analyst", "Viewer"}

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: str = None
    role: str = "Viewer"
    customer_id: int

class UserUpdate(BaseModel):
    username: str = None
    email: str = None
    full_name: str = None
    role: str = None
    password: str = None
    is_active: bool = None
    customer_id: int = None

class Token(BaseModel):
    access_token: str
    token_type: str


@router.post("/auth/login", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = user_repository.get_user_by_email(form_data.username) or user_repository.get_user_by_username(form_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user["is_active"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user["id"]), "role": user["role"], "customer_id": user["customer_id"]}, 
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/auth/logout")
def logout():
    # JWTs are stateless, logout is typically handled client-side by deleting the token
    return {"message": "Successfully logged out"}


@router.get("/auth/me")
def read_users_me(current_user: dict = Depends(get_current_user)):
    # exclude hashed_password
    safe_user = {k: v for k, v in current_user.items() if k != "hashed_password"}
    return safe_user


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/auth/change-password")
def change_password(request: ChangePasswordRequest, current_user: dict = Depends(require_admin)):
    if not verify_password(request.current_password, current_user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    if request.current_password == request.new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be different from the current password")

    hashed_password = get_password_hash(request.new_password)
    user_repository.update_user(current_user["id"], {"hashed_password": hashed_password})
    return {"message": "Password updated successfully"}


# User Management endpoints
@router.get("/users")
def get_users(current_user: dict = Depends(require_admin)):
    # Admins can see users for their customer
    # If superadmin, could see all, but here we restrict to same customer_id unless you want a global admin.
    # The prompt implies Admin manages users. We'll show all users for their customer.
    users = user_repository.list_users(customer_id=current_user["customer_id"])
    return users


@router.post("/users")
def create_user(user: UserCreate, current_user: dict = Depends(require_admin)):
    # Only allow creating users for the same customer
    if user.customer_id != current_user["customer_id"]:
        raise HTTPException(status_code=403, detail="Cannot create user for different customer")
    if user.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")
        
    existing = user_repository.get_user_by_email(user.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
        
    hashed_password = get_password_hash(user.password)
    new_user = user_repository.create_user(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        full_name=user.full_name,
        role=user.role,
        customer_id=user.customer_id
    )
    return new_user


@router.put("/users/{user_id}")
def update_user(user_id: int, user_update: UserUpdate, current_user: dict = Depends(require_admin)):
    existing = user_repository.get_user_by_id(user_id)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
        
    if existing["customer_id"] != current_user["customer_id"]:
        raise HTTPException(status_code=403, detail="Not authorized to edit this user")

    update_data = user_update.dict(exclude_unset=True)
    if "customer_id" in update_data and update_data["customer_id"] != current_user["customer_id"]:
        raise HTTPException(status_code=403, detail="Cannot move user to a different customer")
    if "role" in update_data and update_data["role"] not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")
    if "password" in update_data:
        update_data["hashed_password"] = get_password_hash(update_data.pop("password"))
        
    updated_user = user_repository.update_user(user_id, update_data)
    return updated_user


@router.delete("/users/{user_id}")
def delete_user(user_id: int, current_user: dict = Depends(require_admin)):
    existing = user_repository.get_user_by_id(user_id)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
        
    if existing["customer_id"] != current_user["customer_id"]:
        raise HTTPException(status_code=403, detail="Not authorized to delete this user")
        
    success = user_repository.delete_user(user_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete user")
    return {"message": "User deleted successfully"}
