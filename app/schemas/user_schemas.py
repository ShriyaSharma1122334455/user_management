from builtins import ValueError, any, bool, str
from pydantic import BaseModel, EmailStr, Field, validator, root_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum
import uuid
import re
from app.models.user_model import UserRole
from app.utils.security import validate_password
from app.utils.validators import validate_email_address
from app.utils.nickname_gen import validate_or_generate_nickname, generate_random_nickname

def validate_nickname(nickname: Optional[str]) -> str:
    """
    Public validator that ensures we always return a valid nickname.
    Either validates the provided one or generates a new valid one.
    """
    if nickname is None:
        return generate_random_nickname()
    return nickname

def validate_url(url: Optional[str]) -> Optional[str]:
    if url is None:
        return url
    url_regex = r'^https?:\/\/[^\s/$.?#].[^\s]*$'
    if not re.match(url_regex, url):
        raise ValueError('Invalid URL format')
    return url

class UserBase(BaseModel):
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(
        None,
        min_length=3,
        max_length=32,
        pattern=r'^[\w-]+$',
        example="clever_raccoon_308"
    )
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] = Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")
    role: UserRole = Field(default=UserRole.ANONYMOUS)

    # Validators
    _validate_email = validator('email', pre=True, allow_reuse=True)(validate_email_address)
    _validate_urls = validator('profile_picture_url', 'linkedin_profile_url', 'github_profile_url', pre=True, allow_reuse=True)(validate_url)
    
    @validator('nickname', pre=True)
    def set_nickname(cls, v):
        return validate_nickname(v)

    class Config:
        from_attributes = True

class UserCreate(UserBase):
    password: str = Field(..., example="Secure*1234", min_length=8)

    _validate_password = validator('password', pre=True, allow_reuse=True)(validate_password)

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = Field(None, example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=3, max_length=32, pattern=r'^[\w-]+$', example="john_doe123")
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] = Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")
    role: Optional[UserRole] = Field(None, example="AUTHENTICATED")
    password: Optional[str] = Field(None, example="NewSecure*1234")

    _validate_password = validator('password', pre=True, allow_reuse=True)(validate_password)

    @root_validator(pre=True)
    def check_at_least_one_value(cls, values):
        if not any(values.values()):
            raise ValueError("At least one field must be provided for update")
        return values

class UserResponse(UserBase):
    id: uuid.UUID = Field(..., example=uuid.uuid4())
    is_professional: bool = Field(default=False)
    role: UserRole

class LoginRequest(BaseModel):
    email: str = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")

    _validate_email = validator('email', pre=True, allow_reuse=True)(validate_email_address)
    _validate_password = validator('password', pre=True, allow_reuse=True)(validate_password)

class ErrorResponse(BaseModel):
    error: str = Field(..., example="Not Found")
    details: Optional[str] = Field(None, example="The requested resource was not found.")

class UserListResponse(BaseModel):
    items: List[UserResponse] = Field(..., example=[{
        "id": uuid.uuid4(),
        "nickname": "clever_raccoon_308",
        "email": "john.doe@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "bio": "Experienced developer",
        "role": "AUTHENTICATED",
        "profile_picture_url": "https://example.com/profiles/john.jpg", 
        "linkedin_profile_url": "https://linkedin.com/in/johndoe", 
        "github_profile_url": "https://github.com/johndoe",
        "is_professional": False
    }])
    total: int = Field(..., example=100)
    page: int = Field(..., example=1)
    size: int = Field(..., example=10)

class UserRole(str, Enum):
    VISITOR = "VISITOR"
    REGISTERED = "REGISTERED"
    SUPERVISOR = "SUPERVISOR"
    SYSTEM_ADMIN = "SYSTEM_ADMIN"

class LoginRequest(BaseModel):
    account_email: EmailStr = Field(
        ...,
        example="user.name@organization.com",
        description="The registered email address for the account"
    )
    access_code: str = Field(
        ...,
        min_length=10,
        example="SecurePass#2024",
        description="Minimum 10 character authentication code"
    )

    @validator('access_code')
    def validate_access_code(cls, v):
        if len(v) < 10:
            raise ValueError("Access code must be at least 10 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Must contain at least one digit")
        return v

class ErrorResponse(BaseModel):
    error_type: str = Field(
        ...,
        example="AUTHENTICATION_FAILURE",
        description="Machine-readable error code"
    )
    error_message: str = Field(
        ...,
        example="Invalid credentials provided",
        description="Human-readable error details"
    )
    resolution_hint: Optional[str] = Field(
        None,
        example="Please check your email and password",
        description="Suggested corrective action"
    )

class UserSearchFilterRequest(BaseModel):
    search_query: Optional[str] = Field(
        None,
        example="john",
        description="Searches both username and email fields"
    )
    account_status: Optional[UserRole] = Field(
        None,
        example="REGISTERED"
    )
    include_inactive: bool = Field(
        False,
        example=False,
        description="Set to True to include locked accounts"
    )
    date_range_start: Optional[datetime] = Field(
        None,
        example="2024-01-01T00:00:00Z",
        description="Start of account creation date range"
    )
    date_range_end: Optional[datetime] = Field(
        None,
        example="2024-12-31T23:59:59Z",
        description="End of account creation date range"
    )
    results_per_page: int = Field(
        20,
        gt=0,
        le=100,
        example=20,
        description="Number of records per response"
    )
    continuation_token: Optional[str] = Field(
        None,
        description="Token for paginating through large result sets"
    )

class UserListResponse(BaseModel):
    user_records: List[UserResponse]
    total_results: int
    current_page: int
    page_size: int
    navigation_links: Optional[List[PaginationLink]]
    active_filters: Optional[UserSearchFilterRequest]
    next_page_token: Optional[str] = Field(
        None,
        description="Token for retrieving next page of results"
    )