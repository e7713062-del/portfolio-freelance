from fastapi import FastAPI, APIRouter, Depends, status
from fastapi import FastAPI, APIRouter
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
import uuid

# ================================
# Entities & Models
# ================================

@dataclass
class Tenant:
    id: str
    name: str
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class User:
    id: str
    tenant_id: str
    email: str
    password_hash: str
    full_name: str
    roles: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

# ================================
# DTOs (Data Transfer Objects)
# ================================

@dataclass
class RegisterDTO:
    tenant_name: str
    email: str
    password: str
    full_name: str

@dataclass
class LoginDTO:
    email: str
    password: str

@dataclass
class TokenResponseDTO:
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"

@dataclass
class UserProfileDTO:
    id: str
    tenant_id: str
    email: str
    full_name: str
    roles: List[str]

@dataclass
class UpdateProfileDTO:
    full_name: Optional[str] = None
    email: Optional[str] = None

# ================================
# Interfaces (Abstraction)
# ================================

class IUserRepository(ABC):
    @abstractmethod
    def save_tenant(self, tenant: Tenant) -> None:
        pass
    
    @abstractmethod
    def save_user(self, user: User) -> None:
        pass

    @abstractmethod
    def find_by_email(self, email: str) -> Optional[User]:
        pass

    @abstractmethod
    def find_by_id(self, user_id: str) -> Optional[User]:
        pass

    @abstractmethod
    def update_user(self, user: User) -> None:
        pass


class ITokenProvider(ABC):
    @abstractmethod
    def generate_access_token(self, user: User) -> str:
        pass

    @abstractmethod
    def generate_refresh_token(self, user: User) -> str:
        pass

    @abstractmethod
    def decode_token(self, token: str) -> Dict[str, Any]:
        pass


class IPasswordHasher(ABC):
    @abstractmethod
    def hash(self, password: str) -> str:
        pass

    @abstractmethod
    def verify(self, plain_password: str, hashed_password: str) -> bool:
        pass
    # Custom Exceptions
class AuthenticationError(Exception): pass
class NotFoundError(Exception): pass
class DuplicateEntityError(Exception): pass


class AuthService:
    def __init__(
        self, 
        user_repo: IUserRepository, 
        hasher: IPasswordHasher, 
        token_provider: ITokenProvider
    ):
        self._user_repo = user_repo
        self._hasher = hasher
        self._token_provider = token_provider

    def register_tenant_and_user(self, dto: RegisterDTO) -> UserProfileDTO:
        if self._user_repo.find_by_email(dto.email):
            raise DuplicateEntityError("Email is already registered.")

        tenant = Tenant(id=str(uuid.uuid4()), name=dto.tenant_name)
        self._user_repo.save_tenant(tenant)

        user = User(
            id=str(uuid.uuid4()),
            tenant_id=tenant.id,
            email=dto.email,
            password_hash=self._hasher.hash(dto.password),
            full_name=dto.full_name,
            roles=["TenantAdmin"]
        )
        self._user_repo.save_user(user)

        return UserProfileDTO(
            id=user.id,
            tenant_id=user.tenant_id,
            email=user.email,
            full_name=user.full_name,
            roles=user.roles
        )

    def login(self, dto: LoginDTO) -> TokenResponseDTO:
        user = self._user_repo.find_by_email(dto.email)
        if not user or not self._hasher.verify(dto.password, user.password_hash):
            raise AuthenticationError("Invalid email or password.")

        return TokenResponseDTO(
            access_token=self._token_provider.generate_access_token(user),
            refresh_token=self._token_provider.generate_refresh_token(user)
        )

    def refresh_access_token(self, refresh_token: str) -> TokenResponseDTO:
        payload = self._token_provider.decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise AuthenticationError("Invalid token type. Refresh token required.")

        user = self._user_repo.find_by_id(payload.get("sub"))
        if not user:
            raise NotFoundError("User associated with token not found.")

        return TokenResponseDTO(
            access_token=self._token_provider.generate_access_token(user),
            refresh_token=refresh_token
        )


class UserService:
    def __init__(self, user_repo: IUserRepository):
        self._user_repo = user_repo

    def get_profile(self, user_id: str) -> UserProfileDTO:
        user = self._user_repo.find_by_id(user_id)
        if not user:
            raise NotFoundError("User profile not found.")

        return UserProfileDTO(
            id=user.id,
            tenant_id=user.tenant_id,
            email=user.email,
            full_name=user.full_name,
            roles=user.roles
        )

    def update_profile(self, user_id: str, dto: UpdateProfileDTO) -> UserProfileDTO:
        user = self._user_repo.find_by_id(user_id)
        if not user:
            raise NotFoundError("User not found.")

        if dto.full_name is not None:
            user.full_name = dto.full_name
            
        if dto.email is not None and dto.email != user.email:
            if self._user_repo.find_by_email(dto.email):
                raise DuplicateEntityError("Email is already in use.")
            user.email = dto.email

        self._user_repo.update_user(user)

        return UserProfileDTO(
            id=user.id,
            tenant_id=user.tenant_id,
            email=user.email,
            full_name=user.full_name,
            roles=user.roles
        )
    from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

router = APIRouter(prefix="/api/v1")
security = HTTPBearer()

# ================================
# Dependency Injection Wiring
# ================================

def get_auth_service() -> AuthService:
    # يتم هنا ربط الـ Repositories والـ Security implementations الفعلية
    pass

def get_user_service() -> UserService:
    pass

def get_token_provider() -> ITokenProvider:
    pass

def get_current_user_id(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    token_provider: ITokenProvider = Depends(get_token_provider)
) -> str:
    try:
        payload = token_provider.decode_token(credentials.credentials)
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Access token required"
            )
        return payload["sub"]
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid or expired token"
        )

# ================================
# Endpoints
# ================================

@router.post("/auth/register", status_code=status.HTTP_201_CREATED, response_model=UserProfileDTO)
def register(
    dto: RegisterDTO, 
    auth_service: AuthService = Depends(get_auth_service)
):
    try:
        return auth_service.register_tenant_and_user(dto)
    except DuplicateEntityError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.post("/auth/login", response_model=TokenResponseDTO)
def login(
    dto: LoginDTO, 
    auth_service: AuthService = Depends(get_auth_service)
):
    try:
        return auth_service.login(dto)
    except AuthenticationError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

@router.post("/auth/refresh-token", response_model=TokenResponseDTO)
def refresh_token(
    refresh_token: str, 
    auth_service: AuthService = Depends(get_auth_service)
):
    try:
        return auth_service.refresh_access_token(refresh_token)
    except (AuthenticationError, NotFoundError) as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

@router.get("/users/me", response_model=UserProfileDTO)
def get_current_user_profile(
    current_user_id: str = Depends(get_current_user_id),
    user_service: UserService = Depends(get_user_service)
):
    try:
        return user_service.get_profile(current_user_id)
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

@router.put("/users/me", response_model=UserProfileDTO)
def update_current_user_profile(
    dto: UpdateProfileDTO,
    current_user_id: str = Depends(get_current_user_id),
    user_service: UserService = Depends(get_user_service)
):
    try:
        return user_service.update_profile(current_user_id, dto)
    except (NotFoundError, DuplicateEntityError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    # schemas.py
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ProviderType(str, Enum):
    STRIPE = "stripe"
    GITHUB = "github"
    SLACK = "slack"


class AuthMethod(str, Enum):
    OAUTH2 = "oauth2"
    API_KEY = "api_key"


class IntegrationResponse(BaseModel):
    id: str
    provider: ProviderType
    name: str
    auth_method: AuthMethod
    is_connected: bool


class ConnectRequest(BaseModel):
    auth_method: AuthMethod
    api_key: Optional[str] = Field(None, description="مطلوب في حالة استخدام API Key")
    code: Optional[str] = Field(None, description="كود التفويض المرجع في حالة OAuth2")
    redirect_uri: Optional[str] = None


class ConnectionResponse(BaseModel):
    integration_id: str
    status: str
    message: str


class WebhookPayload(BaseModel):
    provider: ProviderType
    event_type: str
    data: Dict[str, Any]
    # providers/base.py
from abc import ABC, abstractmethod
from typing import Any, Dict
from schemas import ConnectRequest


class BaseIntegrationProvider(ABC):
    """الفئة الأم المجرّدة لجميع الموفرين الخارجيين"""

    @property
    @abstractmethod
    def provider_type(self) -> str:
        pass

    @abstractmethod
    async def connect(self, request: ConnectRequest) -> Dict[str, Any]:
        """معالجة عملية الاتصال وتسليم Tokens أو حِفظ API Key"""
        pass

    @abstractmethod
    async def handle_webhook(
        self, payload: Dict[str, Any], headers: Dict[str, str]
    ) -> bool:
        """معالجة Webhooks القادمة والتحقق من التوقيع (Signature Verification)"""
        pass
    # providers/stripe_provider.py
from typing import Any, Dict
from providers.base import BaseIntegrationProvider
from schemas import ConnectRequest, ProviderType


class StripeIntegrationProvider(BaseIntegrationProvider):

    @property
    def provider_type(self) -> str:
        return ProviderType.STRIPE

    async def connect(self, request: ConnectRequest) -> Dict[str, Any]:
        if request.auth_method == "api_key":
            # معالجة والتحقق من Stripe API Key
            return {"status": "connected", "access_token": request.api_key}
        # معالجة OAuth2...
        return {"status": "connected", "access_token": "stripe_oauth_token"}

    async def handle_webhook(
        self, payload: Dict[str, Any], headers: Dict[str, str]
    ) -> bool:
        # التحقق من توقيع Stripe Webhook ومعالجة الحدث
        event_type = payload.get("type")
        # تنفيذ المنطق الخاص بالحدث...
        return True
    # service.py
from typing import Dict, List
from fastapi import HTTPException, status
from providers.base import BaseIntegrationProvider
from providers.stripe_provider import StripeIntegrationProvider
from schemas import (
    ConnectRequest,
    ConnectionResponse,
    IntegrationResponse,
    ProviderType,
)


class IntegrationService:

    def __init__(self):
        # تسجيل الموفرين المتاحين في النظام (Registry)
        self._providers: Dict[str, BaseIntegrationProvider] = {}
        self._register_default_providers()

    def _register_default_providers(self):
        stripe = StripeIntegrationProvider()
        self._providers[stripe.provider_type] = stripe

    def get_provider(self, provider_name: str) -> BaseIntegrationProvider:
        provider = self._providers.get(provider_name)
        if not provider:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"الخدمة '{provider_name}' غير مدعومة حالياً.",
            )
        return provider

    async def list_available_integrations(self) -> List[IntegrationResponse]:
        # استرجاع جميع الخدمات والتحقق من حالة الاتصال للمستخدم
        return [
            IntegrationResponse(
                id="int_123",
                provider=ProviderType.STRIPE,
                name="Stripe Payment Gateway",
                auth_method="api_key",
                is_connected=True,
            )
        ]

    async def connect_service(
        self, provider_name: str, request: ConnectRequest
    ) -> ConnectionResponse:
        provider = self.get_provider(provider_name)
        result = await provider.connect(request)

        # حفظ بيانات الاتصال المشفرة في قاعدة البيانات هنا...

        return ConnectionResponse(
            integration_id="int_123",
            status="success",
            message=f"تم الربط بنجاح مع {provider_name}",
        )

    async def disconnect_service(self, integration_id: str) -> None:
        # إلغاء الربط وحذف/تعطيل المفاتيح من قاعدة البيانات
        # إذا لم تعثر على المعرف:
        # raise HTTPException(status_code=404, detail="Integration not found")
        pass

    async def process_incoming_webhook(
        self, provider_name: str, payload: Dict, headers: Dict
    ) -> bool:
        provider = self.get_provider(provider_name)
        return await provider.handle_webhook(payload, headers)
    # router.py
from typing import Dict, List
from fastapi import APIRouter, Header, Request, status
from schemas import ConnectRequest, ConnectionResponse, IntegrationResponse
from service import IntegrationService

router = APIRouter(prefix="/api/v1/integrations", tags=["Integrations"])
integration_service = IntegrationService()


@router.get("", response_model=List[IntegrationResponse])
async def list_integrations():
    """عرض جميع الخدمات الخارجية المتاحة وحالة الربط"""
    return await integration_service.list_available_integrations()


@router.post("/{provider}/connect", response_model=ConnectionResponse)
async def connect_integration(provider: str, request: ConnectRequest):
    """ربط خدمة خارجية جديدة عبر OAuth2 أو API Key"""
    return await integration_service.connect_service(provider, request)


@router.delete("/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
async def disconnect_integration(integration_id: str):
    """إلغاء ربط خدمة خارجية"""
    await integration_service.disconnect_service(integration_id)


@router.post("/webhooks/incoming/{provider}")
async def handle_incoming_webhook(
    provider: str, request: Request, x_signature: str = Header(None)
):
    """استقبال وإدارة البيانات الواردة (Webhooks) من الخدمات الخارجية"""
    payload = await request.json()
    headers = dict(request.headers)

    success = await integration_service.process_incoming_webhook(
        provider, payload, headers
    )
    return {"received": True, "processed": success}
# app/models/resource.py
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class ResourceModel(BaseModel):
    """الكيان الأساسي للمورد داخل النظام (Domain Model)"""
    id: int
    name: str
    description: Optional[str] = None
    is_active: bool = True
    is_deleted: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# app/schemas/resource.py
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class ResourceCreateSchema(BaseModel):
    """DTO لإنشاء مورد جديد"""
    name: str = Field(..., min_length=2, max_length=100, example="Resource Alpha")
    description: Optional[str] = Field(None, max_length=500, example="Primary system resource")

class ResourceUpdateSchema(BaseModel):
    """DTO للتحديث الشامل (PUT)"""
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    is_active: bool

class ResourcePatchSchema(BaseModel):
    """DTO للتحديث الجزئي (PATCH)"""
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    is_active: Optional[bool] = None

class ResourceResponseSchema(BaseModel):
    """DTO لإرجاع البيانات للعميل"""
    id: int
    name: str
    description: Optional[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
        # app/repositories/resource.py
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple
from datetime import datetime
from app.models.resource import ResourceModel
from app.schemas.resource import ResourceCreateSchema, ResourceUpdateSchema, ResourcePatchSchema

class AbstractResourceRepository(ABC):
    """واجهة تجريدية لنمط الـ Repository لضمان مرونة تغيير مصدر البيانات مستقبلاً"""
    
    @abstractmethod
    def get_all(self, skip: int = 0, limit: int = 10, search: Optional[str] = None) -> Tuple[List[ResourceModel], int]:
        pass

    @abstractmethod
    def get_by_id(self, resource_id: int) -> Optional[ResourceModel]:
        pass

    @abstractmethod
    def create(self, schema: ResourceCreateSchema) -> ResourceModel:
        pass

    @abstractmethod
    def update(self, resource_id: int, schema: ResourceUpdateSchema) -> Optional[ResourceModel]:
        pass

    @abstractmethod
    def patch(self, resource_id: int, schema: ResourcePatchSchema) -> Optional[ResourceModel]:
        pass

    @abstractmethod
    def delete(self, resource_id: int, hard_delete: bool = False) -> bool:
        pass


class InMemoryResourceRepository(AbstractResourceRepository):
    """تطبيق عملي للـ Repository باستخدام الذاكرة (يمكن استبداله بـ SQLAlchemy/PostgreSQL بسهولة)"""
    
    def __init__(self):
        self._storage: dict[int, ResourceModel] = {}
        self._counter: int = 1

    def get_all(self, skip: int = 0, limit: int = 10, search: Optional[str] = None) -> Tuple[List[ResourceModel], int]:
        active_items = [r for r in self._storage.values() if not r.is_deleted]
        
        if search:
            active_items = [r for r in active_items if search.lower() in r.name.lower()]
            
        total = len(active_items)
        paginated_items = active_items[skip : skip + limit]
        return paginated_items, total

    def get_by_id(self, resource_id: int) -> Optional[ResourceModel]:
        resource = self._storage.get(resource_id)
        if resource and not resource.is_deleted:
            return resource
        return None

    def create(self, schema: ResourceCreateSchema) -> ResourceModel:
        resource = ResourceModel(
            id=self._counter,
            name=schema.name,
            description=schema.description
        )
        self._storage[self._counter] = resource
        self._counter += 1
        return resource

    def update(self, resource_id: int, schema: ResourceUpdateSchema) -> Optional[ResourceModel]:
        resource = self.get_by_id(resource_id)
        if not resource:
            return None
        
        resource.name = schema.name
        resource.description = schema.description
        resource.is_active = schema.is_active
        resource.updated_at = datetime.utcnow()
        return resource

    def patch(self, resource_id: int, schema: ResourcePatchSchema) -> Optional[ResourceModel]:
        resource = self.get_by_id(resource_id)
        if not resource:
            return None

        update_data = schema.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(resource, key, value)
            
        resource.updated_at = datetime.utcnow()
        return resource

    def delete(self, resource_id: int, hard_delete: bool = False) -> bool:
        resource = self._storage.get(resource_id)
        if not resource or resource.is_deleted:
            return False

        if hard_delete:
            del self._storage[resource_id]
        else:
            resource.is_deleted = True
            resource.updated_at = datetime.utcnow()
        return True
    # app/services/resource.py
from typing import Optional, List, Dict, Any
from fastapi import HTTPException, status
from app.repositories.resource import AbstractResourceRepository
from app.schemas.resource import (
    ResourceCreateSchema, 
    ResourceUpdateSchema, 
    ResourcePatchSchema, 
    ResourceResponseSchema
)

class ResourceService:
    """طبقة البيزنس لوجيك لعزل الـ Controllers عن قواعد البيانات"""
    
    def __init__(self, repository: AbstractResourceRepository):
        self.repository = repository

    def list_resources(self, page: int = 1, limit: int = 10, search: Optional[str] = None) -> Dict[str, Any]:
        if page < 1:
            page = 1
        skip = (page - 1) * limit
        
        items, total = self.repository.get_all(skip=skip, limit=limit, search=search)
        
        return {
            "data": items,
            "meta": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit if total > 0 else 0
            }
        }

    def get_resource_by_id(self, resource_id: int) -> ResourceResponseSchema:
        resource = self.repository.get_by_id(resource_id)
        if not resource:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail=f"Resource with ID {resource_id} not found."
            )
        return resource

    def create_resource(self, schema: ResourceCreateSchema) -> ResourceResponseSchema:
        return self.repository.create(schema)

    def update_resource(self, resource_id: int, schema: ResourceUpdateSchema) -> ResourceResponseSchema:
        updated_resource = self.repository.update(resource_id, schema)
        if not updated_resource:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail=f"Resource with ID {resource_id} not found."
            )
        return updated_resource

    def patch_resource(self, resource_id: int, schema: ResourcePatchSchema) -> ResourceResponseSchema:
        patched_resource = self.repository.patch(resource_id, schema)
        if not patched_resource:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail=f"Resource with ID {resource_id} not found."
            )
        return patched_resource

    def delete_resource(self, resource_id: int, hard_delete: bool = False) -> None:
        success = self.repository.delete(resource_id, hard_delete=hard_delete)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail=f"Resource with ID {resource_id} not found."
            )
        # app/routers/resource.py
from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from app.repositories.resource import InMemoryResourceRepository
from app.services.resource import ResourceService
from app.schemas.resource import (
    ResourceCreateSchema, 
    ResourceUpdateSchema, 
    ResourcePatchSchema, 
    ResourceResponseSchema
)

router = APIRouter(prefix="/api/v1/resources", tags=["System & Data Management"])

# Dependency Injection Setup
db_repository = InMemoryResourceRepository()

def get_resource_service() -> ResourceService:
    return ResourceService(repository=db_repository)


@router.get("", response_model=dict, status_code=status.HTTP_200_OK)
def get_resources(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(10, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search by name"),
    service: ResourceService = Depends(get_resource_service)
):
    """GET /api/v1/resources - استرجاع قوائم البيانات مع دعم الـ Pagination والـ Filtering"""
    return service.list_resources(page=page, limit=limit, search=search)


@router.post("", response_model=ResourceResponseSchema, status_code=status.HTTP_201_CREATED)
def create_resource(
    schema: ResourceCreateSchema,
    service: ResourceService = Depends(get_resource_service)
):
    """POST /api/v1/resources - إنشاء مورد جديد في النظام"""
    return service.create_resource(schema)


@router.get("/{resource_id}", response_model=ResourceResponseSchema, status_code=status.HTTP_200_OK)
def get_resource_by_id(
    resource_id: int,
    service: ResourceService = Depends(get_resource_service)
):
    """GET /api/v1/resources/{id} - جلب تفاصيل عنصر محدد"""
    return service.get_resource_by_id(resource_id)


@router.put("/{resource_id}", response_model=ResourceResponseSchema, status_code=status.HTTP_200_OK)
def update_resource(
    resource_id: int,
    schema: ResourceUpdateSchema,
    service: ResourceService = Depends(get_resource_service)
):
    """PUT /api/v1/resources/{id} - تحديث شامل لعنصر محدد"""
    return service.update_resource(resource_id, schema)


@router.patch("/{resource_id}", response_model=ResourceResponseSchema, status_code=status.HTTP_200_OK)
def patch_resource(
    resource_id: int,
    schema: ResourcePatchSchema,
    service: ResourceService = Depends(get_resource_service)
):
    """PATCH /api/v1/resources/{id} - تحديث جزئي لبيانات عنصر"""
    return service.patch_resource(resource_id, schema)


@router.delete("/{resource_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_resource(
    resource_id: int,
    hard_delete: bool = Query(False, description="Set True for Hard Delete, False for Soft Delete"),
    service: ResourceService = Depends(get_resource_service)
):
    """DELETE /api/v1/resources/{id} - حذف عنصر (Soft Delete / Hard Delete)"""
    service.delete_resource(resource_id, hard_delete=hard_delete)
    return None
# main.py
from fastapi import FastAPI
from app.routers.resource import router as resource_router

app = FastAPI(
    title="Data & System Management API",
    version="1.0.0",
    description="Clean Architecture implementation of RESTful API guidelines"
)

app.include_router(resource_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
    from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from typing import Dict, Any
from abc import ABC, abstractmethod


# 1. Interface / Abstract Class for Health Checkers
class BaseChecker(ABC):
    @abstractmethod
    async def check(self) -> bool:
        pass


# 2. Database Health Checker (PostgreSQL)
class DatabaseChecker(BaseChecker):
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def check(self) -> bool:
        try:
            # تنفيذ استعلام خفيف جدا للتأكد من استجابة PostgreSQL
            result = await self.db_session.execute(text("SELECT 1"))
            return result.scalar() == 1
        except Exception:
            return False


# 3. Health Service (Encapsulates Business Logic)
class HealthService:
    def __init__(self, db_checker: DatabaseChecker):
        self.db_checker = db_checker

    def get_liveness(self) -> Dict[str, str]:
        """Liveness Probe: التأكد من أن السيرفر يعمل ويستقبل طلبات"""
        return {"status": "alive"}

    async def get_readiness(self) -> Dict[str, Any]:
        """Readiness Probe: التأكد من جاهزية السيرفر والخدمات المساعدة"""
        db_healthy = await self.db_checker.check()
        
        # يمكنك إضافة فحوصات أخرى هنا (Redis, RabbitMQ, external APIs...)
        services_status = {
            "database": "connected" if db_healthy else "disconnected"
        }
        
        is_ready = db_healthy  # يُعتبر السيرفر جاهزاً إذا كانت كل الخدمات الأساسية تعمل

        return {
            "status": "ready" if is_ready else "unhealthy",
            "services": services_status,
            "is_ready": is_ready
        }


# 4. Dependency Injection Helper
# افترض أن لديك دالة get_db توفر جلسة قاعدة البيانات AsyncSession
async def get_db_session() -> AsyncSession:
    # يتم استبدال هذا الجزء بجلسة قاعدة البيانات الخاصة بالمشروع (e.g., async_session)
    pass 

async def get_health_service(db: AsyncSession = Depends(get_db_session)) -> HealthService:
    db_checker = DatabaseChecker(db_session=db)
    return HealthService(db_checker=db_checker)


# 5. API Router Definition
router = APIRouter(prefix="/api/v1/health", tags=["Health & Monitoring"])


@router.get("", status_code=status.HTTP_200_OK, summary="Liveness Probe")
async def liveness_check(
    service: HealthService = Depends(get_health_service)
) -> Dict[str, str]:
    """الفحص السريع لسلامة السيرفر."""
    return service.get_liveness()


@router.get("/ready", summary="Readiness Probe")
async def readiness_check(
    service: HealthService = Depends(get_health_service)
):
    """التأكد من اتصال FastAPI بقاعدة البيانات والخدمات المساعدة."""
    health_data = await service.get_readiness()
    
    if not health_data["is_ready"]:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": health_data["status"],
                "services": health_data["services"]
            }
        )
        
    return {
        "status": health_data["status"],
        "services": health_data["services"]
    }
    
