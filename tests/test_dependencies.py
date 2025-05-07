import pytest
from unittest.mock import MagicMock, AsyncMock
from fastapi import status
from fastapi.exceptions import HTTPException
from app.core.config import AppSettings
from app.dependencies import (
    get_application_config,
    get_mail_service,
    get_database_session,
    authenticate_current_user,
    verify_user_permissions,
)
from app.services.mail.mailer import MailDispatcher
from app.services.database.session import AsyncDatabaseSession


class TestApplicationDependencies:
    """Test suite for application dependency injections"""
    
    @pytest.fixture
    def mock_config(self):
        return AppSettings()
    
    @pytest.fixture
    def mock_mailer(self):
        return MailDispatcher(template_engine=None)

    def test_config_loader(self, mock_config):
        """Verify configuration loader provides valid settings"""
        config = get_application_config()
        assert config is not None, "Should return configuration object"
        assert isinstance(config.db_connection, str), "Should contain database URL"
        assert hasattr(config, "security"), "Should contain security settings"

    def test_mail_service_initialization(self, mock_mailer):
        """Test mail service dependency injection"""
        mail_service = get_mail_service()
        assert isinstance(mail_service, MailDispatcher), "Should return mail dispatcher"
        assert mail_service.template_engine is not None, "Should have template engine"


class TestAuthenticationDependencies:
    """Test suite for authentication-related dependencies"""
    
    @pytest.fixture
    def admin_user(self):
        return {"id": "usr_123", "access_level": "administrator"}
    
    @pytest.fixture
    def standard_user(self):
        return {"id": "usr_456", "access_level": "basic"}
    
    @pytest.mark.asyncio
    async def test_failed_authentication(self, mocker):
        """Test invalid token handling"""
        mocker.patch(
            "app.services.auth.token_processor.validate_access_token",
            return_value=None
        )
        
        with pytest.raises(HTTPException) as context:
            await authenticate_current_user("broken_token")
            
        assert context.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid authentication" in context.value.detail

    @pytest.mark.asyncio
    async def test_permission_verification_success(self, admin_user):
        """Test successful permission check"""
        permission_check = verify_user_permissions(["administrator", "moderator"])
        result = await permission_check(current_user=admin_user)
        assert result == admin_user

    @pytest.mark.asyncio
    async def test_permission_verification_failure(self, standard_user):
        """Test failed permission check"""
        permission_check = verify_user_permissions(["administrator"])
        
        with pytest.raises(HTTPException) as context:
            await permission_check(current_user=standard_user)
            
        assert context.value.status_code == status.HTTP_403_FORBIDDEN
        assert "permission" in context.value.detail.lower()


class TestDatabaseDependencies:
    """Test suite for database connection handling"""
    
    @pytest.mark.asyncio
    async def test_database_session_management(self, mocker):
        """Verify database session generator"""
        mock_session = AsyncMock(spec=AsyncDatabaseSession)
        mocker.patch(
            "app.services.database.connector.create_session",
            return_value=mock_session
        )
        
        session_generator = get_database_session()
        async with session_generator() as session:
            assert isinstance(session, AsyncDatabaseSession)