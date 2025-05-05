# test_security.py
from builtins import RuntimeError, ValueError, isinstance, str
import pytest
import bcrypt

from app.utils.security import hash_password, verify_password, validate_password, generate_verification_token

# def test_hash_password():
#     """Test that hashing password returns a bcrypt hashed string."""
#     password = "secure_password"
#     hashed = hash_password(password)
#     assert hashed is not None
#     assert isinstance(hashed, str)
#     assert hashed.startswith('$2b$')

# def test_hash_password_with_different_rounds():
#     """Test hashing with different cost factors."""
#     password = "secure_password"
#     rounds = 10
#     hashed_10 = hash_password(password, rounds)
#     rounds = 12
#     hashed_12 = hash_password(password, rounds)
#     assert hashed_10 != hashed_12, "Hashes should differ with different cost factors"

# def test_verify_password_correct():
#     """Test verifying the correct password."""
#     password = "secure_password"
#     hashed = hash_password(password)
#     assert verify_password(password, hashed) is True

# def test_verify_password_incorrect():
#     """Test verifying the incorrect password."""
#     password = "secure_password"
#     hashed = hash_password(password)
#     wrong_password = "incorrect_password"
#     assert verify_password(wrong_password, hashed) is False

# def test_verify_password_invalid_hash():
#     """Test verifying a password against an invalid hash format."""
#     with pytest.raises(ValueError):
#         verify_password("secure_password", "invalid_hash_format")

# @pytest.mark.parametrize("password", [
#     "",
#     " ",
#     "a"*100  # Long password
# ])
# def test_hash_password_edge_cases(password):
#     """Test hashing various edge cases."""
#     hashed = hash_password(password)
#     assert isinstance(hashed, str) and hashed.startswith('$2b$'), "Should handle edge cases properly"

# def test_verify_password_edge_cases():
#     """Test verifying passwords with edge cases."""
#     password = " "
#     hashed = hash_password(password)
#     assert verify_password(password, hashed) is True
#     assert verify_password("not empty", hashed) is False

# # This function tests the error handling when an internal error occurs in bcrypt
# def test_hash_password_internal_error(monkeypatch):
#     """Test proper error handling when an internal bcrypt error occurs."""
#     def mock_bcrypt_gensalt(rounds):
#         raise RuntimeError("Simulated internal error")

#     monkeypatch.setattr("bcrypt.gensalt", mock_bcrypt_gensalt)
#     with pytest.raises(ValueError):
#         hash_password("test")

# import pytest
# from unittest.mock import patch
# import bcrypt
# import re
# from app.utils.security import (
#     validate_password,
#     hash_password,
#     verify_password,
#     generate_verification_token
# )

# class TestValidatePassword:
#     """Test suite for password validation"""
    
#     @pytest.mark.parametrize("valid_password", [
#         "Secure123!",
#         "LongerPassword123@",
#         "A1!bcdefg",
#         "Test@1234"
#     ])
#     def test_valid_passwords(self, valid_password):
#         """Test that valid passwords pass validation"""
#         assert validate_password(valid_password) == valid_password
    
#     @pytest.mark.parametrize("invalid_password,expected_error", [
#         ("short", "Password must be at least 8 characters long"),
#         ("nouppercase123!", "Password must contain at least one uppercase letter"),
#         ("NOLOWERCASE123!", "Password must contain at least one lowercase letter"),
#         ("NoDigitsHere!", "Password must contain at least one digit"),
#         ("MissingSpecial123", "Password must contain at least one special character"),
#         ("", "Password must be at least 8 characters long"),
#         ("         ", "Password must contain at least one uppercase letter"),
#         (None, "Password must be a string"),
#         (12345678, "Password must be a string"),
#         (True, "Password must be a string")
#     ])
#     def test_invalid_passwords(self, invalid_password, expected_error):
#         """Test that invalid passwords raise proper errors"""
#         with pytest.raises(ValueError) as excinfo:
#             validate_password(invalid_password)
#         assert expected_error in str(excinfo.value)

class TestValidatePassword:
    """Test suite for password validation"""
    
    @pytest.mark.parametrize("valid_password", [
        "Secure123!",
        "LongerPassword123@",
        "A1!bcdefg",
        "Test@1234"
    ])
    def test_valid_passwords(self, valid_password):
        """Test that valid passwords pass validation"""
        assert validate_password(valid_password) == valid_password
    
    @pytest.mark.parametrize("invalid_password,expected_error", [
        ("short", "Password must be at least 8 characters long"),
        ("nouppercase123!", "Password must contain at least one uppercase letter"),
        ("NOLOWERCASE123!", "Password must contain at least one lowercase letter"),
        ("NoDigitsHere!", "Password must contain at least one digit"),
        ("MissingSpecial123", "Password must contain at least one special character"),
        ("", "Password must be at least 8 characters long"),
        ("         ", "Password must contain at least one uppercase letter")
    ])
    def test_invalid_passwords(self, invalid_password, expected_error):
        """Test that invalid passwords raise proper errors"""
        with pytest.raises(ValueError, match=expected_error):
            validate_password(invalid_password)
        

    @pytest.mark.parametrize("non_string_input,expected_error", [
    (None, "Password must be a string"),
    (12345678, "Password must be a string"),
    (True, "Password must be a string")
])
    def test_non_string_inputs(self, non_string_input, expected_error):
        """Test that non-string inputs raise TypeError"""
        with pytest.raises(TypeError, match=expected_error):
            validate_password(non_string_input)
        

class TestHashPassword:
    """Test suite for password hashing"""
    
    def test_successful_hash(self):
        """Test that hashing returns a valid bcrypt hash"""
        password = "ValidPass123!"
        hashed = hash_password(password)
        assert isinstance(hashed, str)
        assert hashed.startswith('$2b$')
        assert len(hashed) == 60  # Standard bcrypt hash length
    
    def test_hash_verification(self):
        """Test that hashed password can be verified"""
        password = "Test@1234"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True
    
    def test_different_rounds_produce_different_hashes(self):
        """Test that different cost factors produce different hashes"""
        password = "SamePassword123!"
        hashed_10 = hash_password(password, rounds=10)
        hashed_12 = hash_password(password, rounds=12)
        assert hashed_10 != hashed_12
    
    def test_hash_rejects_invalid_passwords(self):
        """Test that hash_password rejects invalid passwords"""
        with pytest.raises(ValueError):
            hash_password("short")
        with pytest.raises(ValueError):
            hash_password("noSpecial123")
    
    def test_hash_non_string_input(self):
        """Test that non-string inputs are rejected"""
        with pytest.raises(ValueError):
            hash_password(12345678)
        with pytest.raises(ValueError):
            hash_password(True)

class TestVerifyPassword:
    """Test suite for password verification"""
    
    def test_correct_password(self):
        """Test verification with correct password"""
        password = "CorrectPass123!"
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        assert verify_password(password, hashed) is True
    
    def test_incorrect_password(self):
        """Test verification with incorrect password"""
        password = "CorrectPass123!"
        wrong_password = "WrongPass123!"
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        assert verify_password(wrong_password, hashed) is False
    
    def test_invalid_hash_format(self):
        """Test verification with invalid hash format"""
        with pytest.raises(ValueError):
            verify_password("anypassword", "invalid_hash_format")
    
    def test_empty_password(self):
        """Test verification with empty password"""
        hashed = bcrypt.hashpw(b" ", bcrypt.gensalt()).decode('utf-8')
        assert verify_password(" ", hashed) is True
        assert verify_password("", hashed) is False

class TestGenerateVerificationToken:
    """Test suite for verification token generation"""
    
    def test_token_generation(self):
        """Test that tokens are generated correctly"""
        token = generate_verification_token()
        assert isinstance(token, str)
        assert len(token) >= 22  # 16 bytes in URL-safe base64
        
    def test_token_uniqueness(self):
        """Test that generated tokens are unique"""
        tokens = {generate_verification_token() for _ in range(100)}
        assert len(tokens) == 100  # All tokens should be unique

def test_hash_password_internal_error(monkeypatch):
    """Test proper error handling when bcrypt fails"""
    def mock_gensalt(*args, **kwargs):
        raise RuntimeError("Simulated bcrypt failure")
    
    monkeypatch.setattr(bcrypt, "gensalt", mock_gensalt)
    with pytest.raises(ValueError) as excinfo:
        hash_password("ValidPass123!")
    assert "Failed to hash password" in str(excinfo.value)