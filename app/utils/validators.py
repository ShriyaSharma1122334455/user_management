from email_validator import validate_email, EmailNotValidError

def validate_email_address(email: str | None) -> str:
    """
    Validate and normalize an email address.
    
    Args:
        email: Email address to validate
    
    Returns:
        Normalized email address if valid (lowercase, whitespace trimmed)
    
    Raises:
        ValueError: If email is invalid, empty, or whitespace-only
        TypeError: If input is not a string
    """
    if email is None:
        raise TypeError("Email cannot be None")
    if not isinstance(email, str):
        raise TypeError(f"Email must be string, got {type(email)}")
    
    # Trim whitespace and check for empty string
    email = email.strip()
    if not email:
        raise ValueError("Email cannot be empty or whitespace only")
    
    try:
        validated = validate_email(email, check_deliverability=False)
        return validated.email.lower().strip()  # Ensure consistent normalization
    except EmailNotValidError as e:
        raise ValueError(f"Invalid email address: {str(e)}") from e