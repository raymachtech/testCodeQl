from flask import jsonify, make_response
import re
import json
from typing import Optional, Tuple, Any


MAX_STRING_LENGTH = 10000
MAX_QUERY_PARAM_LENGTH = 1000

DANGEROUS_PATTERNS = [
    (r'<script[^>]*>.*?</script>', '', re.IGNORECASE | re.DOTALL),
    (r'javascript:', '', re.IGNORECASE),
    (r'on\w+\s*=', '', re.IGNORECASE),
    (r'\.\./', ''),
    (r'\.\.\\', ''),
]
def sanitize_string(value: str, max_length: int = MAX_STRING_LENGTH) -> str:
    if not isinstance(value, str):
        return value
    # Truncate to max length
    if len(value) > max_length:
        value = value[:max_length]
    # Remove dangerous patterns (XSS, path traversal, etc.)
    for pattern, replacement, *flags in DANGEROUS_PATTERNS:
        if flags:
            value = re.sub(pattern, replacement, value, flags=flags[0])
        else:
            value = re.sub(pattern, replacement, value)
    # Remove null bytes
    value = value.replace('\x00', '')
    # Convert newlines to spaces
    value = value.replace('\r\n', ' ')
    value = value.replace('\n', ' ')
    # Strip whitespace
    value = value.strip()
    return value

def validate_required(value: Any, field_name: str) -> Tuple[bool, Optional[str]]:
    if value is None:
        return False, f"{field_name} is required"
    if isinstance(value, str) and value.strip() == "":
        return False, f"{field_name} cannot be empty"
    return True, None

def validate_email(email: str, field_name: str = "Email") -> Tuple[bool, Optional[str]]:
    if not email or not isinstance(email, str):
        return False, f"{field_name} is required"
    
    email = email.strip()
    if len(email) == 0:
        return False, f"{field_name} cannot be empty"
    
    if len(email) > 100:
        return False, f"{field_name} exceeds maximum length of 100 characters"
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, f"{field_name} is not a valid email format"
    
    return True, None

def validate_int(value: Any, field_name: str, min_value: Optional[int] = None, 
                 max_value: Optional[int] = None, allow_zero: bool = True) -> Tuple[bool, Optional[str], Optional[int]]:
    if value is None:
        return True, None, None
    
    try:
        if isinstance(value, str):
            int_value = int(value.strip())
        else:
            int_value = int(value)
    except (ValueError, AttributeError):
        return False, f"{field_name} must be a valid integer", None
    
    if not allow_zero and int_value == 0:
        return False, f"{field_name} must be greater than 0", None
    
    if min_value is not None and int_value < min_value:
        return False, f"{field_name} must be at least {min_value}", None
    
    if max_value is not None and int_value > max_value:
        return False, f"{field_name} must be at most {max_value}", None
    
    return True, None, int_value

def validate_positive_int(value: Any, field_name: str, max_value: Optional[int] = None) -> Tuple[bool, Optional[str], Optional[int]]:
    return validate_int(value, field_name, min_value=1, max_value=max_value, allow_zero=False)

def validate_non_negative_int(value: Any, field_name: str, max_value: Optional[int] = None) -> Tuple[bool, Optional[str], Optional[int]]:
    return validate_int(value, field_name, min_value=0, max_value=max_value, allow_zero=True)

def validate_id_list(value: Any, field_name: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate ID or comma-separated list of IDs.
    Accepts: 2456, "2985", "2985,2467"
    Returns validated string of comma-separated IDs.
    """
    if value is None:
        return False, f"{field_name} is required", None
    # Convert to string
    value_str = str(value).strip()
    if not value_str:
        return False, f"{field_name} cannot be empty", None
    # Split by comma and validate each ID
    ids = [id.strip() for id in value_str.split(',')]
    validated_ids = []
    for id_val in ids:
        if not id_val:
            continue
        # Check if it's a valid positive integer
        if not id_val.isdigit():
            return False, f"{field_name} contains invalid ID: {id_val}", None
        try:
            if int(id_val) <= 0:
                return False, f"{field_name} contains invalid ID: {id_val}", None
        except (ValueError, OverflowError):
            return False, f"{field_name} contains invalid ID: {id_val}", None
        validated_ids.append(id_val)
    if not validated_ids:
        return False, f"{field_name} must contain at least one valid ID", None
    return True, None, ','.join(validated_ids)

def validate_string(value: Any, field_name: str, max_length: Optional[int] = None, 
                   min_length: Optional[int] = None, allow_empty: bool = False) -> Tuple[bool, Optional[str], Optional[str]]:
    if value is None:
        return True, None, None
    
    if not isinstance(value, str):
        value = str(value)
    
    value = value.strip()
    
    if not allow_empty and len(value) == 0:
        return False, f"{field_name} cannot be empty", None
    
    if min_length is not None and len(value) < min_length:
        return False, f"{field_name} must be at least {min_length} characters", None
    
    if max_length is not None and len(value) > max_length:
        return False, f"{field_name} exceeds maximum length of {max_length} characters", None
    
    return True, None, value

def validate_enum(value: Any, field_name: str, allowed_values: list) -> Tuple[bool, Optional[str]]:
    if value is None:
        return True, None
    
    if value not in allowed_values:
        return False, f"{field_name} must be one of: {', '.join(map(str, allowed_values))}"
    
    return True, None

def validate_date_format(date_str: str, field_name: str = "Date") -> Tuple[bool, Optional[str]]:
    if not date_str or not isinstance(date_str, str):
        return False, f"{field_name} is required"
    
    date_str = date_str.strip()
    date_pattern = r'^\d{4}-\d{2}-\d{2}$'
    
    if not re.match(date_pattern, date_str):
        return False, f"{field_name} must be in format YYYY-MM-DD"
    
    try:
        from datetime import datetime
        datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError:
        return False, f"{field_name} is not a valid date"
    
    return True, None

def validate_time_format(time_str: str, field_name: str = "Time") -> Tuple[bool, Optional[str]]:
    if not time_str or not isinstance(time_str, str):
        return True, None
    
    time_str = time_str.strip()
    time_pattern = r'^([0-1][0-9]|2[0-3]):[0-5][0-9]$'
    
    if not re.match(time_pattern, time_str):
        return False, f"{field_name} must be in format HH:MM (24-hour format)"
    
    return True, None

def return_validation_error(message: str, status_code: int = 400):
    response = make_response(json.dumps({
        "status": "error",
        "code": status_code,
        "message": message,
        "error": "Validation failed"
    }), status_code)
    response.headers['Content-Type'] = 'application/json'
    return response

def validate_fields(field_validations: dict) -> Tuple[bool, Optional[str], dict]:
    validated = {}
    
    for field_name, validation_config in field_validations.items():
        value = validation_config[0]
        validator_func = validation_config[1]
        validator_args = validation_config[2:] if len(validation_config) > 2 else []
        
        if value is None:
            validated[field_name] = None
            continue
        
        result = validator_func(value, *validator_args)
        
        if len(result) == 2:
            is_valid, error_msg = result
            if not is_valid:
                return False, error_msg, {}
            validated[field_name] = value
        elif len(result) == 3:
            is_valid, error_msg, converted_value = result
            if not is_valid:
                return False, error_msg, {}
            validated[field_name] = converted_value
    
    return True, None, validated

def validate_and_return(field_validations: dict):
    is_valid, error_msg, validated = validate_fields(field_validations)
    if not is_valid:
        return return_validation_error(error_msg)
    return None

def validate_args(**kwargs) -> Tuple[Optional[Any], Optional[Any]]:
    is_valid, error_msg, validated = validate_fields(kwargs)
    if not is_valid:
        return return_validation_error(error_msg), None
    return None, validated
