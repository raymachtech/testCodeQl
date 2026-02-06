import base64
import logging
from time import strftime
import traceback
import uuid
from html import escape
from flask import request
from flask_cors import CORS
from flask import Flask, Blueprint, request, redirect, make_response, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import datetime

import json
import jwt
import msal

from router.validators import MAX_QUERY_PARAM_LENGTH, sanitize_string
from router.eLogRoute import egca_aix_bp
from response_maker import responseMaker
from config import (
    AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID,
    AZURE_REDIRECT_URI, AZURE_SCOPE, JWT_SECRET, JWT_EXP_MINUTES,
    ALLOWED_ORIGINS, FRONTEND_REDIRECT_URL
)
from controller.elogController import routeVerifyUser

logging.basicConfig(
    filename='logs/app.log',
    level=logging.ERROR,
    format='%(asctime)s %(levelname)s %(message)s',
    filemode='a'
)

app = Flask(__name__)

app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024

if not ALLOWED_ORIGINS:
    raise ValueError("ALLOWED_ORIGINS must be configured for CORS. No fallback to * allowed.")

CORS(
    app,
    supports_credentials=True,
    origins=ALLOWED_ORIGINS,
    allow_headers=['Content-Type', 'Authorization', 'Accept'],
    methods=['GET', 'POST', 'OPTIONS'],
    expose_headers=['Content-Type']
)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100000 per day", "20000 per hour"],
    storage_uri="memory://",
    headers_enabled=True
)

PUBLIC_ROUTES = [
    '/',
    '/login',
    '/redirect',
    '/logout',
    '/auth/me'
]


 
@app.before_request
def sanitize_query_params():
    if request.path in PUBLIC_ROUTES:
        return
    """Sanitize query parameters to prevent XSS and injection attacks"""
    if request.args:
        from werkzeug.datastructures import MultiDict
        sanitized_dict = MultiDict()
        for key, value in request.args.items(multi=True):
            sanitized_value = sanitize_string(str(value), MAX_QUERY_PARAM_LENGTH)
            sanitized_dict.add(key, sanitized_value)
        request.args = sanitized_dict
        
@app.before_request
def authenticate_request():
    if request.method == 'TRACE':
        return jsonify({
            "error": "Method not allowed",
            "message": "TRACE method is not supported"
        }), 405
    if request.path in PUBLIC_ROUTES:
        return None
    
    if request.method == 'OPTIONS':
        return None
    
    decoded, error = validate_token_from_cookie()
    
    if error or not decoded:
        return jsonify({
            "error": error or "Authentication required",
            "message": "Please login to access this resource"
        }), 401
    
    request.user = decoded
    request.user_id = decoded.get('RM_UserId')
    request.user_role = decoded.get('UserRole')
    request.user_email = decoded.get('email')
    request.user_name = decoded.get('name')


@app.route('/')
def default():
    return responseMaker("Connected to CrewMach API", "success", 200,"default")

CLIENT_ID = AZURE_CLIENT_ID
CLIENT_SECRET = AZURE_CLIENT_SECRET
TENANT_ID = AZURE_TENANT_ID
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
REDIRECT_URI = AZURE_REDIRECT_URI
SCOPE = AZURE_SCOPE

def build_msal_app():
    return msal.ConfidentialClientApplication(
        CLIENT_ID, authority=AUTHORITY,
        client_credential=CLIENT_SECRET
    )

def get_user_info_from_email(email):
    try:
        response = routeVerifyUser(email, None)
        response_data = response.get_json()
        
        if response_data:
            user_data = response_data.get('UserVerification', [])
            if user_data and len(user_data) > 0:
                first_user = user_data[0]
                if first_user.get('Message') == 'User found and active':
                    return {
                        'RM_UserId': first_user.get('RM_UserId'),
                        'UserRole': first_user.get('UserRole'),
                        'EgcaId': first_user.get('EgcaId')
                    }
        return None
    except Exception as e:
        logging.error(f"Error getting user info from email: {e}")
        return None

def validate_token_from_cookie():
    token = request.cookies.get('auth_token')
    
    if not token:
        return None, "No authentication token found"
    
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return decoded, None
    except jwt.ExpiredSignatureError:
        return None, "Token expired"
    except jwt.InvalidTokenError as e:
        logging.error(f"Invalid token: {e}")
        return None, f"Invalid token"
    except Exception as e:
        logging.error(f"Token validation error: {e}")
        return None, f"Token validation error"

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        decoded, error = validate_token_from_cookie()
        
        if error or not decoded:
            return jsonify({
                "error": error or "Authentication required",
                "message": "Please login to access this resource"
            }), 401
        
        request.user = decoded
        request.user_id = decoded.get('RM_UserId')
        request.user_role = decoded.get('UserRole')
        request.user_email = decoded.get('email')
        request.user_name = decoded.get('name')
        
        return f(*args, **kwargs)
    
    return decorated_function

# def require_role(*allowed_roles):
#     def decorator(f):
#         @wraps(f)
#         def decorated_function(*args, **kwargs):
#             if not hasattr(request, 'user_role'):
#                 return jsonify({
#                     "error": "Authentication required",
#                     "message": "Please use @require_auth decorator first"
#                 }), 500
            
#             user_role = request.user_role
            
#             if user_role not in allowed_roles:
#                 return jsonify({
#                     "error": "Insufficient permissions",
#                     "message": f"Required role: {', '.join(allowed_roles)}. Your role: {user_role}"
#                 }), 403
            
#             return f(*args, **kwargs)
        
#         return decorated_function
#     return decorator

@app.route("/login")
@limiter.limit("5 per minute")
def login():
    frontend_redirect = FRONTEND_REDIRECT_URL
    state = str(uuid.uuid4())
    state_data = {
        'state': state,
        'frontend_redirect': frontend_redirect
    }
    encoded_state = base64.b64encode(json.dumps(state_data).encode()).decode()
    auth_url = build_msal_app().get_authorization_request_url(
        scopes=SCOPE,
        state=encoded_state,
        redirect_uri=REDIRECT_URI
    )
    safe_auth_url = escape(auth_url)
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Redirecting to Azure AD...</title>
        <meta http-equiv="refresh" content="0;url={safe_auth_url}">
        <link rel="icon" href="data:," />
    </head>
    <body>
        <p>Redirecting to Azure AD login...</p>
        <p>If you are not redirected automatically, <a href="{safe_auth_url}">click here</a></p>
    </body>
    </html>
    '''

@app.route("/redirect")
@limiter.limit("10 per minute")
def handle_redirect():
    code = request.args.get("code")
    encoded_state = request.args.get("state")
    if not code or not encoded_state:
        return "Missing code or state", 400
    try:
        state_data = json.loads(base64.b64decode(encoded_state).decode())
        frontend_redirect = state_data.get('frontend_redirect', FRONTEND_REDIRECT_URL)
    except Exception as e:
        logging.error(f"Error decoding state: {e}")
        frontend_redirect = FRONTEND_REDIRECT_URL
    result = build_msal_app().acquire_token_by_authorization_code(
        code,
        scopes=SCOPE,
        redirect_uri=REDIRECT_URI
    )
    if "access_token" in result:
        claims = result["id_token_claims"]
        email = claims.get("preferred_username")
        
        user_db_info = get_user_info_from_email(email)
        
        if not user_db_info or not user_db_info.get('RM_UserId'):
            error_message = "User not found in system or inactive. Please contact administrator."
            safe_frontend_redirect = escape(frontend_redirect)
            return f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login Failed</title>
                <link rel="icon" href="data:," />
            </head>
            <body>
                <h2>Login Failed</h2>
                <p>{escape(error_message)}</p>
                <p><a href="{safe_frontend_redirect}">Return to login</a></p>
            </body>
            </html>
            ''', 403
        
        user_info = {
            "name": claims.get("name"),
            "email": email,
            "oid": claims.get("oid"),
            "RM_UserId": user_db_info.get('RM_UserId'),
            "UserRole": user_db_info.get('UserRole'),
            "EgcaId": user_db_info.get('EgcaId'),
        }
        
        token = jwt.encode({
            **user_info,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_EXP_MINUTES)
        }, JWT_SECRET, algorithm="HS256")
        
        safe_frontend_redirect = escape(frontend_redirect)
        response = make_response(f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Redirecting...</title>
            <meta http-equiv="refresh" content="0;url={safe_frontend_redirect}">
            <link rel="icon" href="data:," />
        </head>
        <body>
            <p>Redirecting...</p>
            <p>If you are not redirected automatically, <a href="{safe_frontend_redirect}">click here</a></p>
        </body>
        </html>
        ''')
        
        response.set_cookie(
            key='auth_token',
            value=token,
            httponly=True,
            secure=True,
            samesite='None',
            max_age=JWT_EXP_MINUTES * 60,
            path='/'
        )
        
        return response
    return "Login failed", 401

@app.route("/auth/me", methods=['GET'])
def get_current_user():
    decoded, error = validate_token_from_cookie()
    
    if error or not decoded:
        return jsonify({
            "authenticated": False,
            "error": error or "Not authenticated"
        }), 401
    
    return jsonify({
        "authenticated": True,
        "user": {
            "email": decoded.get("email"),
            "name": decoded.get("name"),
            "RM_UserId": decoded.get("RM_UserId"),
            "UserRole": decoded.get("UserRole"),
            "EgcaId": decoded.get("EgcaId"),
            "oid": decoded.get("oid")
        }
    }), 200

@app.route("/logout")
def logout():
    frontend_redirect = FRONTEND_REDIRECT_URL
    logout_url = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/logout?post_logout_redirect_uri={frontend_redirect}'
    
    safe_logout_url = escape(logout_url)
    response = make_response(f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Redirecting to Azure AD...</title>
        <meta http-equiv="refresh" content="0;url={safe_logout_url}">
    </head>
    <body>
        <p>Redirecting to Azure AD logout...</p>
        <p>If you are not redirected automatically, <a href="{safe_logout_url}">click here</a></p>
    </body>
    </html>
    ''')
    
    response.set_cookie('auth_token', '', max_age=0, path='/')
    
    return response

@app.after_request
def add_security_headers(response):
  origin = request.headers.get('Origin')
  if origin and origin in ALLOWED_ORIGINS and 'Access-Control-Allow-Origin' in response.headers:
    response.headers['Access-Control-Allow-Credentials'] = 'true'

  response.headers['X-Frame-Options'] = 'DENY'
  response.headers['X-XSS-Protection'] = '1; mode=block'
  response.headers['X-Content-Type-Options'] = 'nosniff'
  response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
  response.headers['Referrer-Policy'] = 'origin'
  response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
  response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
  response.headers['Server'] = 'Flask'
  response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; frame-src 'self' blob: ;style-src 'self'; img-src 'self' blob: data: https:; font-src 'self'; connect-src 'self' blob: https://test-egca-api.airindiaexpress.com https://login.microsoftonline.com; frame-ancestors 'self' https://test-egca-api.airindiaexpress.com https://test-egca.airindiaexpress.com; form-action 'self'; base-uri 'self'"
  return response

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please try again later.",
        "code": 429
    }), 429

@app.errorhandler(Exception)
def exceptions(e):
    tb = traceback.format_exc()
    # Log URL, method, and error details for easier debugging
    url = request.url if request else 'Unknown URL'
    method = request.method if request else 'Unknown Method'
    endpoint = request.endpoint if request else 'Unknown Endpoint'
    logging.error(f"Internal error on {method} {url} (endpoint: {endpoint}): {tb}")

    return jsonify({
        "error": "An internal error occurred",
        "message": "Please contact support if this persists",
        "code": 500
    }), 500

app.register_blueprint(egca_aix_bp)

if __name__ == "__main__":
    import os
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 50300))
    
    print("Starting Flask development server...")
    print(f"Server will be available at http://{host}:{port}")
    print("NOTE: For production, use 'python run_production.py' instead")
    app.run(debug=False, host=host, port=port)
