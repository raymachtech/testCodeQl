# egca_aix_bp.py - Standalone Blueprint for SSE functionality
from functools import wraps
from flask import Blueprint, Response, request, jsonify, send_from_directory
import json
import threading
import sys
import logging

def debug_print(msg):
    """Print and flush immediately, also log"""
    # print(msg)
    sys.stdout.flush()
    logging.error(msg)  # Use error level so it always shows
    
from response_maker import error_response
from controller.elogController import (
    routeAdminFilters, routeAdminFlights, routeAdminHistory, routeAdminRosterChanges, routeAdminSubmission, routeChangeReasonEnum, routeCrewFlights, 
    routeCrewSubmitFlightLog, routeSubmitTLChanges, routeVerifyUser
)
from router.validators import (
    validate_positive_int, validate_non_negative_int, return_validation_error, validate_args,
    validate_required, validate_string, validate_date_format, validate_time_format, validate_id_list
)
from controller.notificationController import (
    routeGetNotifications, routeMarkNotifications, routePWASubscribe, routePWAUnsubscribe, 
    routePWAGetSubscriptions, sendPWANotification,
    getVAPIDPublicKey
)
from werkzeug.utils import secure_filename
import os
import uuid


def require_role(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'user_role'):
                return jsonify({
                    "error": "Authentication required",
                    "message": "Please use @require_auth decorator first"
                }), 500
            
            user_role = request.user_role
            
            if user_role not in allowed_roles:
                return jsonify({
                    "error": "Insufficient permissions",
                    "message": f"Required role: {', '.join(allowed_roles)}. Your role: {user_role}"
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def _trigger_async_notification():
    """Fire-and-forget helper to send push notifications without blocking request."""
    def _runner():
        try:
            sendPWANotification()
        except Exception as exc:
            # Log error without exposing exception details
            logging.error(f"[PWA Notification] Async send failed", exc_info=True)
    threading.Thread(target=_runner, daemon=True).start()

# Configuration
_current_file_dir = os.path.dirname(os.path.abspath(__file__))  # router/
FLASK_ROOT = os.path.dirname(_current_file_dir)  # flask/ (one level up from router/)
UPLOAD_FOLDER = os.path.join(FLASK_ROOT, 'static', 'uploads')  # flask/static/uploads (absolute path)
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf', 'docx'}
MAX_SIZE_MB = 10
# Ensure the upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Create a Blueprint for all '/aix_task' routes
egca_aix_bp = Blueprint('egca_aix', __name__, url_prefix='/egcaix')


# Define the '/aix_task' route inside the Blueprint
@egca_aix_bp.route('/')
def default():
    return {"message": "Connected to E-LOG API", "status": "success", "code": 200, "endpoint": "default"}

@egca_aix_bp.route('/pool-stats', methods=['GET'])
def get_pool_stats():
    """Get connection pool statistics for monitoring"""
    try:
        from database.db_pool import get_egca_pool
        egca_pool = get_egca_pool()
        
        return jsonify({
            "status": "success",
            "code": 200,
            "pools": {
                "egca": egca_pool.get_stats()
            }
        })
    except Exception as e:
        return error_response("An internal error occurred", 500, e, "pool_stats endpoint")


# @egca_aix_bp.route('/userVerification', methods=['GET'])
# def getVerifyUser():
#     UserEmail = request.args.get('UserEmail', None)
#     DeviceInfo = request.args.get('DeviceInfo', None)
#     return routeVerifyUser(UserEmail,DeviceInfo) 


@egca_aix_bp.route('/crewFlights', methods=['GET'])
@require_role('PILOT')
def getCrewFlights():
    """
    Get crew flights for the authenticated user.
    Uses request.user_id from authentication middleware (security: users can only see their own flights).
    """
    # Security: Use authenticated user's ID from middleware ONLY - never accept from user input
    if not hasattr(request, 'user_id') or not request.user_id:
        return return_validation_error("User authentication required", 401)
    
    RM_UserId = request.user_id
    
    # Validate optional parameters (concise validation)
    error, vals = validate_args(
        SubmissionId=(request.args.get('SubmissionId', None), validate_positive_int, 'SubmissionId'),
        LastDays=(request.args.get('LastDays', None), validate_non_negative_int, 'LastDays', 365),
        NextDays=(request.args.get('NextDays', None), validate_non_negative_int, 'NextDays', 365)
    )
    if error: return error
    SubmissionId, LastDays, NextDays = vals['SubmissionId'], vals['LastDays'], vals['NextDays']
    
    return routeCrewFlights(RM_UserId, SubmissionId, LastDays, NextDays)




@egca_aix_bp.route('/changeReasonEnum', methods=['GET'])
@require_role('PILOT')
def getChangeReasonEnum():
    return routeChangeReasonEnum() 

@egca_aix_bp.route('/uploadTechLog', methods=['POST'])
@require_role('PILOT')
def uploadTechLogURL():
    """
    Upload tech log file. Validates file presence, size, type, and filename security.
    """
    # Check if 'file' key exists
    if 'file' not in request.files:
        return return_validation_error('No file part in request')

    file = request.files['file']

    # Check if file was actually selected
    if not file or file.filename == '':
        return return_validation_error('No file selected')

    # Validate filename length (prevent extremely long filenames)
    if len(file.filename) > 255:  # Standard filesystem limit
        return return_validation_error('Filename exceeds maximum length of 255 characters')

    # Validate filename for path traversal attempts
    if '..' in file.filename or '/' in file.filename or '\\' in file.filename:
        return return_validation_error('Invalid filename: path traversal not allowed')

    # Check file size manually (in bytes)
    file.seek(0, os.SEEK_END)  # move to end of file
    file_size = file.tell()    # get current position = size
    file.seek(0)               # reset pointer for saving

    if file_size == 0:
        return return_validation_error('File is empty')

    if file_size > MAX_SIZE_MB * 1024 * 1024:
        return return_validation_error(f'File exceeds {MAX_SIZE_MB} MB limit', 413)

    # Validate file extension
    if not allowed_file(file.filename):
        allowed_extensions = ', '.join(ALLOWED_EXTENSIONS)
        return return_validation_error(f'File type not allowed. Allowed types: {allowed_extensions}')

    # Validate and save file
    try:
        filename = secure_filename(file.filename)
        if not filename:  # secure_filename returns empty string for invalid filenames
            return return_validation_error('Invalid filename format')
        
        unique_name = f"{uuid.uuid4().hex}_{filename}"  # Add random ID for uniqueness
        save_path = os.path.join(UPLOAD_FOLDER, unique_name)
        file.save(save_path)

        return jsonify({
            'status': 'success',
            'message': 'File uploaded successfully',
            'file_url': unique_name
        }), 200
    except Exception as e:
        return error_response("File upload failed", 500, e, "file upload")


@egca_aix_bp.route('/getTechLog/<filename>', methods=['GET'])
# @require_role('PILOT')
def get_techlog(filename):
    """
    Get tech log file by filename. Validates filename security and prevents path traversal.
    """
    # Validate filename is not empty
    if not filename or filename.strip() == '':
        return return_validation_error('Filename is required')
    
    # Validate filename length
    if len(filename) > 255:
        return return_validation_error('Filename exceeds maximum length of 255 characters')
    
    # Validate filename for path traversal attempts
    if '..' in filename or '/' in filename or '\\' in filename:
        return return_validation_error('Invalid filename: path traversal not allowed')
    
    try:
        # Ensure filename is safe (sanitizes filename)
        safe_filename = secure_filename(filename)
        
        # Check if secure_filename returned empty (invalid filename)
        if not safe_filename:
            return return_validation_error('Invalid filename format')
        
        # Additional check: ensure sanitized filename matches original (no path components)
        if safe_filename != filename:
            # This could indicate path traversal attempt or invalid characters
            # For security, we'll use the sanitized version but log the mismatch
            pass
        
        return send_from_directory(UPLOAD_FOLDER, safe_filename)
    except FileNotFoundError:
        return return_validation_error('File not found', 404)
    except Exception as e:
        return error_response("Error retrieving file", 500, e, "file retrieval")


@egca_aix_bp.route('/crewSubmitFlightLog', methods=['POST'])
@require_role('PILOT')
def postCrewSubmitFlightLog():
    """
    Submit crew flight log. Validates all required fields, enums, dates, times, and string lengths.
    Uses authenticated user's RM_UserId from middleware (security).
    """
    # Get JSON data from request body first
    if not request.is_json:
        return return_validation_error("Request must be JSON")
    
    data = request.get_json()
    if not data:
        return return_validation_error("Request body is empty")
    
    # Security: Use authenticated user's ID from middleware ONLY - never accept from user input
    if not hasattr(request, 'user_id') or not request.user_id:
        return return_validation_error("User authentication required", 401)
    
    RM_UserId = request.user_id
    
    # Extract all required parameters for fsp_CrewSubmitFlightLog
    FlightLegId = data.get('FlightLegId', None)
    FlightKey = data.get('FlightKey', None)
    CrewPosition = data.get('CrewPosition', None)  # 'PIC' or 'COPILOT'
    CrewAction = data.get('CrewAction', None)      # 'APPROVE' or 'REJECT'

    # Basic flight info
    FlightDate = data.get('FlightDate', None)
    FlightNumber = data.get('FlightNumber', None)
    TailNumber = data.get('TailNumber', None)
    Origin = data.get('Origin', None)
    Destination = data.get('Destination', None)

    DepatureTime = data.get('DepatureTime', None)
    ArrivalTime = data.get('ArrivalTime', None)
    InstrumentTime = data.get('InstrumentTime', None)
    
    # Flight Times
    FlightTimeDay = data.get('FlightTimeDay', None)
    FlightTimeNight = data.get('FlightTimeNight', None)
    FlightTimeBoth = data.get('FlightTimeBoth', None)
    DistanceNM = data.get('DistanceNM', None)

    # Submitted flight data
    ChocksOff = data.get('ChocksOff', None)
    ChocksOn = data.get('ChocksOn', None)
    Takeoff = data.get('Takeoff', None)
    Touchdown = data.get('Touchdown', None)

    # PIC and CoPilot Information
    PicId = data.get('PicId', None)
    PicName = data.get('PicName', None)
    CopilotId = data.get('CopilotId', None)
    CopilotName = data.get('CopilotName', None)

    # Original Takeoff and Landing Pilot Information
    OrginalTakeoffPilotId = data.get('OrginalTakeoffPilotId', None)
    OrginalTakeoffPilotName = data.get('OrginalTakeoffPilotName', None)
    OrginalLandingPilotId = data.get('OrginalLandingPilotId', None)
    OrginalLandingPilotName = data.get('OrginalLandingPilotName', None)

    # Misc
    CrewRemarks = data.get('CrewRemarks', None)
    RejectionReason = data.get('RejectionReason', None)
    RejectionCode = data.get('RejectionCode', None)
    TechLogUrl = data.get('TechLogUrl', None)
    
    # Additional flight info
    DutyCode = data.get('DutyCode', None)
    ServiceTypeCode = data.get('ServiceTypeCode', None)

    # Validate required fields (based on SP: fsp_PilotSubmitFlightLog)
    # Required: FlightLegId, FlightKey, CrewPosition, CrewAction, FlightDate, DepatureTime, ArrivalTime, FlightNumber
    for value, field_name in [
        (FlightLegId, 'FlightLegId'), (FlightKey, 'FlightKey'), 
        (CrewPosition, 'CrewPosition'), (CrewAction, 'CrewAction'),
        (FlightDate, 'FlightDate'), (DepatureTime, 'DepatureTime'),
        (ArrivalTime, 'ArrivalTime'), (FlightNumber, 'FlightNumber')
    ]:
        is_valid, error_msg = validate_required(value, field_name)
        if not is_valid:
            return return_validation_error(error_msg)
    
    # Validate enums
    if CrewPosition not in ['PIC', 'COPILOT']:
        return return_validation_error("CrewPosition must be 'PIC' or 'COPILOT'")
    if CrewAction not in ['APPROVE', 'REJECT']:
        return return_validation_error("CrewAction must be 'APPROVE' or 'REJECT'")
    
    # Validate FlightLegId (BIGINT - positive integer)
    error, vals = validate_args(FlightLegId=(FlightLegId, validate_positive_int, 'FlightLegId'))
    if error: return error
    FlightLegId = vals['FlightLegId']
    

    if CrewAction == 'REJECT' and RejectionCode:
        # RejectionCode is required for REJECT action
        is_valid, error_msg = validate_required(RejectionCode, 'RejectionCode')
        if not is_valid:
            return return_validation_error(error_msg)
        error, vals = validate_args(RejectionCode=(RejectionCode, validate_positive_int, 'RejectionCode'))
        if error: return error
        RejectionCode = vals['RejectionCode']

    
    # Validate string lengths (based on SP parameters)
    error, vals = validate_args(
        FlightKey=(FlightKey, validate_string, 'FlightKey', 50),
        FlightNumber=(FlightNumber, validate_string, 'FlightNumber', 20)
    )
    if error: return error
    FlightKey, FlightNumber = vals['FlightKey'], vals['FlightNumber']
    
    # Validate optional strings with correct max lengths (from SP)
    for field_name, value, max_len in [
        ('TailNumber', TailNumber, 20), ('Origin', Origin, 10), ('Destination', Destination, 10),
        ('PicId', PicId, 50), ('PicName', PicName, 100), ('CopilotId', CopilotId, 50),
        ('CopilotName', CopilotName, 100), ('RejectionReason', RejectionReason, 100),
        ('CrewRemarks', CrewRemarks, 500),  # SP allows NVARCHAR(500)
        ('OrginalTakeoffPilotId', OrginalTakeoffPilotId, 50),
        ('OrginalTakeoffPilotName', OrginalTakeoffPilotName, 100),
        ('OrginalLandingPilotId', OrginalLandingPilotId, 50),
        ('OrginalLandingPilotName', OrginalLandingPilotName, 100),
        ('FlightTimeDay', FlightTimeDay, 20), ('FlightTimeNight', FlightTimeNight, 20),
        ('FlightTimeBoth', FlightTimeBoth, 20), ('InstrumentTime', InstrumentTime, 20),
        ('ServiceTypeCode', DutyCode, 20), ('ServiceTypeCode', ServiceTypeCode, 20),

    ]:
        if value:
            is_valid, error_msg, validated = validate_string(value, field_name, max_length=max_len)
            if not is_valid:
                return return_validation_error(error_msg)
    
    # Validate TechLogUrl (NVARCHAR(MAX) - no length limit, but validate it's a string)
    if TechLogUrl:
        is_valid, error_msg, validated = validate_string(TechLogUrl, 'TechLogUrl')
        if not is_valid:
            return return_validation_error(error_msg)
    
    # Validate date format (DATE)
    is_valid, error_msg = validate_date_format(FlightDate, 'FlightDate')
    if not is_valid:
        return return_validation_error(error_msg)
    
    # Validate DateTime formats for DepatureTime and ArrivalTime (required)
    # SP expects DateTime, table shows full DATETIME format (YYYY-MM-DD HH:MM:SS)
    # Frontend might send ISO format or separate date/time - validate both
    for dt_value, field_name in [(DepatureTime, 'DepatureTime'), (ArrivalTime, 'ArrivalTime')]:
        if not isinstance(dt_value, str):
            return return_validation_error(f"{field_name} must be a valid date-time string")
        # Try to parse ISO format datetime or SQL Server datetime format
        try:
            from datetime import datetime
            # Try ISO format first
            try:
                datetime.fromisoformat(dt_value.replace('Z', '+00:00'))
            except ValueError:
                # Try SQL Server format: YYYY-MM-DD HH:MM:SS
                datetime.strptime(dt_value, '%Y-%m-%d %H:%M:%S')
        except (ValueError, AttributeError):
            return return_validation_error(f"{field_name} must be in datetime format (YYYY-MM-DD HH:MM:SS or ISO format)")
    
    # Validate time formats (TIME - HH:MM) - optional fields
    # Table shows TIME format stored as HH:MM (e.g., "22:29", "03:25", "00:00")
    # SP expects TIME type, frontend sends as string HH:MM
    for time_value, field_name in [
        (ChocksOff, 'ChocksOff'), (ChocksOn, 'ChocksOn'),
        (Takeoff, 'Takeoff'), (Touchdown, 'Touchdown')
    ]:
        if time_value:
            is_valid, error_msg = validate_time_format(time_value, field_name)
            if not is_valid:
                return return_validation_error(error_msg)
    
    # Validate optional time fields (stored as NVARCHAR(20) in SP, displayed as TIME in table)
    # These are flight time durations: flightTimeDay, flightTimeNight, flightTimeBoth, InstrumentTime
    for time_value, field_name in [
        (FlightTimeDay, 'FlightTimeDay'), (FlightTimeNight, 'FlightTimeNight'),
        (FlightTimeBoth, 'FlightTimeBoth'), (InstrumentTime, 'InstrumentTime')
    ]:
        if time_value:
            # These can be TIME format (HH:MM) or might be duration strings
            # Validate as TIME format (HH:MM)
            is_valid, error_msg = validate_time_format(time_value, field_name)
            if not is_valid:
                return return_validation_error(error_msg)
    
    # Validate optional numeric fields
    # DistanceNM is INT, can be NULL (table shows NULL values)
    if DistanceNM is not None:
        error, vals = validate_args(DistanceNM=(DistanceNM, validate_non_negative_int, 'DistanceNM'))
        if error: return error
        DistanceNM = vals['DistanceNM']
    
    # Call the route function with all parameters
    response = routeCrewSubmitFlightLog(
        FlightLegId=FlightLegId,
    FlightKey=FlightKey,
    RM_UserId=RM_UserId,
    CrewPosition=CrewPosition,
    CrewAction=CrewAction,
    FlightDate=FlightDate,
    FlightNumber=FlightNumber,
    TailNumber=TailNumber,
    Origin=Origin,
    Destination=Destination,
    DepatureTime=DepatureTime,
    ArrivalTime=ArrivalTime,
    InstrumentTime=InstrumentTime,
    FlightTimeDay=FlightTimeDay,
    FlightTimeNight=FlightTimeNight,
	FlightTimeBoth=FlightTimeBoth,
    DistanceNM=DistanceNM,
    ChocksOff=ChocksOff,
    ChocksOn=ChocksOn,
    Takeoff=Takeoff,
    Touchdown=Touchdown,
    PicId=PicId,
    PicName=PicName,
    CopilotId=CopilotId,
    CopilotName=CopilotName,
    OrginalTakeoffPilotId=OrginalTakeoffPilotId,
    OrginalTakeoffPilotName=OrginalTakeoffPilotName,
    OrginalLandingPilotId=OrginalLandingPilotId,
    OrginalLandingPilotName=OrginalLandingPilotName,
    CrewRemarks=CrewRemarks,
    RejectionReason=RejectionReason,
    RejectionCode=RejectionCode,
    TechLogUrl = TechLogUrl,
    DutyCode=DutyCode,
    ServiceTypeCode=ServiceTypeCode
    )
    
    # Check if response indicates error
    if isinstance(response, dict) and response.get('status') == 'error':
        return jsonify(response), response.get('code', 400)
    
    # _trigger_async_notification()
    # sendPWANotification()
    # Run notification in background thread (non-blocking) - prevents 1.5min delay
    def send_notifications_async():
        try:
            sendPWANotification()
        except Exception as e:
            debug_print(f"[sendPWANotification] Background error: {e}")
    notification_thread = threading.Thread(target=send_notifications_async, daemon=True)
    notification_thread.start()
    return jsonify(response) if isinstance(response, dict) else response

@egca_aix_bp.route('/submitTLChanges', methods=['POST'])
@require_role('PILOT')
def postSubmitTLChanges():
    """
    Submit Takeoff/Landing pilot changes. Validates all required fields.
    Uses authenticated user's RM_UserId from middleware (security).
    """
    # Get JSON data from request body
    if not request.is_json:
        return return_validation_error("Request must be JSON")
    data = request.get_json()
    if not data:
        return return_validation_error("Request body is empty")
    # Security: Use authenticated user's ID from middleware ONLY
    if not hasattr(request, 'user_id') or not request.user_id:
        return return_validation_error("User authentication required", 401)
    RM_UserId = request.user_id
    # Extract parameters
    SubmissionId = data.get('SubmissionId', None)
    FlightKey = data.get('FlightKey', None)
    # Original pilot info
    OrginalTakeoffPilotId = data.get('OrginalTakeoffPilotId', None)
    OrginalTakeoffPilotName = data.get('OrginalTakeoffPilotName', None)
    OrginalLandingPilotId = data.get('OrginalLandingPilotId', None)
    OrginalLandingPilotName = data.get('OrginalLandingPilotName', None)
    # Submitted pilot info
    SubmittedTakeoffPilotId = data.get('SubmittedTakeoffPilotId', None)
    SubmittedTakeoffPilotName = data.get('SubmittedTakeoffPilotName', None)
    SubmittedLandingPilotId = data.get('SubmittedLandingPilotId', None)
    SubmittedLandingPilotName = data.get('SubmittedLandingPilotName', None)
    # Validate required fields (SubmissionId is optional - may not exist before crewSubmitFlightLog)
    for value, field_name in [
        (FlightKey, 'FlightKey'),
        (SubmittedTakeoffPilotId, 'SubmittedTakeoffPilotId'),
        (SubmittedTakeoffPilotName, 'SubmittedTakeoffPilotName'),
        (SubmittedLandingPilotId, 'SubmittedLandingPilotId'),
        (SubmittedLandingPilotName, 'SubmittedLandingPilotName')
    ]:
        is_valid, error_msg = validate_required(value, field_name)
        if not is_valid:
            return return_validation_error(error_msg)
    # Validate SubmissionId if provided (INT - positive integer, optional)
    if SubmissionId is not None:
        error, vals = validate_args(SubmissionId=(SubmissionId, validate_positive_int, 'SubmissionId'))
        if error: return error
        SubmissionId = vals['SubmissionId']
    # Validate string lengths
    error, vals = validate_args(
        FlightKey=(FlightKey, validate_string, 'FlightKey', 50),
        OrginalTakeoffPilotId=(OrginalTakeoffPilotId, validate_string, 'OrginalTakeoffPilotId', 50),
        OrginalTakeoffPilotName=(OrginalTakeoffPilotName, validate_string, 'OrginalTakeoffPilotName', 100),
        OrginalLandingPilotId=(OrginalLandingPilotId, validate_string, 'OrginalLandingPilotId', 50),
        OrginalLandingPilotName=(OrginalLandingPilotName, validate_string, 'OrginalLandingPilotName', 100),
        SubmittedTakeoffPilotId=(SubmittedTakeoffPilotId, validate_string, 'SubmittedTakeoffPilotId', 50),
        SubmittedTakeoffPilotName=(SubmittedTakeoffPilotName, validate_string, 'SubmittedTakeoffPilotName', 100),
        SubmittedLandingPilotId=(SubmittedLandingPilotId, validate_string, 'SubmittedLandingPilotId', 50),
        SubmittedLandingPilotName=(SubmittedLandingPilotName, validate_string, 'SubmittedLandingPilotName', 100)
    )
    if error: return error
    FlightKey = vals['FlightKey']
    OrginalTakeoffPilotId = vals.get('OrginalTakeoffPilotId')
    OrginalTakeoffPilotName = vals.get('OrginalTakeoffPilotName')
    OrginalLandingPilotId = vals.get('OrginalLandingPilotId')
    OrginalLandingPilotName = vals.get('OrginalLandingPilotName')
    SubmittedTakeoffPilotId = vals.get('SubmittedTakeoffPilotId')
    SubmittedTakeoffPilotName = vals.get('SubmittedTakeoffPilotName')
    SubmittedLandingPilotId = vals.get('SubmittedLandingPilotId')
    SubmittedLandingPilotName = vals.get('SubmittedLandingPilotName')
    # Call the controller function
    response = routeSubmitTLChanges(
        SubmissionId, FlightKey,
        OrginalTakeoffPilotId, OrginalTakeoffPilotName, OrginalLandingPilotId, OrginalLandingPilotName,
        SubmittedTakeoffPilotId, SubmittedTakeoffPilotName, SubmittedLandingPilotId, SubmittedLandingPilotName,
        RM_UserId
    )
    # Check if response indicates error
    if isinstance(response, dict) and response.get('status') == 'error':
        return jsonify(response), response.get('code', 400)
    return jsonify(response) if isinstance(response, dict) else response   



@egca_aix_bp.route('/adminFlights', methods=['GET'])
@require_role('ADMIN')
def getAdminFlights():
    """
    Get admin flights data. Validates LastDays and NextDays parameters.
    Admin-only endpoint (should check role in production).
    """
    # Validate optional parameters
    LastDays = request.args.get('LastDays', 30)
    NextDays = request.args.get('NextDays', 0)
    PageNumber = request.args.get('PageNumber', 0)
    # Filter parameters (optional)
    RejectionType = request.args.get('RejectionType', None)
    TailNumber = request.args.get('TailNumber', None)
    FlightNumber = request.args.get('FlightNumber', None)
    Pilot = request.args.get('Pilot', None)
    EntryBy = request.args.get('EntryBy', None)
    SubmissionId = request.args.get('SubmissionId', None)
    # Validate LastDays (optional, but if provided must be non-negative integer, max 365)
    error, vals = validate_args(
        LastDays=(LastDays, validate_non_negative_int, 'LastDays', 365),
        NextDays=(NextDays, validate_non_negative_int, 'NextDays', 365),
        PageNumber=(PageNumber, validate_non_negative_int, 'PageNumber', 500),
        SubmissionId=(SubmissionId, validate_non_negative_int, 'SubmissionId', 50000)
    )
    if error: return error
    LastDays, NextDays, PageNumber,SubmissionId = vals['LastDays'], vals['NextDays'], vals['PageNumber'],vals['SubmissionId']
    # Validate optional string parameters
    for field_name, value, max_len in [
        ('RejectionType', RejectionType, 10),
        ('TailNumber', TailNumber, 20),
        ('FlightNumber', FlightNumber, 20),
        ('Pilot', Pilot, 70),
        ('EntryBy', EntryBy, 10)
    ]:
        if value:
            is_valid, error_msg, validated = validate_string(value, field_name, max_length=max_len)
            if not is_valid:
                return return_validation_error(error_msg)
    return routeAdminFlights(LastDays, NextDays, PageNumber,SubmissionId, RejectionType, TailNumber, FlightNumber, Pilot,EntryBy)

@egca_aix_bp.route('/adminFilters', methods=['GET'])
@require_role('ADMIN')
def getAdminFilters():
    """
    Get admin filtered flights data.
    Admin-only endpoint for filtered search.
    """
    # Validate optional parameters
    LastDays = request.args.get('LastDays', 30)
    NextDays = request.args.get('NextDays', 0)
    # Filter parameters (optional)
    RejectionType = request.args.get('RejectionType', None)
    TailNumber = request.args.get('TailNumber', None)
    FlightNumber = request.args.get('FlightNumber', None)
    Pilot = request.args.get('Pilot', None)
    EntryBy = request.args.get('EntryBy', None)
    # Validate numeric parameters
    error, vals = validate_args(
        LastDays=(LastDays, validate_non_negative_int, 'LastDays', 365),
        NextDays=(NextDays, validate_non_negative_int, 'NextDays', 365)
    )
    if error: return error
    LastDays, NextDays = vals['LastDays'], vals['NextDays']
    # Validate optional string parameters
    for field_name, value, max_len in [
        ('RejectionType', RejectionType, 50),
        ('TailNumber', TailNumber, 20),
        ('FlightNumber', FlightNumber, 20),
        ('Pilot', Pilot, 70),
        ('EntryBy', EntryBy, 10)
    ]:
        if value:
            is_valid, error_msg, validated = validate_string(value, field_name, max_length=max_len)
            if not is_valid:
                return return_validation_error(error_msg)
    return routeAdminFilters(LastDays, NextDays, RejectionType, TailNumber, FlightNumber, Pilot,EntryBy)


@egca_aix_bp.route('/adminHistory', methods=['GET'])
@require_role('ADMIN')
def getHistoryFlights():
    RM_UserId = request.user_id
    PageNumber = request.args.get('PageNumber', 1)
    # Validate LastDays (optional, but if provided must be non-negative integer, max 365)
    error, vals = validate_args(PageNumber=(PageNumber, validate_non_negative_int, 'PageNumber', 500))
    if error: return error
    PageNumber = vals['PageNumber']
    return routeAdminHistory(RM_UserId,PageNumber)


# @egca_aix_bp.route('/adminFlights', methods=['GET'])
# def getAdminFlights():
#     """
#     Get admin flights data. Validates LastDays and NextDays parameters.
#     Admin-only endpoint (should check role in production).
#     """
#     # Validate optional parameters
#     LastDays = request.args.get('LastDays', 14)
#     NextDays = request.args.get('NextDays', 0)
    
#     # Validate LastDays (optional, but if provided must be non-negative integer, max 365)
#     error, vals = validate_args(
#         LastDays=(LastDays, validate_non_negative_int, 'LastDays', 365),
#         NextDays=(NextDays, validate_non_negative_int, 'NextDays', 365)
#     )
#     if error: return error
#     LastDays, NextDays = vals['LastDays'], vals['NextDays']
    
#     return routeAdminFlights(LastDays, NextDays)

@egca_aix_bp.route('/adminRosterChanges', methods=['GET'])
@require_role('ADMIN')
def getRosterChanges():
    """
    Get admin roster changes for a specific submission.
    Validates SubmissionId parameter.
    """
    SubmissionId = request.args.get('SubmissionId', None)
    
    # Validate SubmissionId (required, must be positive integer)
    if SubmissionId is None:
        return return_validation_error("SubmissionId is required")
    
    error, vals = validate_args(SubmissionId=(SubmissionId, validate_positive_int, 'SubmissionId'))
    if error: return error
    SubmissionId = vals['SubmissionId']
    
    return routeAdminRosterChanges(SubmissionId)

@egca_aix_bp.route('/adminSubmission', methods=['POST'])
@require_role('ADMIN')
def postAdminSubmission():
    """
    Admin process submission. Validates all required fields, enums, times, and string lengths.
    Uses authenticated user's RM_UserId from middleware (security).
    """
    # Get JSON data from request body
    if not request.is_json:
        return return_validation_error("Request must be JSON")
    
    data = request.get_json()
    if not data:
        return return_validation_error("Request body is empty")
    
    # Security: Use authenticated user's ID from middleware ONLY - never accept from user input
    if not hasattr(request, 'user_id') or not request.user_id:
        return return_validation_error("User authentication required", 401)
    
    RM_UserId = request.user_id
    
    # Extract all required parameters for fsp_AdminProcessSubmission
    SubmissionId = data.get('SubmissionId', None)
    AdminAction = data.get('AdminAction', None)
    AdminRemarks = data.get('AdminRemarks', None)
    
    AdminChocksOff = data.get('AdminChocksOff', None)
    AdminChocksOn = data.get('AdminChocksOn', None)
    AdminTakeoff = data.get('AdminTakeoff', None)
    AdminTouchdown = data.get('AdminTouchdown', None)
    
    AdminTakeoffPilotId = data.get('AdminTakeoffPilotId', None)
    AdminTakeoffPilotName = data.get('AdminTakeoffPilotName', None)
    AdminLandingPilotId = data.get('AdminLandingPilotId', None)
    AdminLandingPilotName = data.get('AdminLandingPilotName', None)
    
    AdminTailNumber = data.get('AdminTailNumber', None)
    
    # Validate required fields
    for value, field_name in [
        (SubmissionId, 'SubmissionId'),
        (AdminAction, 'AdminAction')
    ]:
        is_valid, error_msg = validate_required(value, field_name)
        if not is_valid:
            return return_validation_error(error_msg)
    
    # Validate AdminAction enum (likely 'APPROVE' or 'REJECT' based on similar patterns)
    if AdminAction not in ['APPROVE', 'REJECT']:
        return return_validation_error("AdminAction must be 'APPROVE' or 'REJECT'")
    
    # Validate SubmissionId (INT - positive integer)
    error, vals = validate_args(SubmissionId=(SubmissionId, validate_positive_int, 'SubmissionId'))
    if error: return error
    SubmissionId = vals['SubmissionId']
    if not hasattr(request, 'user_id'):
        error, vals = validate_args(RM_UserId=(RM_UserId, validate_positive_int, 'RM_UserId'))
        if error: return error
        RM_UserId = vals['RM_UserId']
    
    # Validate optional string fields with max lengths
    error, vals = validate_args(
        AdminRemarks=(AdminRemarks, validate_string, 'AdminRemarks', 500),
        AdminTailNumber=(AdminTailNumber, validate_string, 'AdminTailNumber', 20),
        AdminTakeoffPilotId=(AdminTakeoffPilotId, validate_string, 'AdminTakeoffPilotId', 50),
        AdminTakeoffPilotName=(AdminTakeoffPilotName, validate_string, 'AdminTakeoffPilotName', 100),
        AdminLandingPilotId=(AdminLandingPilotId, validate_string, 'AdminLandingPilotId', 50),
        AdminLandingPilotName=(AdminLandingPilotName, validate_string, 'AdminLandingPilotName', 100)
    )
    if error: return error
    AdminRemarks = vals.get('AdminRemarks')
    AdminTailNumber = vals.get('AdminTailNumber')
    AdminTakeoffPilotId = vals.get('AdminTakeoffPilotId')
    AdminTakeoffPilotName = vals.get('AdminTakeoffPilotName')
    AdminLandingPilotId = vals.get('AdminLandingPilotId')
    AdminLandingPilotName = vals.get('AdminLandingPilotName')
    
    # Validate optional time fields (TIME format - HH:MM)
    for time_value, field_name in [
        (AdminChocksOff, 'AdminChocksOff'),
        (AdminChocksOn, 'AdminChocksOn'),
        (AdminTakeoff, 'AdminTakeoff'),
        (AdminTouchdown, 'AdminTouchdown')
    ]:
        if time_value:
            is_valid, error_msg = validate_time_format(time_value, field_name)
            if not is_valid:
                return return_validation_error(error_msg)
    
    # Call the route function with all validated parameters
    response = routeAdminSubmission(
        SubmissionId, RM_UserId, AdminAction, AdminRemarks,
        AdminChocksOff, AdminChocksOn, AdminTakeoff, AdminTouchdown,
        AdminTakeoffPilotId, AdminTakeoffPilotName, AdminLandingPilotId, AdminLandingPilotName, AdminTailNumber
    )
    
    # Check if response indicates error
    if isinstance(response, dict) and response.get('status') == 'error':
        return jsonify(response), response.get('code', 400)
    
    # _trigger_async_notification()
    # sendPWANotification()

    # Run notification in background thread (non-blocking) - prevents 1.5min delay
    def send_notifications_async():
        try:
            sendPWANotification()
        except Exception as e:
            debug_print(f"[sendPWANotification] Background error: {e}")
    notification_thread = threading.Thread(target=send_notifications_async, daemon=True)
    notification_thread.start()
    
    return jsonify(response) if isinstance(response, dict) else response

 
@egca_aix_bp.route('/getNotifications', methods=['GET'])
def getNotifications():
    """
    Get notifications for a user. Validates RM_UserId parameter.
    Uses authenticated user's RM_UserId from middleware (security).
    """
    # Security: Use authenticated user's ID from middleware ONLY - never accept from user input
    if not hasattr(request, 'user_id') or not request.user_id:
        return return_validation_error("User authentication required", 401)
    
    RM_UserId = request.user_id
    
    return routeGetNotifications(RM_UserId)

@egca_aix_bp.route('/markNotifications', methods=['POST'])
def markNotifications():
    """
    Mark notifications as read/processed. Validates Id parameter.
    """
    # Get JSON data from request body
    if not request.is_json:
        return return_validation_error("Request must be JSON")
    
    data = request.get_json()
    if not data:
        return return_validation_error("Request body is empty")
    Id = data.get('Id', None)

    # Validate Id (required, can be single ID or comma-separated list)
    is_valid, error_msg, validated_ids = validate_id_list(Id, 'Id')
    if not is_valid:
        return return_validation_error(error_msg)
    return routeMarkNotifications(validated_ids)
     



@egca_aix_bp.route('/getVapidKey', methods=['GET'])
def get_vapid_public_key():
    """Return the VAPID public key for client-side subscription"""
    return jsonify({
        'publicKey': getVAPIDPublicKey()
    })


@egca_aix_bp.route('/subscribeNotification', methods=['POST'])
def subscribeNotification():
    """
    Register a push subscription. Validates subscription data, endpoint, and keys.
    Uses authenticated user's RM_UserId from middleware (security).
    """
    # Get JSON data from request body
    if not request.is_json:
        return return_validation_error("Request must be JSON")
    
    try:
        NotificationData = request.get_json()
        if not NotificationData:
            return return_validation_error("Request body is empty")
        
        # Security: Use authenticated user's ID from middleware ONLY - never accept from user input
        if not hasattr(request, 'user_id') or not request.user_id:
            return return_validation_error("User authentication required", 401)
        
        RM_UserId = request.user_id
        
        subscription_data = NotificationData.get('subscription_data', None)
        
        # Validate subscription_data is present and is a dict
        if not subscription_data:
            return return_validation_error("subscription_data is required")
        
        if not isinstance(subscription_data, dict):
            return return_validation_error("subscription_data must be an object")
        
        # Validate endpoint (required, must be a valid URL string)
        endpoint = subscription_data.get('endpoint', None)
        is_valid, error_msg = validate_required(endpoint, 'endpoint')
        if not is_valid:
            return return_validation_error(error_msg)
        
        # Validate endpoint is a string and looks like a URL
        if not isinstance(endpoint, str) or len(endpoint.strip()) == 0:
            return return_validation_error("endpoint must be a non-empty string")
        
        if len(endpoint) > 500:  # Reasonable max length for URL
            return return_validation_error("endpoint exceeds maximum length of 500 characters")
        
        if not endpoint.startswith('https://'):
            endpoint = 'https://'+ endpoint
            # return return_validation_error("endpoint must be a valid HTTPS URL")
        
        endpoint = endpoint.strip()
        
        # Validate keys object
        keys = subscription_data.get('keys', None)
        if not keys:
            return return_validation_error("keys object is required in subscription_data")
        
        if not isinstance(keys, dict):
            return return_validation_error("keys must be an object")
        
        # Validate p256dh_key (required)
        p256dh_key = keys.get('p256dh', None)
        is_valid, error_msg = validate_required(p256dh_key, 'p256dh')
        if not is_valid:
            return return_validation_error(error_msg)
        
        if not isinstance(p256dh_key, str) or len(p256dh_key.strip()) == 0:
            return return_validation_error("p256dh must be a non-empty string")
        
        # if len(p256dh_key) > 500:  # Base64 encoded key can be long
        #     return return_validation_error("p256dh exceeds maximum length of 500 characters")
        
        p256dh_key = p256dh_key.strip()
        
        # Validate auth_key (required)
        auth_key = keys.get('auth', None)
        is_valid, error_msg = validate_required(auth_key, 'auth')
        if not is_valid:
            return return_validation_error(error_msg)
        
        if not isinstance(auth_key, str) or len(auth_key.strip()) == 0:
            return return_validation_error("auth must be a non-empty string")
        
        if len(auth_key) > 500:  # Base64 encoded key can be long
            return return_validation_error("auth exceeds maximum length of 500 characters")
        
        auth_key = auth_key.strip()
        
        # Validate expirationTime (optional, must be ISO format if provided)
        expirationTime = subscription_data.get('expirationTime', None)
        expiration_datetime = None
        if expirationTime:
            if not isinstance(expirationTime, (str, int)):
                return return_validation_error("expirationTime must be a string or number")
            
            try:
                from datetime import datetime
                if isinstance(expirationTime, str):
                    expiration_datetime = datetime.fromisoformat(expirationTime.replace('Z', '+00:00'))
                else:
                    # If it's a timestamp (number), convert to datetime
                    expiration_datetime = datetime.fromtimestamp(expirationTime / 1000)
            except (ValueError, TypeError, OSError) as e:
                return return_validation_error(f"expirationTime must be in ISO format or valid timestamp: {str(e)}")
        
        # Call route method that executes stored procedure
        return routePWASubscribe(RM_UserId, endpoint, p256dh_key, auth_key, expiration_datetime)
        
    except Exception as e:
        return error_response("An internal error occurred", 500, e, "subscribe endpoint")


@egca_aix_bp.route('/unsubscribe', methods=['POST'])
def unsubscribe():
    """
    Remove a push subscription. Validates endpoint parameter.
    """
    # Get JSON data from request body
    if not request.is_json:
        return return_validation_error("Request must be JSON")
    
    try:
        subscription_data = request.get_json()
        if not subscription_data:
            return return_validation_error("Request body is empty")
        
        if not isinstance(subscription_data, dict):
            return return_validation_error("Request body must be an object")
        
        # Validate endpoint (required)
        endpoint = subscription_data.get('endpoint', None)
        is_valid, error_msg = validate_required(endpoint, 'endpoint')
        if not is_valid:
            return return_validation_error(error_msg)
        
        # Validate endpoint is a string and looks like a URL
        if not isinstance(endpoint, str) or len(endpoint.strip()) == 0:
            return return_validation_error("endpoint must be a non-empty string")
        
        # if len(endpoint) > 500:  # Reasonable max length for URL
        #     return return_validation_error("endpoint exceeds maximum length of 500 characters")
        
        if not endpoint.startswith('https://'):
            return return_validation_error("endpoint must be a valid HTTPS URL")
        
        endpoint = endpoint.strip()
        
        # Call route method that executes stored procedure
        return routePWAUnsubscribe(endpoint)
            
    except Exception as e:
        return error_response("An internal error occurred", 500, e, "unsubscribe endpoint")



@egca_aix_bp.route('/sendNotification', methods=['GET'])
def send_notification():
    """API endpoint to send unsent push notifications - simple GET with no parameters"""
    try:
        # Call the reusable function (no parameters needed)
        results = sendPWANotification()
        
        # Ensure results is a dict and has required keys
        if not isinstance(results, dict):
            results = {
                'notifications_processed': 0,
                'notifications_sent': 0,
                'notifications_failed': 0,
                'subscriptions_notified': 0,
                'errors': ['Invalid response from sendPWANotification'],
                'status': 'error',
                'code': 500
            }
        
        # Ensure code exists
        code = results.get('code', 200)
        
        return jsonify(results), code
        
    except Exception as e:
         return error_response("An internal error occurred while sending notification", 500, e, "send_notification endpoint")


@egca_aix_bp.route('/subscriptions', methods=['GET'])
def get_subscriptions():
    """
    Get all registered subscriptions (for debugging/admin).
    Uses authenticated user's RM_UserId from middleware (security).
    """
    # Security: Use authenticated user's ID from middleware ONLY - never accept from user input
    if not hasattr(request, 'user_id') or not request.user_id:
        return return_validation_error("User authentication required", 401)
    
    RM_UserId = request.user_id
    
    return routePWAGetSubscriptions(RM_UserId)


