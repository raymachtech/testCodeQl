import logging
from flask import jsonify, make_response

def responseMaker(data, status, statuscode, header, contenttype="application/json"):
    responseBody = {header: data}
    
    response = make_response(jsonify(responseBody), statuscode)
    response.headers["Content-Type"] = contenttype
    response.status_code = statuscode
    
    return response

def error_response(error_message="An internal error occurred", status_code=500, exception=None, context=None):
    if exception:
        if context:
            logging.error(f"{context}: {exception}", exc_info=True)
        else:
            logging.error(f"Error: {exception}", exc_info=True)
    return jsonify({
        "error": error_message,
        "message": "Please contact support if this persists",
        "code": status_code
    }), status_code

def validation_error_response(message: str, status_code: int = 400):
    """
    Return a validation error response. Handles exceptions to prevent stack trace exposure.
    Uses the same format as error_response for consistency.
    """
    try:
        return jsonify({
            "error": message,
            "message": "Validation error",
            "code": status_code
        }), status_code
    except Exception as e:
        # If jsonify fails, log internally and return generic error using error_response
        logging.error("Error creating validation response", exc_info=True)
        return error_response("Validation failed", status_code)
        
def log_error(exception, context=None):
    if context:
        logging.error(f"{context}: {exception}", exc_info=True)
    else:
        logging.error(f"Error: {exception}", exc_info=True)
