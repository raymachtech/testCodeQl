import pyodbc as db
from pyodbc import ProgrammingError
import json

def dbGetRMeLOG(dbstring, *args):
    from database.db_pool import get_egca_pool
    pool = get_egca_pool()
    
    with pool.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(dbstring, args)

        try:
            rows = cursor.fetchall()
            cols = [col[0] for col in cursor.description] if cursor.description else []
        except ProgrammingError as exc:
            if "No results" in str(exc):
                rows = []
                cols = []
            else:
                raise

        return rows, rows, cols

def dbTransRMeLOG(dbstring, *args): 
    from database.db_pool import get_egca_pool
    pool = get_egca_pool()
    
    try:
        with pool.get_connection() as conn:
            cursor = conn.cursor()
            result = cursor.execute(dbstring, args)
            
            response = result.fetchone()
            
            if response:
                result_value = response[0]
                message = response[1]
                
                return {
                    "status": "success" if str(result_value).upper() == "SUCCESS" else "error",
                    "message": message,
                    "code": 200 if str(result_value).upper() == "SUCCESS" else 400
                }
            else:
                return {
                    "status": "error",
                    "message": "No response from stored procedure",
                    "code": 500
                }
                
    except Exception as e:
        import logging
        logging.error(f"Database transaction error: {str(e)}")
        return {
            "status": "error",
            "message": "Database operation failed. Please try again or contact support.",
            "code": 500
        }

def prepareJson(rows, cols):
    response = []
    for row in rows:
        data = {}
        for key, val in zip(cols, row):
            data[key] = val
        response.append(data)
    return response

def prepareJson2(rows, cols):
    response = []
    
    for row in rows:
        data = {}
        for key, val in zip(cols, row):
            if isinstance(val, str) and val.startswith('["') and val.endswith('"]'):
                try:
                    data[key] = json.loads(val)
                except json.JSONDecodeError:
                    data[key] = val
            else:
                data[key] = val
        
        response.append(data)
    
    return response
