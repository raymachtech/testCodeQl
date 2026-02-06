import pyodbc as db
from queue import Queue, Empty
import threading
from contextlib import contextmanager
from config import EGCA_AIX_DB_STRING

egcaaixDBString = EGCA_AIX_DB_STRING

class ConnectionPool:
    def __init__(self, connection_string, pool_size=10, max_overflow=5):
        self.connection_string = connection_string
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool = Queue(maxsize=pool_size)
        self.overflow_count = 0
        self.lock = threading.Lock()
        self.created_connections = 0
        self.initialized = False
        self.init_lock = threading.Lock()
    
    def _create_connection(self):
        conn = db.connect(self.connection_string)
        conn.autocommit = True
        return conn
    
    @contextmanager
    def get_connection(self):
        conn = None
        try:
            try:
                conn = self.pool.get_nowait()
            except Empty:
                with self.lock:
                    if self.overflow_count < self.max_overflow:
                        try:
                            conn = self._create_connection()
                            self.overflow_count += 1
                            self.created_connections += 1
                        except Exception as e:
                            try:
                                conn = self.pool.get(timeout=10)
                            except Empty:
                                raise ConnectionError(f"Database connection pool exhausted. Cannot create new connection: {e}")
                    else:
                        try:
                            conn = self.pool.get(timeout=10)
                        except Empty:
                            raise ConnectionError("Database connection pool exhausted. All connections in use. Please retry later.")
            
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT 1")
                    cursor.close()
                except Exception:
                    try:
                        conn.close()
                    except:
                        pass
                    try:
                        conn = self._create_connection()
                        with self.lock:
                            if self.overflow_count < self.max_overflow:
                                self.overflow_count += 1
                    except Exception as e:
                        raise ConnectionError(f"Database connection failed. Server may be unavailable: {e}")
            
            yield conn
            
        except Exception as e:
            if conn:
                try:
                    conn.close()
                except:
                    pass
                with self.lock:
                    if self.overflow_count > 0:
                        self.overflow_count -= 1
            raise e
        finally:
            if conn:
                try:
                    if self.pool.qsize() < self.pool_size:
                        self.pool.put_nowait(conn)
                    else:
                        conn.close()
                        with self.lock:
                            if self.overflow_count > 0:
                                self.overflow_count -= 1
                except Exception:
                    try:
                        conn.close()
                    except:
                        pass
                    with self.lock:
                        if self.overflow_count > 0:
                            self.overflow_count -= 1
    
    def get_stats(self):
        return {
            'pool_size': self.pool_size,
            'available': self.pool.qsize(),
            'overflow': self.overflow_count,
            'total_created': self.created_connections
        }

_egca_pool = None
_pool_lock = threading.Lock()

def get_egca_pool():
    global _egca_pool
    if _egca_pool is None:
        with _pool_lock:
            if _egca_pool is None:
                _egca_pool = ConnectionPool(egcaaixDBString, pool_size=20, max_overflow=10)
    return _egca_pool
