from waitress import serve
from server import app
from config import HOST, PORT, WAITRESS_THREADS, WAITRESS_CHANNEL_TIMEOUT

if __name__ == "__main__":
    host = HOST
    port = PORT
    threads = WAITRESS_THREADS
    channel_timeout = WAITRESS_CHANNEL_TIMEOUT
    
    print(f"Starting Waitress server on {host}:{port}")
    print(f"Threads: {threads}")
    print(f"Channel timeout: {channel_timeout}s")
    
    serve(
        app,
        host=host,
        port=port,
        threads=threads,
        channel_timeout=channel_timeout,
        cleanup_interval=30,
        asyncore_use_poll=True,
        connection_limit=1000,
        backlog=2048
    )
