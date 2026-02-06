from server import app
from config import HOST, PORT

if __name__ == "__main__":
    host = '127.0.0.1'
    port = PORT
    
    print("=" * 50)
    print("DEVELOPMENT SERVER - Auto-reload enabled")
    print("=" * 50)
    print(f"Server running on http://{host}:{port}")
    print("Press CTRL+C to stop")
    print("=" * 50)
    print()
    
    app.run(
        host=host,
        port=port,
        debug=True,
        use_reloader=True,
        use_debugger=True,
        threaded=True,
        extra_files=['router/eLogRoute.py']
    )
