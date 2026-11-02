import multiprocessing

from app.factory import create_app

# Spawned helper processes (PDF sandbox) re-import this module; only the real server process builds the app.
if multiprocessing.current_process().name == "MainProcess":
    app = create_app()

if __name__ == "__main__":
    import os
    multiprocessing.freeze_support()
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 5000)), debug=False, threaded=True)
