import uvicorn
from app.main import app
import sys
import multiprocessing

if __name__ == "__main__":
    # Required for PyInstaller + multiprocessing
    multiprocessing.freeze_support()
    
    # Run server
    uvicorn.run(
        app, 
        host="127.0.0.1", 
        port=8000, 
        log_level="info",
        reload=False  # Must be False in packaged app
    )
