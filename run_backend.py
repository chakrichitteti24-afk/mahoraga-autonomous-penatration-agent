"""
Mahoraga AI - Autonomous Vulnerability Scanner Backend Server Runner
"""
import sys
import uvicorn
from backend.config import settings

def main():
    print("=" * 65)
    print("  MAHORAGA AI - AUTONOMOUS VULNERABILITY SCANNER BACKEND")
    print("=" * 65)
    print(f"  • API Root:      http://{settings.host}:{settings.port}/api")
    print(f"  • OpenAPI Docs:  http://{settings.host}:{settings.port}/docs")
    print(f"  • ReDoc:         http://{settings.host}:{settings.port}/redoc")
    print(f"  • Health Check:  http://{settings.host}:{settings.port}/api/health")
    print("=" * 65)
    print("Starting server... Press Ctrl+C to terminate.")
    
    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
    )

if __name__ == "__main__":
    main()
