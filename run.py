import uvicorn

if __name__ == "__main__":
    print("=" * 60)
    print("  Starting Detecto AI Malicious URL Detection Server...")
    print("  Web Dashboard: http://localhost:8000")
    print("  API Docs:      http://localhost:8000/docs")
    print("=" * 60)
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
