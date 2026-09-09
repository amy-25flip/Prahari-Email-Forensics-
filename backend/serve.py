"""Same-origin service entry point for hosts that assign PORT dynamically."""
import os
import uvicorn

if __name__ == '__main__':
    uvicorn.run('main:app', host='0.0.0.0', port=int(os.getenv('PORT', '8000')),
                workers=1, proxy_headers=False, limit_concurrency=30,
                timeout_keep_alive=5)
