import os
import time
from fastapi import HTTPException, Request
try:
    import redis
except ImportError:
    redis = None

class RateLimiter:
    def __init__(self):
        self.url = os.getenv('REDIS_URL', '')
        self.limit = int(os.getenv('RATE_LIMIT_PER_MINUTE', '120'))
        self.client = None
        if redis and self.url:
            try:
                self.client = redis.Redis.from_url(self.url, decode_responses=True)
                self.client.ping()
            except Exception:
                self.client = None
        self.local = {}

    def __call__(self, request: Request):
        ip = request.client.host if request.client else 'unknown'
        bucket = int(time.time() // 60)
        key = f'ag:rl:{ip}:{bucket}'
        if self.client:
            try:
                count = int(self.client.incr(key))
                if count == 1:
                    self.client.expire(key, 61)
            except Exception:
                count = self.local.get(key, 0) + 1
                self.local[key] = count
        else:
            count = self.local.get(key, 0) + 1
            self.local[key] = count
        if count > self.limit:
            raise HTTPException(429, 'Rate limit exceeded')

rate_limiter = RateLimiter()
