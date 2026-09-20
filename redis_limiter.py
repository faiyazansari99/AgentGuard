import os
import time
from fastapi import HTTPException, Request
try:
    import redis
except ImportError:  # pragma: no cover
    redis = None

class RateLimiter:
    def __init__(self):
        self.url = os.getenv('REDIS_URL', '')
        self.limit = int(os.getenv('RATE_LIMIT_PER_MINUTE', '120'))
        self.allow_fallback = os.getenv('ALLOW_LOCAL_RATE_LIMIT_FALLBACK', 'false').lower() == 'true'
        self.client = redis.Redis.from_url(self.url, decode_responses=True) if redis and self.url else None
        self.local = {}
    def __call__(self, request: Request):
        ip = request.client.host if request.client else 'unknown'
        bucket = int(time.time() // 60)
        key = f'ag:rl:{ip}:{bucket}'
        try:
            if not self.client:
                raise RuntimeError('REDIS_URL is not configured')
            count = int(self.client.incr(key))
            if count == 1:
                self.client.expire(key, 61)
        except Exception:
            if not self.allow_fallback:
                raise HTTPException(503, 'Rate limiting service unavailable')
            local_key = (ip, bucket)
            count = self.local.get(local_key, 0) + 1
            self.local[local_key] = count
        if count > self.limit:
            raise HTTPException(429, 'Rate limit exceeded')

rate_limiter = RateLimiter()
