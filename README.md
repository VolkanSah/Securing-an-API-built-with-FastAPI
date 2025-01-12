# Securing an API built with FastAPI 
### detailed guide: How to secure your FastAPI application.



### 1. **Authentication and Authorization**
- **Authentication**: Ensure users can securely authenticate. Use libraries like `OAuth2`, `JWT` (JSON Web Tokens), or API keys.
    - FastAPI has built-in support for OAuth2 and JWT integration.
    - Use `fastapi.security` to define OAuth2 token flow.
- **Authorization**: Control access to resources based on user roles or permissions.
    - Use dependency injection to enforce access rules at the endpoint level.

**Example**:
```python
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    # Verify and decode token (use a library like PyJWT)
    if token != "valid_token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    return {"username": "test_user"}

@app.get("/secure-endpoint")
def secure_endpoint(user: dict = Depends(get_current_user)):
    return {"message": f"Hello, {user['username']}!"}
```

---

### 2. **Input Validation and Sanitization**
- Validate all inputs using Pydantic models to prevent injection attacks and ensure data consistency.
- Example of a Pydantic model:
```python
from pydantic import BaseModel, Field

class UserInput(BaseModel):
    username: str = Field(..., max_length=50)
    email: str
    age: int = Field(..., ge=0)
```



### 3. **HTTPS (TLS/SSL)**
- Always serve your API over HTTPS to encrypt data in transit.
- Use tools like Let’s Encrypt for free TLS certificates.
- Configure your web server (e.g., Nginx or Uvicorn) to redirect HTTP to HTTPS.



### 4. **Secure Headers**
- Use security headers to protect your API from common attacks like XSS, clickjacking, etc.
- Libraries like `starlette.middleware.trustedhost` and `secure` can add secure headers.
- Example:
```python
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["yourdomain.com", "*.yourdomain.com"])
app.add_middleware(HTTPSRedirectMiddleware)
```



### 5. **Rate Limiting**
- Implement rate limiting to prevent abuse or brute-force attacks.
- Use tools like `slowapi`:
```bash
pip install slowapi
```
```python
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import FastAPI

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()

@app.get("/")
@limiter.limit("5/minute")
def home():
    return {"message": "Welcome!"}
```

---

### 6. **Cross-Origin Resource Sharing (CORS)**
- Restrict which domains can interact with your API.
- Use `fastapi.middleware.cors.CORSMiddleware`:
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
```



### 7. **Data Encryption**
- Encrypt sensitive data at rest using libraries like `cryptography` or database-specific encryption features.
- Ensure sensitive environment variables (e.g., secret keys) are securely stored using tools like `dotenv` or cloud secret managers.



### 8. **Logging and Monitoring**
- Log suspicious activities and monitor logs for anomalies.
- Use tools like `Sentry` for error tracking and `Prometheus` for monitoring metrics.



### 9. **Static File Handling**
- Be cautious when serving static files. Do not expose sensitive files accidentally.
- Use FastAPI's `StaticFiles` carefully and configure proper permissions.


### 10. **Dependency Injection**
- FastAPI’s dependency injection system can help inject security checks and other reusable code at different layers.



### 11. **Use Security Best Practices**
- Keep FastAPI and dependencies updated to avoid vulnerabilities.
- Regularly scan your code for security vulnerabilities using tools like `bandit`.
- Follow the principle of least privilege for database and API permissions.


### 12. **Advanced Protections**
- Implement Web Application Firewall (WAF) rules.
- Consider API gateways like Kong or AWS API Gateway for centralized security.

Hoply it helps, do mt forget the ⭐
