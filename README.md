# Securing FastAPI Applications
### A Practical Guide to Building Secure APIs with FastAPI


FastAPI is a modern, high-performance web framework for building APIs with Python. While its speed and developer-friendly syntax make it an excellent choice, securing your application properly is crucial.

This guide covers key areas of API security, including authentication, input validation, HTTPS, and more. Each section includes examples and tools to help you apply best practices in real-world applications.

## Table of Contents
1. [Authentication and Authorization](#1-authentication-and-authorization)
2. [Input Validation and Sanitization](#2-input-validation-and-sanitization)
3. [HTTPS (TLS/SSL)](#3-https-tlsssl)
4. [Secure Headers](#4-secure-headers)
5. [Rate Limiting](#5-rate-limiting)
6. [CORS (Cross-Origin Resource Sharing)](#6-cross-origin-resource-sharing-cors)
7. [Data Encryption](#7-data-encryption)
8. [Logging and Monitoring](#8-logging-and-monitoring)
9. [Static File Handling](#9-static-file-handling)
10. [Dependency Injection](#10-dependency-injection)
11. [Security Best Practices](#11-use-security-best-practices)
12. [Advanced Protections](#12-advanced-protections)
13. [Checklist for Deployment](#checklist-for-deployment)




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

## Checklist for Deployment

## Checklist for Deployment

Before you deploy your FastAPI application to production, make sure you've checked the following boxes:

### 🔐 **Security**

* [ ] **Authentication implemented** (OAuth2 / JWT / API Keys)
* [ ] **Authorization rules enforced** (role-based / permissions)
* [ ] **Rate limiting active** (`slowapi` or via reverse proxy)
* [ ] **CORS configured properly** (only allow trusted domains)
* [ ] **Security headers enabled** (`TrustedHostMiddleware`, `HTTPSRedirectMiddleware`, etc.)
* [ ] **HTTPS/TLS enabled** (via Nginx, Caddy, or cloud provider)
* [ ] **Static file permissions checked** (no `.env` or secrets exposed)
* [ ] **Environment variables protected** (`dotenv`, Docker secrets, Vault, etc.)
* [ ] **Sensitive data encrypted** (at rest and in transit)

### 🛡️ **Code & Dependency Safety**

* [ ] **All packages up-to-date**
* [ ] **Security scan run** (`bandit`, `pip-audit`, `safety`, etc.)
* [ ] **Remove debug endpoints or dev routes**
* [ ] **No hardcoded secrets in code or version control**

### 📊 **Monitoring & Logging**

* [ ] **Error tracking active** (e.g., Sentry)
* [ ] **Application logs enabled** (e.g., log to file or stdout)
* [ ] **Performance monitoring** (e.g., Prometheus, Grafana)
* [ ] **Alerts configured** for critical errors or traffic spikes

### 🚀 **Deployment Readiness**

* [ ] **Dockerized or virtualized properly**
* [ ] **Gunicorn/Uvicorn workers configured**
* [ ] **Database backups configured and tested**
* [ ] **Health check endpoints exist** (`/health`, `/ready`)
* [ ] **CI/CD pipeline tested** (GitHub Actions, GitLab, etc.)

### 🧪 **Final Test Run**

* [ ] Manual test of all endpoints done
* [ ] Auth flow tested end-to-end
* [ ] Edge cases handled (e.g., token expiry, wrong inputs)
* [ ] 404/500 fallback routes implemented

---

📌 *Pro tip: Save this checklist as `DEPLOYMENT.md` in your repo and tick the boxes during your review.*

Hopefully it helps! If you found this useful, don't forget to ⭐ the repo! Created by [VolkanSah](https://github.com/volkansah)
