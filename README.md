User Management API

A secure RESTful API built with FastAPI for user authentication, authorization, and session management, following modern backend best practices.


---

Features

JWT authentication (Access & Refresh Tokens)

Secure session handling with CSRF protection

Role-Based Access Control (User / Moderator / Admin)

User & Post management

Redis-based rate limiting and abuse protection

Secure password hashing (Argon2 / Bcrypt)



---

Tech Stack

Python, FastAPI

SQLAlchemy, PostgreSQL

Redis

JWT (python-jose)

Passlib



---

Highlights

One-time refresh tokens bound to device

Logout from single or all devices

Strong permission system

Clean service-based architecture



---

Setup

pip install fastapi uvicorn sqlalchemy psycopg2 redis passlib[argon2] python-jose
uvicorn app_main:app --reload


---

Author

Ahmed Saeed
Backend Developer | Python & FastAPI
