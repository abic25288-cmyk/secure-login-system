# Secure Login System

A Flask + SQLite educational login app demonstrating password hashing, parameterized SQL, session authentication, CSRF protection, and input validation.

## Run
```bash
python -m venv .venv
# activate the environment, then:
pip install -r requirements.txt
```
Set a strong `SECRET_KEY` environment variable, then run `python app.py` and open http://127.0.0.1:5000.

## Security notes
Passwords are hashed with Werkzeug. SQL queries use placeholders. This is a learning project, not production-ready. For deployment, use HTTPS, a unique secret key, secure cookies, rate limiting, monitoring, and a security review. Never commit secrets or real user data.
