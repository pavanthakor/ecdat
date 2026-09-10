"""must_not_fire (ADR-0034): the Juice Shop false-positive class, in Python.

Every name reads like a key; every value is a cookie name, header, cache
prefix, settings key or environment-variable NAME. Nothing may fire.
"""
import os

SESSION_COOKIE_NAME = "sessionid"
CSRF_HEADER_KEY = "X-CSRFToken"
API_KEY_HEADER = "X-Api-Key"
CACHE_KEY_PREFIX = "basket:"
SECRET_KEY_ENV = "DJANGO_SECRET_KEY"
PASSWORD_FIELD = "password"

SECRET_KEY = os.environ.get(SECRET_KEY_ENV, "")


def cache_key(user_id: int) -> str:
    return f"{CACHE_KEY_PREFIX}{user_id}"
