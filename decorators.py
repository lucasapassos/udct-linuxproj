from flask import session as login_session
from flask import redirect
from functools import wraps

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwds):
        print login_session
        if 'username' in login_session:
            return function(*args, **kwds)
        else:
            return redirect('/login/')
    return wrapper
