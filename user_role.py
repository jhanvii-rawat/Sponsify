from flask import session
from models import User

def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None