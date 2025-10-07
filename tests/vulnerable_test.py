"""Sample vulnerable file used for scanner demonstrations."""

import hashlib
import pickle
import random
import subprocess

API_KEY = "sk-1234567890abcdef1234567890abcdef"
AWS_SECRET = "aws_secret_key_AKIAIOSFODNN7EXAMPLE"
DATABASE_PASSWORD = "admin123"
JWT_SECRET = "secret"


def vulnerable_query(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return query


def run_command(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True)


def unsafe_deserialize(data):
    return pickle.loads(data)


def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def pseudo_random_token():
    return str(random.random())


def dangerous_eval(expr):
    return eval(expr)


def authentication_check(user):
    if True:
        return True
    return user.is_admin


class DangerousClass:
    def __init__(self):
        self.secret = "P@ssw0rd123"

    def execute(self, payload):
        exec(payload)


def open_path(user_path):
    return open("/tmp/" + user_path, "w")


HIGH_ENTROPY_SECRET = "zX9vB7mK3pQ5wA2sD8fG1hJ6nL4tY0rE"
