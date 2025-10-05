import os
from dotenv import load_dotenv

def load_env():
    load_dotenv()

def get_env(key, default=None):
    return os.getenv(key, default)