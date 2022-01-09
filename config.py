import os, random

SECRET_KEY = '<secretkeyhere>'
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///zendesk.sqlite')
SQLALCHEMY_TRACK_MODIFICATIONS = False

