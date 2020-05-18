from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects import *
from datetime import datetime, timedelta
from pytz import timezone

db = SQLAlchemy()


class Acl(db.Model):
    __tablename__ = 'acl'

    lockId = db.Column(db.Text, db.ForeignKey('locks.lockId'), primary_key=True)
    username = db.Column(db.Text, db.ForeignKey('users.username'), primary_key=True)
    expiry = db.Column(postgresql.TIMESTAMP)
    userType = db.Column(db.Text, nullable=False)

    def __init__(self, lockId, username, userType, expiry):
        self.lockId = lockId
        self.username = username
        self.userType = userType
        self.expiry = expiry


class Locks(db.Model):
    __tablename__ = 'locks'

    lockId = db.Column(db.Text, primary_key=True)
    alias = db.Column(db.Text)
    address = db.Column(db.Text)
    webcam = db.Column(db.Boolean, default=False)
    favourite = db.Column(db.Boolean, default=False)
    username = db.Column(db.Text, db.ForeignKey('users.username'), nullable=False)
    bleUUID = db.Column(db.Text)
    btAddress = db.Column(db.Text)
    state = db.Column(db.Text)

    acl = db.relationship('Acl', cascade='all, delete, delete-orphan')
    logs = db.relationship('Logs', cascade='all, delete, delete-orphan')

    def __init__(self, lockId, username):
        self.lockId = lockId
        self.username = username


class Logs(db.Model):
    __tablename__ = 'logs'

    serial = db.Column(db.Integer, primary_key=True)
    lockId = db.Column(db.Text, db.ForeignKey('locks.lockId'))
    username = db.Column(db.Text, db.ForeignKey('users.username'))
    time = db.Column(postgresql.TIMESTAMP, default=datetime.now(timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M'))
    operation = db.Column(db.Text, nullable=False)
    userType = db.Column(db.Text, nullable=False)
    images = db.Column(db.Text)

    def __init__(self, lockId, username, operation, userType, images):
        self.lockId = lockId
        self.username = username
        self.operation = operation
        self.userType = userType
        self.images = images


class Users(db.Model):
    __tablename__ = 'users'

    username = db.Column(db.Text, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    phone = db.Column(db.Numeric, nullable=False)
    appIds = db.Column(postgresql.ARRAY(db.Text), nullable=False)

    acl = db.relationship('Acl')
    logs = db.relationship('Logs')
    locks = db.relationship('Locks')

    def __init__(self, username, name, phone):
        self.username = username
        self.name = name
        self.phone = phone
        self.appIds = {}
