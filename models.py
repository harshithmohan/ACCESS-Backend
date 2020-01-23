from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects import *
from datetime import datetime, timedelta

db = SQLAlchemy()

class Users(db.Model):
    __tablename__ = 'users'

    username = db.Column(db.Text, primary_key = True)
    name = db.Column(db.Text, nullable = False)
    phone = db.Column(db.Numeric, nullable = False)
    appids = db.Column(postgresql.ARRAY(db.Text))

    acl = db.relationship('Acl')
    logs = db.relationship('Logs')
    locks = db.relationship('Locks')

    def __init__(self, username, name, phone):
        self.username = username
        self.name = name 
        self.phone = phone

class Locks(db.Model):
    __tablename__ = 'locks'

    lockid = db.Column(db.Text, primary_key = True)
    alias = db.Column(db.Text)
    address = db.Column(db.Text)
    favourite = db.Column(db.Boolean, default = False)
    username = db.Column(db.Text, db.ForeignKey('users.username'), nullable = False)

    acl = db.relationship('Acl')
    logs = db.relationship('Logs')

    def __init__(self, lockid, username):
        self.lockid = lockid
        self.username = username

class Acl(db.Model):
    __tablename__ = 'acl'

    lockid = db.Column(db.Text, db.ForeignKey('locks.lockid'), primary_key = True)
    username = db.Column(db.Text, db.ForeignKey('users.username'), primary_key = True)
    expiry = db.Column(postgresql.TIMESTAMP, nullable = False)

    def __init__(self, lockid, username, expiry):
        self.lockid = lockid
        self.username = username
        self.expiry = expiry

class Logs(db.Model):
    __tablename__ = 'logs'

    serial = db.Column(db.Integer, primary_key = True)
    lockid = db.Column(db.Text, db.ForeignKey('locks.lockid'))
    username = db.Column(db.Text, db.ForeignKey('users.username'))
    time = db.Column(postgresql.TIMESTAMP, default = datetime.now())
    operation = db.Column(db.Text, nullable = False)
    user_type = db.Column(db.Text, nullable = False)

    def __init__(self, lockid, username, operation, user_type):
        self.lockid = lockid
        self.username = username
        self.operation = operation
        self.user_type = user_type