#!/usr/bin/python
from flask import Flask, request, jsonify
import boto3
import json
from flask_sqlalchemy import SQLAlchemy
from pyfcm import FCMNotification
from datetime import date
from datetime import datetime, timedelta
from sqlalchemy.dialects import *
cogcli="7mbneubah8favrjhefcn79taum"
cog = boto3.client('cognito-idp', region_name='ap-south-1')
application = Flask(__name__)
application.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres:ITdept(4895@rds.c2ocfdyvtbwu.ap-south-1.rds.amazonaws.com:5432/postgres'
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db=SQLAlchemy(application)

class users(db.Model):
    username=db.Column(db.Text, primary_key=True)
    name=db.Column(db.Text,nullable=False)
    phone=db.Column(db.Numeric, nullable=False)
    lockids=db.Column(postgresql.ARRAY(db.Text))
    appids=db.Column(postgresql.ARRAY(db.Text))
    def __init__(self,username,name,phone,lockids,appids):
        self.username=username
        self.name=name 
        self.phone=phone
        self.lockids=lockids
        self.appids=appids

class locks(db.Model):
    lockid=db.Column(db.Text, primary_key=True)
    alias=db.Column(db.Text,nullable=False)
    address=db.Column(db.Text, nullable=False)
    favourite=db.Column(db.Boolean,nullable=False)
    def __init__(self,lockid,alias,address,favourite):
        self.lockid=lockid
        self.alias=alias
        self.address=address
        self.favourite=favourite 

class acl(db.Model):
    lockid=db.Column(db.Numeric, db.ForeignKey('users.username'),primary_key=True)
    username=db.Column(db.Text,db.ForeignKey('locks.lockid'),primary_key=True)
    expiry=db.Column(postgresql.TIMESTAMP, nullable=False)
    user=db.relationship("users",backref="acl_username")
    lock=db.relationship("locks",backref="acl_lockid")
    def __init__(self,lockid,username,expiry):
        self.lockid=lockid
        self.username=username
        self.expiry=expiry

class log(db.Model):
    serial=db.Column(db.Integer,primary_key=True)
    lockid=db.Column(db.Numeric)
    username=db.Column(db.Text)
    time=db.Column(postgresql.TIMESTAMP, nullable=False)
    operation=db.Column(db.Text)
    user_type=db.Column(db.Text)
    def __init__(self,lockid,username,time,operation,user_type):
        self.lockid=lockid
        self.username=username
        self.time=time
        self.operation=operation
        self.user_type=user_type
        print("time",time)


@application.route('/', methods=["GET"])
def hello():
    return "HELLO. FLASK IS WORKING!"

@application.route('/testsql',methods=["GET","POST"])
def testsql():
    print('in func')
    try:
        print('in try')
        us=users(username='osa',name='Osa',phone='9566425387',lockids=[],appids=[])
        db.session.add(us)
        db.session.commit()
        return "true"
    except Exception as e:
        return str(e)

@application.route('/addLock',methods=["GET","POST"])   
def add_locks():
    try:
        content=json.loads(request.data)
        lock=locks(content['lockid'],content['alias'],content['address'])
        resp=users.query.get(content['username'])
        new_arr=resp.lockids.copy()
        new_arr.append(content['lockid'])
        resp.lockids=new_arr
        db.session.add(lock)
        db.session.commit()
        return "true"
    except Exception as e:
        return str(e)  

@application.route('/deleteLock',methods=["GET","POST"])
def delete_locks():
    try:
        content=json.loads(request.data)
        locks.query.filter_by(lockid=content['lockid']).delete()
        db.session.commit()
        return "true"
    except Exception as e:
        return str(e)

@application.route('/editLock',methods=["GET","POST"])
def edit_locks():
    try:
        content=json.loads(request.data)
        lock=locks.query.get(content['lockid'])
        lock.address=content['address']
        lock.alias=content['alias']
        db.session.commit()
        return "true"
    except Exception as e:
        return str(e)

@application.route('/toggleFavourite',methods=["GET","POST"])
def toggleFavourites():
    try:
        content=json.loads(request.data)
        lock=locks.query.get(content['lockid'])
        if content['choice']=='fav':
            lock.favourite='true'
        else:
            lock.favourite='false'
        db.session.commit()
        return "true"
    except Exception as e:
        return str(e)

@application.route('/addLog',methods=["GET","POST"])
def add_logs():
    try:
        content=json.loads(request.data)
        time = datetime.strptime(content['time'],"%Y-%m-%d %H:%M:%S")
        lg=log(content['lockid'],content['username'],time,content['operation'],content['user_type'])
        db.session.add(lg)
        db.session.commit()
        return "true"
    except Exception as e:
        return str(e)

@application.route('/grantPermission', methods=["GET","POST"])
def grantPermission():
    try:
        content=json.loads(request.data)
        rec=acl(content['lockid'],content['username'],content['expiry'])
        db.session.add(rec)
        db.session.commit()
        return "true"
    except Exception as e:
        return str(e)

@application.route('/checkPermission',methods=["GET","POST"])
def checkPermission():
    try:
        content=json.loads(request.data)
        user=users.query.get['username']
        if content['lockid'] in user.lockids:
            return "true"
        else:
            rec=acl.query.filter_by(username=content['username'],lockid=content['lockid'])
            if rec and rec.expiry>datetime.now():
                return "true"
            else:
                return "false"
    except Exception as e:
        return str(e)
@application.route('/getLocks',methods=["GET","POST"])
def getLocks():
    try:
        content=json.loads(request.data)
        lockarr=[]
        resp=users.query.get(content['username'])
        # print(resp.lockids)
        lcks=resp.lockids
        for lock in lcks:
            dct={}
            print(lock)
            details=locks.query.get(lock)
            dct['lockid']=details.lockid
            dct['alias']=details.alias
            dct['address']=details.address
            dct['favourite']=details.favourite
            lockarr.append(dct)
        return json.dumps(lockarr)
    except Exception as e:
        return str(e)
                


@application.route('/login',methods=["GET","POST"])
def login():
    try:
        content=json.loads(request.data)
        auth=cog.initiate_auth(
            AuthFlow = 'USER_PASSWORD_AUTH',
            AuthParameters = {
                'USERNAME': content['username'],
                'PASSWORD': content['password']
            },
            ClientId = cogcli
        )
        resp=users.query.get(content['username'])
        new_arr=resp.appids.copy()
        new_arr.append(content['appid'])
        resp.appids=new_arr
        db.session.commit()
        return "true"
    except cog.exceptions.UserNotConfirmedException:
        return "User is not confirmed. Please check your mail."
    except cog.exceptions.UserNotFoundException:
        return "User does not exist. Check again."
    except cog.exceptions.NotAuthorizedException:
        return "Username/Password is incorrect"
    except Exception as e:
        return "Unknown error. Please contact the developer."

@application.route('/signup',methods=["GET","POST"])
def signup():
    try:
        content=json.loads(request.data)
        cog.sign_up(
                    ClientId  = cogcli,
                    Username = content['username'],
                    Password = content['password'],
                    UserAttributes=[{"Name":"email","Value":content['email']}]
                )
        obj=users(content['username'],content['name'],content['phone'],[],[])
        db.session.add(obj)
        db.session.commit()
        return "true"
    except cog.exceptions.UsernameExistsException:
        return "Username Already Exists!"
    except Exception as e:
        print("Exception: " +str(e))
        return str(e)



if __name__ == "__main__":
    application.run(debug=True)