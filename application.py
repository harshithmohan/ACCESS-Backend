#!/usr/bin/python
from flask import Flask, request, jsonify
from flask_cors import CORS
import boto3
import json
from pyfcm import FCMNotification
from models import *
import sqlalchemy
cogcli='7mbneubah8favrjhefcn79taum'
cog = boto3.client('cognito-idp', region_name='ap-south-1')
application = Flask(__name__)
application.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:ITdept(4895@rds.c2ocfdyvtbwu.ap-south-1.rds.amazonaws.com:5432/postgres'
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
cors = CORS(application, resources = {r'/*':{'origins':'*'}})
db.init_app(application)

@application.route('/', methods = ['GET'])
def hello():
    return 'HELLO. FLASK IS WORKING!'

@application.route('/test',methods = ['GET','POST'])   
def test():
    content = json.loads(request.data)
    # print(Locks.query.get(content['lockid']).username)
    try:
        print(Acl.query.filter_by(lockid = content['lockid']).filter_by(username = content['username']).one())
        return 'true'
    except NoResultFound:
        return 'false'

@application.route('/addLock',methods = ['GET','POST'])   
def addLock():
    try:
        content = json.loads(request.data)
        lock = Locks(content['lockid'], content['username'])
        db.session.add(lock)
        db.session.commit()
        return 'true'
    except Exception as e:
        return str(e)  


@application.route('/checkPermission',methods = ['GET','POST'])
def checkPermission():
    try:
        content = json.loads(request.data)
        if Locks.query.get(content['lockid']).username == content['username']:
            content['user_type'] = 'owner'
        else:
            ac = Acl.query.filter_by(lockid = content['lockid']).filter_by(username = content['username']).one()
            content['user_type'] = 'guest'
        content['operation'] = 'lock'
        addLog(content)
        return 'true'
    except sqlalchemy.orm.exc.NoResultFound:
        return 'false'
    except Exception as e:
        return str(e)

@application.route('/deleteLock',methods = ['GET','POST'])
def deleteLock():
    try:
        content = json.loads(request.data)
        Locks.query.get(content['lockid']).delete()
        db.session.commit()
        return 'true'
    except Exception as e:
        return str(e)

@application.route('/editLock',methods = ['GET','POST'])
def editLock():
    try:
        content = json.loads(request.data)
        lock = Locks.query.get(content['lockid'])
        lock.address = content['address']
        lock.alias = content['alias']
        db.session.commit()
        return 'true'
    except Exception as e:
        return str(e)

@application.route('/grantPermission', methods = ['GET','POST'])
def grantPermission():
    try:
        content = json.loads(request.data)
        rec = Acl(content['lockid'], content['username'], content['expiry'])
        db.session.add(rec)
        db.session.commit()
        return 'true'
    except Exception as e:
        return str(e)

def addLog(content):
    try:
        lg = Logs(content['lockid'], content['username'], content['operation'], content['user_type'])
        db.session.add(lg)
        db.session.commit()
        return 'true'
    except Exception as e:
        return str(e)

@application.route('/getLocks', methods = ['GET','POST'])
def getLocks():
    try:
        content = json.loads(request.data)
        lockDict = {}
        lcks = Users.query.get(content['username']).locks
        print(lcks)
        for lock in lcks:
            dct = {}
            dct['lockId'] = lock.lockid
            dct['alias'] = lock.alias
            dct['address'] = lock.address
            dct['favourite'] = lock.favourite
            lockDict[lock.lockid] = dct
        return lockDict
    except Exception as e:
        return str(e)

@application.route('/getOtherLocks', methods = ['GET','POST'])
def getOtherLocks():
    try:
        content = json.loads(request.data)
        lockDict = {}
        lcks = Users.query.get(content['username']).acl
        print(lcks)
        for lock in lcks:
            dct = {}
            dct['lockId'] = lock.lockid
            dct['expiry'] = lock.expiry
            lockDetails = Locks.query.get(lock.lockid)
            dct['alias'] = lockDetails.alias
            dct['address'] = lockDetails.address
            lockDict[lock.lockid] = dct
        return lockDict
    except Exception as e:
        return str(e)

@application.route('/login', methods = ['GET','POST'])
def login():
    try:
        content = json.loads(request.data)
        auth = cog.initiate_auth(
            AuthFlow = 'USER_PASSWORD_AUTH',
            AuthParameters = {
                'USERNAME': content['username'],
                'PASSWORD': content['password']
            },
            ClientId = cogcli
        )
        resp = Users.query.get(content['username'])
        new_arr = resp.appids.copy()
        new_arr.append(content['appId'])
        resp.appids = new_arr
        db.session.commit()
        return 'true'
    except cog.exceptions.UserNotConfirmedException:
        return 'User is not confirmed. Please check your mail.'
    except cog.exceptions.UserNotFoundException:
        return 'User does not exist. Check again.'
    except cog.exceptions.NotAuthorizedException:
        return 'Username/Password is incorrect'
    except Exception as e:
        return 'Unknown error. Please contact the developer.'

@application.route('/signup',methods = ['GET','POST'])
def signup():
    try:
        content = json.loads(request.data)
        cog.sign_up(
                    ClientId  = cogcli,
                    Username = content['username'],
                    Password = content['password'],
                    UserAttributes = [{'Name':'email','Value':content['email']}]
                )
        user = Users(content['username'],content['name'],content['phone'])
        db.session.add(user)
        db.session.commit()
        return 'true'
    except cog.exceptions.UsernameExistsException:
        return 'Username Already Exists!'
    except Exception as e:
        print('Exception: ' +str(e))
        return str(e)

@application.route('/toggleFavourite',methods = ['GET','POST'])
def toggleFavourite():
    try:
        content = json.loads(request.data)
        lock = Locks.query.get(content['lockid'])
        if content['choice'] == 'fav':
            lock.favourite = 'true'
        else:
            lock.favourite = 'false'
        db.session.commit()
        return 'true'
    except Exception as e:
        return str(e)


if __name__ == '__main__':
    application.run(debug = True)