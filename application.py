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
iotcore=boto3.client('iot-data', region_name='ap-south-1')
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
    try:
        print(Acl.query.filter_by(lockId = content['lockId']).filter_by(username = content['username']).one())
        return 'true'
    except NoResultFound:
        return 'false'

@application.route('/addLock',methods = ['GET','POST'])   
def addLock():
    try:
        content = json.loads(request.data)
        lock = Locks(content['lockId'], content['username'])
        db.session.add(lock)
        db.session.commit()
        return 'true'
    except sqlalchemy.orm.exc.NoResultFound:
        return 'false'
    except sqlalchemy.exc.IntegrityError as e:
        return 'duplicate'
    except Exception as e:
        return str(e) 

def addLog(content):
    try:
        lg = Logs(content['lockId'], content['username'], content['operation'], content['userType'])
        db.session.add(lg)
        db.session.commit()
        return 'true'
    except Exception as e:
        return str(e)

@application.route('/changePassword', methods = ['GET', 'POST'])
def changePassword():
    try:
        content=json.loads(request.data)
        cog.change_password( PreviousPassword=content['previousPassword'],ProposedPassword=content['newPassword'],AccessToken=content['accessToken'])
        return 'true'
    except cog.exceptions.UserNotFoundException:
        return 'User does not exist'
    except cog.exceptions.InvalidParameterException:
        return 'Email not verified'
    except cog.exceptions.InvalidPasswordException:
        return 'Invalid Password'
    except Exception as e:
        return str(e)

@application.route('/checkPermission',methods = ['GET','POST'])
def checkPermission():
    try:
        content = json.loads(request.data)
        if Locks.query.get(content['lockId']).username == content['username']:
            content['userType'] = 'owner'
        else:
            ac = Acl.query.filter_by(lockId = content['lockId']).filter_by(username = content['username']).one()
            content['userType'] = 'guest'
        content['operation'] = 'lock'
        addLog(content)
        return 'true'
    except sqlalchemy.orm.exc.NoResultFound:
        return 'false'
    except Exception as e:
        return str(e)

@application.route('/confirmForgotPassword', methods= ['GET', 'POST'])
def confirmForgotPassword():
    try:
        content=json.loads(request.data)
        cog.confirm_forgot_password(ClientId=cogcli, Username=content['username'], ConfirmationCode=content['code'], Password=content['password'])
        return 'true'
    except cog.exceptions.UserNotFoundException:
        return 'User does not exist. Try Again!' 
    except cog.exceptions.InvalidParameterException:
        return 'Email not verified'
    except cog.exceptions.CodeMismatchException:
        return 'Invalid Confirmation Code'
    except Exception as e:
        return str(e)

@application.route('/deleteLock',methods = ['GET','POST'])
def deleteLock():
    try:
        content = json.loads(request.data)
        lock = Locks.query.get(content['lockId'])
        db.session.delete(lock)
        db.session.commit()
        return 'true'
    except sqlalchemy.orm.exc.NoResultFound:
        return 'false'
    except Exception as e:
        return str(e)

@application.route('/editLock',methods = ['GET','POST'])
def editLock():
    try:
        content = json.loads(request.data)
        lock = Locks.query.get(content['lockId'])
        lock.address = content['address']
        lock.alias = content['alias']
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
            dct['lockId'] = lock.lockId
            dct['alias'] = lock.alias
            dct['address'] = lock.address
            dct['favourite'] = lock.favourite
            lockDict[lock.lockId] = dct
        return lockDict
    except sqlalchemy.orm.exc.NoResultFound:
        return 'false'
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
            dct['lockId'] = lock.lockId
            dct['expiry'] = lock.expiry
            lockDetails = Locks.query.get(lock.lockId)
            dct['alias'] = lockDetails.alias
            dct['address'] = lockDetails.address
            lockDict[lock.lockId] = dct
        return lockDict
    except sqlalchemy.orm.exc.NoResultFound:
        return 'false'
    except Exception as e:
        return str(e)

@application.route('/getLogs', methods= ['GET', 'POST'])
def viewLogs():
    try:
        content = json.loads(request.data)
        dct = []
        if content['choice'] == 'all':
            logs = Logs.query.filter_by(username = content['username']).order_by(Logs.time.desc()).all()
        elif content['choice'] == 'lockId':
            logs = Logs.query.filter_by(username = content['username']).filter_by(lockId = content['lockId']).order_by(Logs.time.desc()).all()
        elif content['choice'] == 'operation':
            logs = Logs.query.filter_by(username = content['username']).filter_by(operation = content['operation']).order_by(Logs.time.desc()).all()
        elif content['choice'] == 'userType':
            logs = Logs.query.filter_by(username = content['username']).filter_by(userType = content['userType']).order_by(Logs.time.desc()).all()    
        elif content['choice'] == 'time':
            logs = Logs.query.filter_by(username = content['username']).filter(time.between(datetime.strptime(content['start'],"%Y-%m-%d %H:%M:%S"), datetime.strptime(content['end'],"%Y-%m-%d %H:%M:%S"))).order_by(Logs.time.desc()).all()
        for log in logs:
            indict = {}
            indict['lockId'] = log.lockId
            indict['username'] = log.username
            indict['time'] = datetime.strftime(log.time, "%Y-%m-%d %H:%M:%S")
            indict['userType'] = log.userType
            indict['operation'] = log.operation
            dct.append(indict)
        return str(dct)
    except sqlalchemy.orm.exc.NoResultFound:
        return 'false'
    except Exception as e:
        return str(e)

@application.route('/getUsers', methods = ['GET', 'POST'])
def getUsers():
    try:
        content = json.loads(request.data)
        q=db.session.query(Users).filter_by(lockId = content['lockId']).join(Locks).join(Acl).all()
        dct={}
        for row in q:
            indict = {}
            indcit['name'] = row.name
            indict['userType'] = row.userType
            indict['expiry'] = row.expiry
            dct['username'] = row.username
        return dct
    except sqlalchemy.orm.exc.NoResultFound:
        return 'false'
    except Exception as e:
        return str(e)

@application.route('/grantPermission', methods = ['GET','POST'])
def grantPermission():
    try:
        content = json.loads(request.data)
        rec = Acl(content['lockId'], content['username'], content['expiry'])
        db.session.add(rec)
        db.session.commit()
        return 'true'
    except Exception as e:
        return str(e)

@application.route('/forgotPassword', methods= ['GET', 'POST'])
def forgotPassword():
    try:
        content = json.loads(request.data)
        cog.forgot_password(ClientId=cogcli, Username=content['username'])
        return 'true'
    except cog.exceptions.UserNotFoundException:
        return 'User does not exist' 
    except Exception as e:
        return str(e)

@application.route('/lockOperations', methods = ['GET', 'POST'])
def lockOperations():
    try:
        content = json.loads(request.data)
        pl = {'lockId' : content['lockId'], 'operation' : content['operation']}
        response = iotcore.publish(topic = 'lock', qos = 1, payload = json.dumps(pl))
        addLog(content)
        return str(response)
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
        retval = auth["AuthenticationResult"]["AccessToken"]
        resp = Users.query.get(content['username'])
        if not content['lockId'] in resp.appIds:
            new_arr = resp.appIds.copy()
            new_arr.append(content['appId'])
            resp.appIds = new_arr
            db.session.commit()
        return retval
    except cog.exceptions.UserNotConfirmedException:
        return 'User is not confirmed. Please check your mail.'
    except cog.exceptions.UserNotFoundException:
        return 'User does not exist. Check again.'
    except cog.exceptions.NotAuthorizedException:
        return 'Username/Password is incorrect'
    except Exception as e:
        return 'Unknown error. Please contact the developer.'

@application.route('/logout', methods = ['GET', 'POST'])
def logout():
    try:
        content = json.loads(request.data)
        cog.global_sign_out(AccessToken = content['AccessToken'])
        resp = Users.query.get(content['username'])
        new_arr = resp.appIds.copy()
        new_arr.remove(content['appId'])
        resp.appIds = new_arr
        db.session.commit()
        return 'true'
    except Exception as e:
        return str(e)

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
        lock = Locks.query.get(content['lockId'])
        if content['choice'] == 'fav':
            lock.favourite = 'true'
        else:
            lock.favourite = 'false'
        db.session.commit()
        return 'true'
    except sqlalchemy.orm.exc.NoResultFound:
        return 'false'
    except Exception as e:
        return str(e)

if __name__ == '__main__':
    application.run(debug = True)