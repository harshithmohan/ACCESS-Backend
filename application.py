#!/usr/bin/python
from flask import Flask, request, jsonify
from flask_cors import CORS
import boto3
import botocore
import json
from pyfcm import FCMNotification
from models import *
import sqlalchemy
import base64
from pytz import timezone

cogcli = '7mbneubah8favrjhefcn79taum'
cog = boto3.client('cognito-idp', region_name='ap-south-1')
iotcore = boto3.client('iot-data', region_name='ap-south-1')
s3 = boto3.client('s3', region_name='ap-south-1')
application = Flask(__name__)
application.config['SQLALCHEMY_DATABASE_URI'] = 
'postgresql://postgres:pass@rds.c2ocfdyvtbwu.ap-south-1.rds.amazonaws.com:5432/postgres'
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
cors = CORS(application, resources={r'/*': {'origins': '*'}})
db.init_app(application)


# Flask Functions

@application.route('/addLock', methods=['GET', 'POST'])
def add_lock():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']

        lock = Locks(content['lockId'], checkToken['username'])
        db.session.add(lock)
        db.session.commit()

        return {
            'status': True
        }

    except sqlalchemy.exc.IntegrityError as e:
        return {
            'status': False,
            'content': 'Lock already exists!'
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False,
            'content': 'Unknown error. Please contact the developer.'
        }


@application.route('/changeOfflineCode', methods=['GET', 'POST'])
def change_offline_code():
    try:
        content = json.loads(request.data)
        lock = Locks.query.get(content['lockId'])
        username = lock.username
        owner = Users.query.get(username)

        push_service = FCMNotification(api_key='AAAASi2VHpQ:APA91bGqzWABHfFOtzeuwc1AvIjGDCtXS90JkEErLxICILPrx81ScnzZv_AhE7um20rzOYTe28Hkhy_cF3Xj5ZqxucVaYRwkDGFIiUO3_RRbvfsr1kwsZDHdzZZJTCiPpu9whij3Puoo')
        message_title = 'ACCESS'
        message_icon = 'notification_icon'
        message_body = 'Your new offline code is ' + content['offline_code']
        push_service.notify_multiple_devices(registration_ids=owner.appIds, message_title=message_title, message_body=message_body, message_icon=message_icon, low_priority=False)

        return 'true'

    except Exception as e:
        return str(e)


@application.route('/changePassword', methods=['GET', 'POST'])
def change_password():
    try:
        content = json.loads(request.data)
        res = cog.change_password(
            PreviousPassword=content['oldPassword'],
            ProposedPassword=content['newPassword'],
            AccessToken=content['accessToken']
        )

        return {
            'status': True
        }

    except cog.exceptions.NotAuthorizedException as e:
        return {
            'status': False,
            'content': 'Old password is incorrect!'
        }

    except botocore.exceptions.ParamValidationError:
        return {
            'status': False,
            'content': 'Invalid Password'
        }

    except Exception as e:
        print('Exception:', e.__class__)
        return {
            'status': False,
            'content': 'Unknown error. Please contact the developer.'
        }


@application.route('/confirmLockOperation', methods=['GET', 'POST'])
def confirmLockOperation():
    content = json.loads(request.data)
    print(content)
    data = content['data']

    add_log(data, content['username'])

    users = []
    print(data)
    lock = Locks.query.get(data['lockId'])
    operator = Users.query.get(content['username'])

    push_service = FCMNotification(api_key='AAAASi2VHpQ:APA91bGqzWABHfFOtzeuwc1AvIjGDCtXS90JkEErLxICILPrx81ScnzZv_AhE7um20rzOYTe28Hkhy_cF3Xj5ZqxucVaYRwkDGFIiUO3_RRbvfsr1kwsZDHdzZZJTCiPpu9whij3Puoo')
    message_title = 'ACCESS'
    message_icon = 'notification_icon'

    message_body = lock.alias + ' has been ' + content['operation'] + 'ed!'
    push_service.notify_multiple_devices(registration_ids=operator.appIds, message_title=message_title, message_body=message_body, message_icon=message_icon, low_priority=False)

    if data['userType'] == 'owner':
        if content['username'] != lock.username:
            users.append(lock.username)

        for rec in lock.acl:
            if rec.userType == 'Owner' and rec.username != content['username']:
                users.append(rec.username)

        for user in users:
            row = Users.query.get(user)
            message_body = lock.alias + ' has been ' + content['operation'] + 'ed by ' + content['username']
            push_service.notify_multiple_devices(registration_ids=row.appIds, message_title=message_title, message_body=message_body, message_icon=message_icon, low_priority=False)

    if data['userType'] == 'guest':
        users.append(lock.username)

        for rec in lock.acl:
            if rec.userType == 'Owner':
                users.append(rec.username)

        for user in users:
            row = Users.query.get(user)
            message_body = lock.alias + ' has been ' + content['operation'] + 'ed by ' + content['username']
            push_service.notify_multiple_devices(registration_ids=row.appIds, message_title=message_title, message_body=message_body, message_icon=message_icon, low_priority=False)

    return {
        'status': True
    }


@application.route('/deleteLock', methods=['GET', 'POST'])
def delete_lock():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']

        lock = Locks.query.get(content['lockId'])
        if lock.username != checkToken['username']:
            return 'invalid'
        db.session.delete(lock)
        db.session.commit()

        return {
            'status': True
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False,
            'content': 'Unknown error. Please contact the developer.'
        }


@application.route('/editLock', methods=['GET', 'POST'])
def edit_lock():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']

        lock = Locks.query.get(content['lockId'])
        if lock.username != checkToken['username']:
            return 'invalid'
        lock.address = content['address']
        lock.alias = content['alias']
        lock.webcam = content['webcam']
        db.session.commit()

        return {
            'status': True
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False,
            'content': 'Unknown error. Please contact the developer.'
        }


@application.route('/editPermission', methods=['GET', 'POST'])
def edit_permission():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']

        lock = Locks.query.get(content['lockId'])
        acl = Acl.query.get((content['lockId'], checkToken['username']))
        if lock.username != checkToken['username'] and acl is not None and acl.userType != 'Owner':
            return 'invalid'

        perm = Acl.query.get((content['lockId'], content['username']))
        perm.expiry = content['expiryActual']
        perm.userType = content['userType']
        if perm.userType == 'Owner':
            perm.expiry = None
        db.session.commit()

        return {
            'status': True
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False,
            'content': 'Unknown error. Please contact the developer.'
        }


@application.route('/getBluetoothAddress', methods=['GET', 'POST'])
def get_bluetooth_address():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']

        acl = Acl.query.get((content['lockId'], checkToken['username']))
        if acl is not None:
            lock = Locks.query.get(content['lockId'])
            return {
                'status': True,
                'content': lock.btAddress
            }

        else:
            return {
                'status': 'invalid'
            }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False,
            'content': 'Unknown error. Please contact the developer.'
        }


@application.route('/getNewToken', methods=['GET', 'POST'])
def call_get_new_token():
    content = json.loads(request.data)
    return get_new_token(content['refreshToken'])


@application.route('/getLocks', methods=['GET', 'POST'])
def get_locks():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']

        lockDict = {}
        locks = Users.query.get(checkToken['username']).locks

        for lock in locks:
            temp = {
                'lockId': lock.lockId,
                'alias': lock.alias,
                'address': lock.address,
                'favourite': lock.favourite,
                'webcam': lock.webcam
            }
            lockDict[lock.lockId] = temp

        return {
            'status': True,
            'content': lockDict
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False
        }


@application.route('/getOtherLocks', methods=['GET', 'POST'])
def get_other_locks():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']

        lockDict = {}
        locks = Users.query.get(checkToken['username']).acl

        for lock in locks:
            if lock.userType == 'Owner' or lock.expiry > datetime.now():
                lockDetails = Locks.query.get(lock.lockId)
                temp = {
                    'lockId': lock.lockId,
                    'expiry': lock.expiry,
                    'alias': lockDetails.alias,
                    'address': lockDetails.address,
                    'userType': lock.userType
                }
                lockDict[lock.lockId] = temp

        return {
            'status': True,
            'content': lockDict
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False
        }


@application.route('/getLogs', methods=['GET', 'POST'])
def get_logs():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']

        logArr = []
        locks = []
        users = set()

        for row in Users.query.get(checkToken['username']).locks:
            locks.append(row.lockId)

        for row in Acl.query.filter_by(username=checkToken['username'], userType='Owner'):
            locks.append(row.lockId)

        logs = Logs.query.filter(Logs.lockId.in_(locks)).order_by(Logs.time.desc()).all()

        for log in logs:
            lockAlias = Locks.query.get(log.lockId).alias
            if log.operation == 'doorbell':
                images = log.images.split(",")
            else:
                images = []
            temp = {
                'lockId': log.lockId,
                'lock': lockAlias,
                'username': log.username,
                'time': datetime.strftime(log.time, '%I:%M %P %d-%m-%y'),
                'isoTime': log.time,
                'userType': log.userType,
                'operation': log.operation,
                'images': images
            }
            if log.username and log.username != 'visitor':
                users.add(log.username)
            logArr.append(temp)

        return {
            'status': True,
            'content': {'logs': logArr, 'users': list(users)}
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False
        }


@application.route('/getPermissions', methods=['GET', 'POST'])
def get_permissions():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']
        lock = Locks.query.get(content['lockId'])
        acl = Acl.query.get((content['lockId'], checkToken['username']))
        if lock.username != checkToken['username'] and acl is not None and acl.userType != 'Owner':
            return 'invalid'

        details = []

        for acl in Acl.query.filter_by(lockId=content['lockId']).all():
            temp = {
                'userType': acl.userType,
                'username': acl.username,
                'expiryDisplay': None,
                'expiryActual': None,
                'name': Users.query.get(acl.username).name
            }
            if acl.expiry is not None:
                temp['expiryDisplay'] = datetime.strftime(acl.expiry, '%I:%M %P %d-%m-%y')
                temp['expiryActual'] = datetime.strftime(acl.expiry, '%I:%M %P %m-%d-%y')
            details.append(temp)

        return {
            'status': True,
            'content': {'details': details, 'alias': Locks.query.get(content['lockId']).alias}
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False
        }


@application.route('/grantPermission', methods=['GET', 'POST'])
def grant_permission():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']

        lock = Locks.query.get(content['lockId'])
        acl = Acl.query.get((content['lockId'], checkToken['username']))
        if lock.username != checkToken['username'] and acl is not None and acl.userType != 'Owner':
            return 'invalid'

        rec = Acl(content['lockId'], content['username'], content['userType'], content['expiryActual'])
        db.session.add(rec)
        db.session.commit()

        return {
            'status': True
        }

    except sqlalchemy.exc.IntegrityError as e:
        if ('Key (username)' in str(e)):
            return {
                'status': False,
                'content': 'User does not exist!'
            }
        elif ('already exists' in str(e)):
            return {
                'status': False,
                'content': 'Permission already granted!'
            }
        print('Exception:', e)
        return {
            'status': False,
            'content': 'Unknown error. Please contact the developer.'
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False,
            'content': 'Unknown error. Please contact the developer.'
        }


@application.route('/forgotPassword', methods=['GET', 'POST'])
def forgot_password():
    try:
        data = json.loads(request.data)
        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'
        content = data['content']
        cog.forgot_password(ClientId=cogcli, Username=content['username'])
        return 'true'
    except cog.exceptions.UserNotFoundException:
        return 'User does not exist'
    except Exception as e:
        return str(e)


@application.route('/lockOperations', methods=['GET', 'POST'])
def lock_operations():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']

        lock = Locks.query.get(content['lockId'])
        acl = Acl.query.get((content['lockId'], checkToken['username']))
        if lock.username != checkToken['username'] and acl is not None and acl.userType != 'Owner':
            return 'invalid'

        if content['operation'] not in ['lock', 'unlock']:
            return 'Invalid operation'

        content['userType'] = 'owner'

        pl = {
            'operation': content['operation'],
            'username': checkToken['username'],
            'data': content
        }
        response = iotcore.publish(topic='access/operationRequest' + content['lockId'], qos=1, payload=json.dumps(pl))

        return {
            'status': True
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False
        }


@application.route('/lockOperationsGuest', methods=['GET', 'POST'])
def lock_operations_guest():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']
        lock = Locks.query.get(content['lockId'])

        acl = Acl.query.get((content['lockId'], checkToken['username']))
        if acl is None or acl.expiry < datetime.now():
            return 'invalid'

        if content['btUUID'].lower() != lock.bleUUID:
            return {
                'status': False
            }

        if content['operation'] not in ['lock', 'unlock']:
            return 'Invalid operation'

        content['userType'] = acl.userType
        pl = {
            'operation': content['operation'],
            'username': checkToken['username'],
            'data': content
        }
        response = iotcore.publish(topic='access/operationRequest' + content['lockId'], qos=1, payload=json.dumps(pl))

        return {
            'status': True
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False
        }


@application.route('/login', methods=['GET', 'POST'])
def login():
    try:
        content = json.loads(request.data)

        auth = cog.initiate_auth(
            ClientId=cogcli,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': content['username'],
                'PASSWORD': content['password']
            }
        )

        resp = Users.query.get(content['username'])
        if not content['appId'] in resp.appIds:
            new_arr = resp.appIds.copy()
            new_arr.append(content['appId'])
            resp.appIds = new_arr
            db.session.commit()

        return {
            'status': True,
            'content': auth['AuthenticationResult']
        }

    except cog.exceptions.UserNotConfirmedException:
        return {
            'status': False,
            'content': 'User is not confirmed. Please check your mail.'
        }

    except cog.exceptions.NotAuthorizedException:
        return {
            'status': False,
            'content': 'Username/Password is incorrect'
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False,
            'content': 'Unknown error. Please contact the developer.'
        }


@application.route('/logout', methods=['GET', 'POST'])
def logout():
    try:
        content = json.loads(request.data)

        cog.global_sign_out(AccessToken=content['accessToken'])
        resp = Users.query.get(content['username'])
        new_arr = resp.appIds.copy()
        new_arr.remove(content['appId'])
        resp.appIds = new_arr
        db.session.commit()

        return {
            'status': True
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False
        }


@application.route('/notifyWebcam', methods=['GET', 'POST'])
def notify_webcam():
    try:
        content = json.loads(request.data)

        users = []
        lock = Locks.query.get(content['lockId'])
        username = lock.username
        owner = Users.query.get(username)

        push_service = FCMNotification(api_key='AAAASi2VHpQ:APA91bGqzWABHfFOtzeuwc1AvIjGDCtXS90JkEErLxICILPrx81ScnzZv_AhE7um20rzOYTe28Hkhy_cF3Xj5ZqxucVaYRwkDGFIiUO3_RRbvfsr1kwsZDHdzZZJTCiPpu9whij3Puoo')
        message_title = 'ACCESS'
        message_icon = 'notification_icon'
        message_body = 'Someone wishes to access ' + lock.alias
        push_service.notify_multiple_devices(registration_ids=owner.appIds, message_title=message_title, message_body=message_body, message_icon=message_icon, low_priority=False)

        for user in Acl.query.filter_by(lockId=content['lockId']):
            appIds = Users.query.get(user.username).appIds
            push_service.notify_multiple_devices(registration_ids=appIds, message_title=message_title, message_body=message_body, message_icon=message_icon, low_priority=False)

        return 'true'

    except Exception as e:
        return str(e)


@application.route('/register', methods=['GET', 'POST'])
def register():
    try:
        content = json.loads(request.data)

        user = Users(
            username=content['username'],
            name=content['name'],
            phone=content['phone']
        )

        cog.sign_up(
            ClientId=cogcli,
            Username=content['username'],
            Password=content['password'],
            UserAttributes=[{'Name': 'email', 'Value': content['email']}]
        )

        db.session.add(user)
        db.session.commit()

        return {
            'status': True
        }

    except cog.exceptions.UsernameExistsException:
        return {
            'status': False,
            'content': 'Username Already Exists!'
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False,
            'content': 'Unknown error. Please contact the developer.'
        }


@application.route('/revokePermission', methods=['GET', 'POST'])
def revoke_permission():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']
        lock = Locks.query.get(content['lockId'])
        acl = Acl.query.get((content['lockId'], checkToken['username']))
        if lock.username != checkToken['username'] and acl is not None and acl.userType != 'Owner':
            return 'invalid'

        perm = Acl.query.get((content['lockId'], content['username']))
        db.session.delete(perm)
        db.session.commit()

        return {
            'status': True
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False
        }


@application.route('/toggleFavourite', methods=['GET', 'POST'])
def toggle_favourite():
    try:
        data = json.loads(request.data)

        checkToken = check_access_token(data['accessToken'], data['refreshToken'])
        if not checkToken['status']:
            return 'invalid'

        content = data['content']
        lock = Locks.query.get(content['lockId'])
        if lock.username != checkToken['username']:
            return 'invalid'

        lock = Locks.query.get(content['lockId'])
        if content['choice'] == 'fav':
            lock.favourite = True
        else:
            lock.favourite = False
        db.session.commit()

        return {
            'status': True
        }

    except Exception as e:
        print('Exception:', e)
        return {
            'status': False,
            'content': 'Unknown error. Please contact the developer.'
        }


@application.route('/updateState', methods=['GET', 'POST'])
def update_state():
    try:
        content = json.loads(request.data)
        state = content['state']
        lock = Locks.query.get(content['lockId'])
        lock.state = state
        db.session.commit()
        return 'true'
    except Exception as e:
        return str(e)


@application.route('/updateUUID', methods=['GET', 'POST'])
def update_uuid():
    try:
        content = json.loads(request.data)
        uuid = content['uuid']
        lock = Locks.query.get(content['lockId'])
        lock.bleUUID = uuid
        db.session.commit()
        return 'true'
    except Exception as e:
        return str(e)


@application.route('/uploadImage', methods=['GET', 'POST'])
def upload_image():
    try:
        content = json.loads(request.data)
        lockId = content['lockId']
        images = ""
        i = 1
        for thisframe in content['frames']:
            frame = base64.decodebytes(thisframe.encode('ascii'))
            filename = lockId + str(datetime.now(timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M')) + "(" + str(i) + ")" + ".jpg"
            s3.put_object(Key=filename, Bucket='access-images', Body=frame, ACL='public-read-write')
            s3url = "https://access-images.s3.ap-south-1.amazonaws.com/" + filename
            i += 1
            if images == "":
                images += s3url + ","
            else:
                images += s3url
        doorbell = {
            'lockId': content['lockId'],
            'operation': 'doorbell',
            'userType': 'visitor',
            'images': images
        }
        thislock = Locks.query.get(content['lockId'])
        add_log(doorbell, 'visitor')
        return 'true'

    except Exception as e:
        return "s3 error" + str(e)


# Non-Flask Functions

def add_log(content, username):
    try:
        if not content['images']:
            content['images'] = None
        lg = Logs(content['lockId'], username, content['operation'], content['userType'], content['images'])
        db.session.add(lg)
        db.session.commit()
        return True
    except Exception as e:
        print('Exception:', e)
        return False


def check_access_token(accessToken, refreshToken):
    try:
        user = cog.get_user(AccessToken=accessToken)
        return {
            'status': True,
            'username': user.Username
        }
    except Exception as e:
        newToken = get_new_token(refreshToken)
        if newToken['status']:
            user = cog.get_user(AccessToken=newToken['content']['AccessToken'])
            return {
                'status': True,
                'username': user['Username']
            }
        else:
            print('Exception:', e)
            return {
                'status': False
            }


def get_new_token(refreshToken):
    try:
        auth = cog.initiate_auth(
            AuthFlow='REFRESH_TOKEN_AUTH',
            AuthParameters={
                'REFRESH_TOKEN': refreshToken
            },
            ClientId=cogcli
        )
        return {
            'status': True,
            'content': auth['AuthenticationResult']
        }
    except Exception as e:
        print('Exception:', e)
        return {
            'status': False
        }


if __name__ == '__main__':
    application.run(host='0.0.0.0', debug=True)
