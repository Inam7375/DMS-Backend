import json
from werkzeug.security import check_password_hash
from flask import Flask, request, make_response
from flask_restful import Resource, Api
from flask_cors import CORS
import datetime
import jwt
from functools import wraps
from db import get_documents, save_user, get_user, update_user, save_document, save_log, get_log, get_departments, del_department, save_department, update_department, get_log_sequence, get_user_created_document, get_user_pending_document, get_users, del_user, update_completion, get_user_completed_document, save_user_approved_documents, save_user_notify, get_user_notifications


app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY'] = "mysecretkey"
CORS(app)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return {'msg': 'Token is missing'}, 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = get_user(data['username'])
        except Exception:
            return {'msg': 'Token is invalid'}, 401

        return f(current_user, *args, **kwargs)
    return decorated


class Login(Resource):
    def post(self):
        # auth = request.authorization
        json_data = request.get_json(force=True)
        username = json_data['username']
        password = json_data['password']

        if not username or not password:
            return make_response(
                'Could not verify 1',
                401,
                {'WWW-Authenticate': 'Basic realm="Login required!"'})

        user = get_user(username)
        if not user:
            return make_response(
                'User Not Found',
                401,
                {'WWW-Authenticate': 'Basic realm="Login required!"'})

        if check_password_hash(user['password'], password):
            token = jwt.encode({
                'username': user['_id'],
                'fullName': user['name'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                app.config['SECRET_KEY']
            )
            isAdmin = True if user['role'] == 'Super Admin' else False
            return {'token': token, 'isAdmin': isAdmin}

        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm="Login required!"'})


class Users(Resource):
    def get(self):
        users = get_users()
        return {'results': users}


class User(Resource):
    def get(self, username):
        user = get_user(username)
        if user:
            return user, 201
        else:
            return {'msg': 'User not found'}, 203

    def post(self, username):
        json_data = request.get_json(force=True)
        uName = json_data['un']
        name = json_data['name']
        email = json_data['email']
        password = json_data['password']
        department = json_data['department']
        designation = json_data['designation']
        role = json_data['role']

        try:
            user = get_user(uName)
            if user:
                return {'msg': "User Already Exists"}, 203
            resp = save_user(uName, name, email, password,
                             department, designation, role)
            if resp:
                return {'msg': "User Succesfully Created"}, 201
            else:
                return {'msg': 'User can not be created'}, 203
        except Exception:
            return {'msg': 'Server Error'}, 500

    def put(self, username):
        # Validating the user
        user = get_user(username)
        if not user:
            return {"msg": "User does not Exists"}, 203

        json_data = request.get_json(force=True)
        # uName = json_data['un']
        name = json_data['name']
        email = json_data['email']
        password = json_data['password']
        department = json_data['department']
        designation = json_data['designation']
        role = json_data['role']

        try:
            resp = update_user(username, name, email, password,
                               department, designation, role)
            if resp:
                return {'msg': "User Succesfully Updated"}, 201
            else:
                return {'msg': 'Server error, try again later'}, 500
        except Exception as e:
            print(e)

    def delete(self, username):
        try:
            user = get_user(username)
            if not user:
                return {'msg': "User Not Exists"}, 203
            res = del_user(username)
            if res:
                return {'msg': 'User Succesfully Deleted'}, 201
            else:
                return {'msg': 'User Cannot be Deleted'}, 203

        except Exception as e:
            return {'msg': 'Server error, try again later'}, 500


class UserNotifications(Resource):
    def get(self, uname):
        notifications = get_user_notifications(uname)
        if notifications:
            return {'results': notifications}, 200
        else:
            return {'msg': "No notifications found"}, 404

    def put(self, uname):
        try:
            json_data = request.get_json(force=True)
            docID = json_data['docID']
            created = False
            resp = save_user_notify(docID, created)
            if resp:
                return {'msg': "Document succesfully saved"}, 200
            else:
                return {'msg': "Document was unable to save"}, 500
        except Exception as e:
            print(e)
            return {'msg': "Document was unable to save"}, 500


class Departments(Resource):
    def get(self):
        try:
            departmentsList = get_departments()
            if departmentsList:
                return {'results': departmentsList}, 200
            return {'msg': 'Departments Not Found'}, 203
        except Exception:
            return {'msg': "Server error"}, 500

    def post(self):
        json_data = request.get_json(force=True)
        depName = json_data['_id']
        depHOD = json_data['depHOD']
        about = json_data['about']
        try:
            resp = save_department(depName, depHOD, about)
            if resp:
                return {"msg": "Department succesfully Added"}, 201
            else:
                return {"msg": "Department Already Exists"}, 203
        except Exception:
            return {"msg": "Error in saving deparment"}, 500

    def put(self):
        json_data = request.get_json(force=True)
        depName = json_data['_id']
        depHOD = json_data['depHOD']
        about = json_data['about']
        try:
            resp = update_department(depName, depHOD, about)
            if resp:
                return {"msg": "Department succesfully updated"}, 201
            else:
                return {"msg": "Department Already Exists"}, 203
        except Exception:
            return {"msg": "Error in updating department"}, 500


class Department(Resource):
    def delete(self, id):
        try:
            res = del_department(id)
            if res:
                return {'msg': 'Department Succesfully  Deleted'}, 201
            else:
                return {'msg': 'Department cannot be Deleted'}, 203
        except Exception as e:
            return {'msg': 'Server error, try again later'}, 500


class UserDocuments(Resource):
    def get(self, uname):
        documents = get_user_created_document(uname)
        return {'results': documents}


class UserDocumentsPending(Resource):
    def get(self, uname):
        documents = get_user_pending_document(uname)
        return {'results': documents}


class UserDocumentsApproved(Resource):
    def put(self, uname):
        json_data = request.get_json(force=True)
        docID = json_data['docID']
        resp = save_user_approved_documents(uname, docID)
        if resp:
            return {'msg': 'Approved document saved'}, 200
        else:
            return {'msg': 'Internal server error'}


class UserDocumentsCompleted(Resource):
    def get(self, uname):
        documents = get_user_completed_document(uname)
        return {'results': documents}


class UpdateDocuments(Resource):
    def put(self):
        json_data = request.get_json(force=True)
        docID = json_data['docID']
        resp = update_completion(docID)
        if resp:
            return {'msg': 'Document Completed'}, 200
        else:
            return {'msg': 'Inter Server Error'}, 500


class Documents(Resource):
    def get(self):
        documents = get_documents()
        return {'results': documents}

    def post(self):
        json_data = request.get_json(force=True)
        title = json_data['title']
        frmUser = json_data['created_by_user']
        frmUname = json_data['created_by_uname']
        frmDep = json_data['created_by_department']
        targetUser = json_data['target_user']
        targetDep = json_data['target_department']
        dsc = json_data['description']
        try:
            resp = save_document(title, frmUser, frmUname,
                                 frmDep, targetUser, targetDep, dsc)
            if resp:
                return {'msg': 'Document Saved'}, 200
            else:
                return {'msg': 'Server Error'}, 500
        except Exception:
            return {'msg': 'Server Error'}, 500


class Logs(Resource):
    def get(self, docID):
        # json_data = request.get_json(force=True)
        # docID = json_data['docID']
        try:
            log = get_log(docID)
            sequence = get_log_sequence(docID)
            if log:
                if sequence:
                    return {'results': log, 'sequence': sequence}, 200
                else:
                    return {'results': log}, 200
            else:
                return {'msg': 'Server error'}, 500
        except Exception:
            return {'msg': 'Server error'}, 500

    def put(self, docID):
        json_data = request.get_json(force=True)
        docID = json_data['docID']
        forwardedToUname = json_data['forwardedToUname']
        forwardedDep = json_data['forwardedDep']
        objection = json_data['objection']
        comments = json_data['comments']
        date = json_data['date']
        try:
            log = save_log(docID, forwardedToUname,
                           forwardedDep, objection, comments, date)
            if log:
                return {"msg": "Log Updated"}, 200
            else:
                return {"msg": "Server Error"}, 500
        except Exception:
            return {"msg": "Server Error"}, 500


api.add_resource(Users, '/api/users')
api.add_resource(Login, '/api/login')
api.add_resource(User, '/api/user/<username>')
api.add_resource(UserNotifications, '/api/usernotify/<uname>')
api.add_resource(Documents, '/api/documents')
api.add_resource(UpdateDocuments, '/api/updatedocuments')
api.add_resource(UserDocuments, '/api/userdocuments/<uname>')
api.add_resource(UserDocumentsCompleted, '/api/usercompleteddocuments/<uname>')
api.add_resource(UserDocumentsPending, '/api/userpendingdocuments/<uname>')
api.add_resource(UserDocumentsApproved, '/api/userapproveddocuments/<uname>')
api.add_resource(Logs, '/api/logs/<docID>')
api.add_resource(Departments, '/api/departments')
api.add_resource(Department, '/api/department/<id>')

if __name__ == '__main__':
    app.run(debug=True)
