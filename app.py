from flask import Flask, request
from flask_restful import Resource, Api
from db import get_users, get_documents, save_user, get_user, update_user, save_document, save_log, get_log, get_departments, save_department, update_department, get_log_sequence, save_log_sequence
from flask_cors import CORS


app = Flask(__name__)
api = Api(app)
CORS(app)

class Users(Resource):
    def get(self):
        users = get_users()
        return {'results': users}

class User(Resource):
    def get (self, username):
        user = get_user(username)
        if user:
            return user, 200
        else:
            return {'msg' : 'User not found'}, 404

    def post(self, username):
        json_data = request.get_json(force=True)
        uName = json_data['username']
        name = json_data['name']
        email = json_data['email']
        password = json_data['password']
        department = json_data['department']
        designation = json_data['designation']
        role = json_data['role']

        try:
            resp = save_user(uName, name, email, password, department, designation, role)
            if resp:
                return { 'msg': "User Created" }, 201
            else:
                return {'msg': 'Username already exists'}, 422
        except Exception:
            return {'msg': 'User can not be created'}, 500
    
    def put(self, username):
        #Validating the user
        user = get_user(username)
        if not user:
            return {"msg": "User does not exist"}, 404

        json_data = request.get_json(force=True)
        uName = json_data['username']
        name = json_data['name']
        email = json_data['email']
        password = json_data['password']
        department = json_data['department']
        designation = json_data['designation']
        role = json_data['role']

        try:
            resp = update_user(uName, name, email, password, department, designation, role)
            if resp:
                return { 'msg': "User Updated" }, 201
            else:
                return {'msg': 'Server error, try again later'}, 500
        except Exception as e:
            print(e)

class Departments(Resource):
    def get(self):
        try:
            departmentsList = get_departments()
            if departmentsList :
                return {'results': departmentsList}, 200
            return {'msg': 'Departments Not Found'}, 405
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
                return {"msg": "Department succesfully saved"}
            else:
                return {"msg": "Department could not be saved"}
        except Exception:
            return {"msg": "Error in saving deparment"}
    
    def put(self):
        json_data = request.get_json(force=True)
        depName = json_data['_id']
        depHOD = json_data['depHOD']
        about = json_data['about']
        try:
            resp = update_department(depName, depHOD, about)
            if resp:
                return {"msg": "Department succesfully updated"}
            else:
                return {"msg": "Department could not be updated"}
        except Exception:
            return {"msg": "Error in updating department"}

class Documents(Resource):
    def get(self):
        documents = get_documents()
        return {'results': documents}
    
    def post(self):
        json_data = request.get_json(force=True)
        docID = json_data['_id']
        title = json_data['title']
        frmUser = json_data['created_by_user']
        frmDep = json_data['created_by_department']
        targetUser = json_data['target_user']
        targetDep = json_data['target_department']
        dsc = json_data['description']
        try:
            resp = save_document(docID, title, frmUser, frmDep, targetUser, targetDep, dsc)
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
                    return {'results': log, 'sequence':sequence}, 200
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
        try :
            log = save_log(docID, forwardedToUname, forwardedDep, objection, comments, date)
            if log :
                return {"msg": "Log Updated"}, 200
            else:
                return {"msg": "Server Error"}, 500
        except Exception:
            return {"msg": "Server Error"}, 500

api.add_resource(Users, '/api/users')
api.add_resource(User, '/api/user/<username>')
api.add_resource(Documents, '/api/documents')
api.add_resource(Logs, '/api/logs/<docID>')
api.add_resource(Departments, '/api/departments')

if __name__=='__main__':
    app.run(debug=True)