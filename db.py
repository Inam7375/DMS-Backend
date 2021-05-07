from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from bson import json_util
from flask import jsonify
import json
from datetime import datetime

client = MongoClient("mongodb+srv://Inam:inam123@devconnector.acy6n.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")

database = client.get_database("fuuast")
user_collection = database.get_collection("users")
doc_collection = database.get_collection("documents")
log_collection = database.get_collection("logs")
department_collection = database.get_collection("department")
sequence_collection = database.get_collection("sequences")

def myconverter(o):
    if isinstance(o, datetime):
        return o.__str__()

def parse_json(data):
    return json.loads(json_util.dumps(data))

def get_users():
    users = list(user_collection.find())
    for i in users:
        i['date_created'] = json.dumps(i['date_created'], default = myconverter)
    return users 

def get_user(uname):
    try:
        user = user_collection.find_one({'_id': uname})
        if user:
            user['date_created'] = json.dumps(user['date_created'], default = myconverter)
            return user
        else:
            return False
    except Exception:
        return False


def save_user(uname, name, email, password, dpt, desig, role):
    hash_pass = generate_password_hash(password)
    try:
        user_collection.insert_one({
            '_id': uname,
            'name': name,
            'email': email,
            'password': hash_pass,
            'department': dpt,
            'designation': desig,
            'role': role,
            'date_created': datetime.now()
            })
        return True
    except Exception:
        return False

def update_user(uname, name, email, password, dpt, desig, role):
    try:
        user_collection.find_one_and_update(
            {'_id': uname},
            {"$set": {
                '_id': uname,
                'name': name,
                'email': email,
                'password': password,
                'department': dpt,
                'designation': desig,
                'role': role,
                'date_created': datetime.now()
                }
            })
        return True
    except Exception as e:
        print(e)
        return False

def save_department(
    depName, 
    depHOD,
    about
    ):
    try:
        department_collection.insert_one({
            "_id": depName,
            "depHOD": depHOD,
            "about": about
        })
        return True
    except Exception:
        return False

def get_departments():
    try:
        departments = list(department_collection.find())
        if len(departments) < 1:
            return False
        for i in departments:
            i['_id'] = parse_json(i['_id'])
        return departments
    except Exception:
        return False

def update_department(depName, depHOD, about):
    try:
        department_collection.find_one_and_update(
            {'_id': depName},
            {'$set':{
                'depHOD': depHOD,
                'about': about
            }
            })
        return True
    except Exception:
        return False

    
def get_documents():
    documents = list(doc_collection.find())
    for i in documents:
        i['date_created'] = json.dumps(i['date_created'], default = myconverter).split(" ")[0]
        i['_id'] = parse_json(i['_id'])
    return documents

def save_document(
    id,
    title,
    createdByUName,
    createdByDep,
    targetUName,
    targetUDep,
    description
    ):
    try:
        doc_collection.insert_one({
            '_id' : id,
            'title': title,
            'created_by_user': createdByUName,
            'created_by_department': createdByDep,
            'target_user': targetUName,
            'target_department': targetUDep,
            'description': description,
            'date_created': datetime.now()
            })
        return True
    except Exception:
        return False

def get_log(docID):
    try:
        log = log_collection.find_one({'docID': docID})
        if not log:
            print(docID)
            print("Not found")
            return False
        log['_id'] = parse_json(log['_id'])
        return log
    except Exception as e:
        print(e)
        return False

def save_log_sequence(
    docID
):
    try:
        sequence_collection.find_one_and_update({
            "docID": docID
        },{
            '$push':{
                "sequence": [
                    "Recieved"
                ]
            }
        },
        return_document=True,
        upsert=True)
        return True
    except:
        return False

def get_log_sequence(docID):
    try:
        resp = sequence_collection.find_one({'docID': docID})
        if resp:
            resp['_id'] = parse_json(resp['_id'])
            return resp
        else:
            return False
    except Exception:
        return False

def save_log(
    docID,
    forwardedToUname,
    forwardedDep,
    objection,
    comments,
    date
):

    #create log db
    try:
        log = get_log(docID)
        if log:
            save_log_sequence(docID)
        log_collection.find_one_and_update({
            'docID': docID
        }, {
                '$push':
                {
                    'logList' : {
                    'forwardedToUname': forwardedToUname,
                    'forwardedDep': forwardedDep,
                    'objection': objection,
                    'comments': comments,
                    'date': date,
                    }
                },
            },
        return_document=True,
        upsert=True
        )
        return True
    except Exception as e:
        print(e)
        return False
    
if __name__ == "__main__":
    get_documents()