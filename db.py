from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from bson import json_util
from flask import jsonify
import json
from datetime import datetime

client = MongoClient(
    "mongodb+srv://Inam:inam123@devconnector.acy6n.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")
# client = MongoClient("mongodb://localhost:27017/fuuast")

database = client.get_database("fuuast")
user_collection = database.get_collection("users")
user_notify_collection = database.get_collection("user_notifications")
doc_collection = database.get_collection("documents")
log_collection = database.get_collection("logs")
department_collection = database.get_collection("department")
sequence_collection = database.get_collection("sequences")
doc_sequence_collection = database.get_collection("document_sequence")
doc_approval_collection = database.get_collection("approved_document_sequence")


def myconverter(o):
    if isinstance(o, datetime):
        return o.__str__()


def parse_json(data):
    return json.loads(json_util.dumps(data))


def get_users():
    users = list(user_collection.find())
    for i in users:
        i['date_created'] = json.dumps(i['date_created'], default=myconverter)
    return users


def get_user(uname):
    try:
        user = user_collection.find_one({'_id': uname})
        if user:
            user['date_created'] = json.dumps(
                user['date_created'], default=myconverter)
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


def save_user_notify(
    docID,
    created=False,
):
    try:
        document = doc_collection.find_one({'_id': docID})
        user_notify_collection.find_one_and_update({
            'uname': document['target_user']
        }, {
            '$push': {
                'notifications': {
                    'title': "New document in pending",
                    'docID': docID,
                    'msg': str(docID) + " is pending...",
                    'icon': "AlertOctagonIcon",
                    'time': datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                    'category': "success"
                }
            }
        },
            upsert=True)

        if created != True:
            user_notify_collection.find_one_and_update({
                'uname': document['created_by_user']
            }, {
                '$push': {
                    'notifications': {
                        'title': "New update in your document",
                        'docID': docID,
                        'msg': str(docID) + " recieved a new update.",
                        'icon': "MailIcon",
                        'time': datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                        'category': "primary"
                    }
                }
            },
                upsert=True)
        else:
            pass

        return True
    except Exception as e:
        print(e)
        return False


def get_user_notifications(
    uname
):
    try:
        notifications = user_notify_collection.find({'uname': uname})
        notifications = list(notifications)
        notifications = notifications[0]['notifications']
        # notifications = [{k: v for k, v in d.items() if k != '_id'} for d in notifications]
        notifications = sorted(
            notifications, key=lambda k: k['time'], reverse=True)
        print(notifications)
        return notifications
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
            {'$set': {
                'depHOD': depHOD,
                'about': about
            }
            })
        return True
    except Exception:
        return False


def del_department(id):
    try:
        department_collection.delete_one({'_id': id})
        return True

    except Exception:
        return False


def get_documents():
    documents = list(doc_collection.find())
    for i in documents:
        i['date_created'] = json.dumps(
            i['date_created'], default=myconverter).split(" ")[0]
        i['_id'] = parse_json(i['_id'])
    return documents


def get_user_created_document(uname):
    documents = list(doc_collection.find({
        'created_by_uname': uname,
        'isCompleted': False
    }))
    for i in documents:
        i['date_created'] = json.dumps(
            i['date_created'], default=myconverter).split(" ")[0]
        i['_id'] = parse_json(i['_id'])
    return documents


def get_user_completed_document(uname):
    documents = list(doc_collection.find({
        'created_by_uname': uname,
        'isCompleted': True
    }))
    for i in documents:
        i['date_created'] = json.dumps(
            i['date_created'], default=myconverter).split(" ")[0]
        i['_id'] = parse_json(i['_id'])
    return documents


def get_user_pending_document(uname):
    documents = list(doc_collection.find({
        'target_user': uname
    }))
    for i in documents:
        i['date_created'] = json.dumps(
            i['date_created'], default=myconverter).split(" ")[0]
        i['_id'] = parse_json(i['_id'])
    return documents


def save_user_approved_documents(uname, docID):
    try:
        doc_approval_collection.find_one_and_update({
            'uname': uname
        }, {
            '$push': {
                'documents': docID
            }
        },
            upsert=True)
        return True
    except:
        return False


def get_user_approved_document(uname):
    ids = doc_approval_collection.find({'uname': uname})
    if ids:
        ids = list(ids)
        ids = ids[0]['documents']
        ids = list(dict.fromkeys(ids))
        documents = doc_collection.find()
        print(list(documents))


def save_document(
    title,
    createdByName,
    createdByUName,
    createdByDep,
    targetUName,
    targetUDep,
    description
):
    try:
        resp = get_docID_sequence()
        resp = int(resp)
        doc_collection.insert_one({
            '_id': createdByDep + "-" + str(int(resp)),
            'title': title,
            'created_by_user': createdByName,
            'created_by_uname': createdByUName,
            'created_by_department': createdByDep,
            'target_user': targetUName,
            'isCompleted': False,
            'archived': False,
            'target_department': targetUDep,
            'description': description,
            'date_created': datetime.now()
        })
        inc_docID_sequence()
        save_user_notify(createdByDep + "-" + str(int(resp)), True)
        return True
    except Exception as e:
        print(e)
        return False


def update_completion(docID):
    try:
        doc_collection.find_one_and_update({
            '_id': docID
        },
            {
            '$set': {
                'isCompleted': True
            }
        })
        return True
    except Exception as e:
        print(e)
        return False


def document_archived(docID):
    try:
        doc_collection.find_one_and_update({
            '_id': docID
        },
            {
            '$set': {
                'archived': True
            }
        })
        return True
    except Exception as e:
        print(e)
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
        }, {
            '$push': {
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


def inc_docID_sequence():
    try:
        doc_sequence_collection.find_one_and_update({
            'collection': 'dep_seq'
        }, {
            '$inc': {
                'id': 1
            }
        },
            return_document=True)
        return True
    except:
        return False


def get_docID_sequence():
    try:
        seq = doc_sequence_collection.find_one({
            'collection': 'dep_seq'
        })
        return seq['id']
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

    # create log db
    try:
        log = get_log(docID)
        if log:
            save_log_sequence(docID)
        log_collection.find_one_and_update({
            'docID': docID
        }, {
            '$push':
                {
                    'logList': {
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

        doc_collection.find_one_and_update({
            "_id": docID
        }, {
            "$set": {
                "target_user": forwardedToUname
            }
        })
        return True
    except Exception as e:
        print(e)
        return False


if __name__ == "__main__":
    get_user_notifications('Hamza9211')
