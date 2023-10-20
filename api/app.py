'''
Coding For Security - CP 6 - Python sniffer & API for capturing raw frames.
Guilherme Valloto, RM550353,
Victória Ventrilho, RM94872,
Vitor Arakaki, RM98824
'''

from flask import Flask
from flask import request
from flask import jsonify
import json
from bson import json_util
from types import SimpleNamespace
import pymongo

# Client interface between our API and the dabatase data
client = pymongo.MongoClient("mongodb://localhost:27017")

# Creating a database named "pdus_db"
db = client["pdus_db"]

# Creating a collection named "pdus"
pdu_collection = db["pdus"]

app = Flask(__name__)

# Get all PDUs endpoint.
@app.get('/pdus')
def get_pdus():
    return json.loads(json.dumps(json_util.dumps(pdu_collection.find())))

# Create a PDU endpoint.
@app.post('/pdus')
def post_pdus():
    x = json.loads(request.data, object_hook=lambda d: SimpleNamespace(**d))
    pdu_collection.insert_one(json.loads(request.data))

    return json.loads(request.data)

@app.delete('/pdus')
def delete_pdus():
    db.pdus.delete_many({})
    return "OK"
