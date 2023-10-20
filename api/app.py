from flask import Flask
from flask import request
import sys
sys.path.insert(1, "../common")
from frame import *
from packet import *
from segment import *
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
    data = []
    for x in pdu_collection.find():
        data.append(x)
    
    return json.loads(json.dumps(json_util.dumps(data)))

# Create a PDU endpoint.
@app.post('/pdus')
def post_pdus():
    x = json.loads(request.data, object_hook=lambda d: SimpleNamespace(**d))
    pdu_collection.insert_one(json.loads(request.data))

    return json.loads(request.data)