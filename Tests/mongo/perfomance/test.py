from pymongo import MongoClient

#Checks if replicaset started
try:
    client = MongoClient(host=["172.19.0.2"])
    myDb = client.testdb # client['testdb']
    myCol = myDb.testdb  # myDb['testdb']
    myCol.insert_one({'id': 1, 'list': []})
except :
    print("No")
    exit()

print("Yes")