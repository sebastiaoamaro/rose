from pymongo import MongoClient
from pprint import pprint
from copy import deepcopy

client = MongoClient(host=["172.19.0.2"])


myDb = client.testdb # client['testdb']
myCol = myDb.testdb  # myDb['testdb']

database_dic = {}
global_i = 0

def write_to_dic(id):
    database_dic[id] = list([])

def write(id):
    myCol.insert_one({'id': id, 'list': []})
    #write_to_dic(id)
    #print(f"[Write ] id:{id}")

def read(id):
    one = myCol.find_one({'id': id})
    print(f"[Read  ] id:{one['id']} list:{one['list']}")

    return one

def append(id, value):
    myquery = { "id": id }
    newList = read(id)['list']
    oldList = deepcopy(newList)
    newList.append(value)
    newvalues = { "$set": { "list": newList } }

    myCol.update_one(myquery, newvalues)

    print(f"[Append] id:{id} list:{newList}")

def incr(id):
    myQuery = { "id": id }
    if(id in database_dic):
        database_dic[id] = database_dic[id] + [database_dic[id][-1] + 1]
    else:
        write(id)
        database_dic[id] = [0]
    newvalues = { "$set": { "list": database_dic[id] } }

    myCol.update_one(myQuery, newvalues)

    print(f"[Increm] id:{id} list:{database_dic[id]}")

def delete(id):
    myQuery ={ 'id': id } 
    myCol.delete_one(myQuery) 

    print(f"[Delete] id:{id}")

def deleteAll():
    global global_i
    global_i = 0
    myCol.delete_many({})
    print(f"[Delete] all")

def workload0():
    deleteAll()

def workload1():
    global global_i
    write(global_i)
    global_i += 1

    
def workload2(id):
    read(id)

def workload3(num):
    for i in range(num):
        workload1()

def workload4(num):
    global global_i
    if(num > global_i):
        print("Cannot read")
    for i in range(num):
        workload2(i)

def workload5(id):
    incr(id)

def workload6(id):
    for i in range(5):
        incr(id)

def workload8():
    for i in range(12):
        write(i)
        for j in range(5):
            append(i, j)
        read(i)

def workload9():
    for i in range(5):
        write(i)
    
    for j in range(5):
        incr(i)
        read(i)

def workload10():
    for i in range(12):
        write(i)

def workload11():
    write(0)
    incr(0)
    incr(0)
    incr(0)
    incr(0)
    incr(0)

def workload12():
    deleteAll()

    print('all')
    for x in myCol.find():
        print(x)

    write(0)
    write(1)
    write(2)

    pprint(read(0))
    pprint(read(2))

    append(0, 1)
    append(1, 2)
    append(2, 0)

    pprint(read(0))
    pprint(read(1))
    pprint(read(2))

    incr(0)
    incr(1)
    incr(2)

    for x in myCol.find():
        print(x)

    delete(2)

    for x in myCol.find():
        print(x)

    delete(0)

    for x in myCol.find():
        print(x)

    deleteAll()

    for x in myCol.find():
        print(x)

import os
# inp = int(input("Workload number: \n"))
inp=3
if(inp == 0):
    workload0()
elif(inp == 1):
    workload1()
elif(inp == 2):
    id = int(input("Read id: \n"))
    workload2(id)
elif(inp == 3):
    workload3(100_000)
elif(inp == 4):
    num = int(input("num of Reads: \n"))
    workload4(num)
elif(inp == 5):
    id = int(input("Increment id: \n"))
    workload5(id)
    pass
elif(inp == 6):
    id = int(input("Increment id: \n"))
    workload6(id)
    pass
elif(inp == 7):
    #workload7()
    pass
elif(inp == 8):
    workload8()
elif(inp == 9):
    workload9()
    pprint(database_dic)
elif(inp == 10):
    workload10()
elif(inp == 11):
    workload11()                
elif(inp == 12):
    workload12()