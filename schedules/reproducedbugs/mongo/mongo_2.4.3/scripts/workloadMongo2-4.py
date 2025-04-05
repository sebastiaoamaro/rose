from pymongo import MongoClient
from multiprocessing import Pool
import time

file_path = "output.log"

def deleteAll(coll):
    coll.remove({})
    print("[Delete] all")

def write(id, coll):
    coll.insert({'_id': id, 'list': []})
    print("[Write] id:{}".format(id))

def read(id, coll):
    one = coll.find_one({'_id': id})
    with open(file_path, "a") as f:
        f.write("R|{}|{}\n".format(id, one['list']))
    return one

def append(id, val, coll):
    my_query = { "_id": id }
    new_values = { "$push": { "list": val } }
    result = coll.update(my_query, new_values, multi=False)
    #print(result)
    if result['updatedExisting']:
        print("I|{}|{}".format(id, val))
    else:
        print("E|{}|{}".format(id, val))

def workload0(data):
    client = MongoClient(host=[data[1]])
    myDb = client["testdbbug"]
    myCollec = myDb.testcollbug
    try:
        deleteAll(myCollec)
        time.sleep(0.5)
    except Exception as e:
        print("Couldn't delete all: {}".format(e))

    try:
        write(0, myCollec)
        time.sleep(0.5)
    except Exception as e:
        print("Couldn't write: {}".format(e))

    id = 0
    primary = False
    for i in range(data[0] * 100000, data[0] * 100000 + 20000):
        #print("Adding i:{} to {}".format(i, str(data[1])))
        time.sleep(0.01)
        try:
            append(id, i, myCollec)
            read(0, myCollec)
        except Exception as e:
            while not primary:
                try:
                    time.sleep(0.01)
                    append(id, i, myCollec)
                    read(0, myCollec)
                    primary = True
                except Exception as e:
                    print("Failed to append on client {}: {}".format(data[1], e))

if __name__ == "__main__":
    # Reset output file
    with open(file_path, "w") as f:
        f.write("")

    args = [
        [0, '172.20.0.2:27017'],
        [1, '172.20.0.3:27017'],
        [2, '172.20.0.4:27017'],
        [3, '172.20.0.5:27017'],
        [4, '172.20.0.6:27017']
    ]

    p = Pool(5)  # Create a Pool with 5 processes
    p.map(workload0, args)  # Map the workload0 function to the arguments
    p.close()  # Close the Pool to prevent further tasks
    p.join()















    '''
    # client0 = MongoClient(host = [ '172.20.0.2:27017' ])
    # client1 = MongoClient(host = [ '172.20.0.3:27017' ])
    # client2 = MongoClient(host = [ '172.20.0.4:27017' ])
    # client3 = MongoClient(host = [ '172.20.0.5:27017' ])
    # client4 = MongoClient(host = [ '172.20.0.3:27017' ])
    # #client = MongoClient('mongodb://mongo0:27017,mongo1:27017,mongo2:27017/?replicaSet=rs0')

    # myDb = client4.get_database("testdbbug")
    # myCollec = myDb.testcollbug # myDb['colltestbug']

    # deleteAll()
    # write(0, myCollec)

    # w = [workload0, workload1, workload2, workload3, workload4]
    # arguments = [0,1,2,3,4]
    # job = [Process(target=w[i], args=(arguments[i])) for i in range(1)]
    # # job = [Process(target=w[i], args=(output_list, arguments[i])) for i in range(4)]
    # for p in job:
    #     p.start()
    # for p in job:
    #     p.join()


    myDb = client.get_database("dbtestbug",
                read_concern=read_concern.ReadConcern('snapshot'),
                write_concern=WriteConcern("majority", wtimeout=1000),
                read_preference=ReadPreference.PRIMARY) # client['dbtestbug']
    myCollec = myDb.colltestbug # myDb['colltestbug']

    print("", file=open(file_path, "w"))

    coll_id = Value('i', 0)

    manager = Manager()
    output_list = manager.list()

    init(10)



    w = [workload0, workload1, workload2, workload3, workload4]
    arguments = create_inputs(2)
    job = [Process(target=w[i], args=({output_list})) for i in range(4)]
    # job = [Process(target=w[i], args=(output_list, arguments[i])) for i in range(4)]
    for p in job:
        p.start()
    for p in job:
        p.join()

    for i in output_list:
        pprint(i)
    '''
