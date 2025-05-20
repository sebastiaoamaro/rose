import redis
import random
import string
import sys
import time
import random
import concurrent.futures

def workload(num_operations,r,number):
    print("I am"+str(number))
    # Perform the specified number of operations
    for i in range(num_operations):
        key = generate_random_string()
        value = generate_random_string()
        # Use a pipeline to execute the SET and GET commands as a transaction
        with r.pipeline() as pipe:
            try:
                pipe.multi()  # Start the transaction
                pipe.set(key, value)
                pipe.get(key)
                result = pipe.execute()  # Execute the transaction
                # Uncomment the line below to see the results
                #print(f"Set {key} to {value}, got {result[1]}")
            except redis.exceptions.RedisError as e:
                print(f"Transaction failed: {e}"+ " " + str(number))
                continue


def generate_random_string(length=5):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

if __name__ == "__main__":
    
    num_operations = int(sys.argv[1])

    redis_conns = []
    redis_conns.append(redis.Redis(host='172.19.1.10', port=5001, decode_responses=True))
    redis_conns.append(redis.Redis(host='172.19.1.11', port=5001, decode_responses=True))
    redis_conns.append(redis.Redis(host='172.19.1.12', port=5001, decode_responses=True))
    redis_conns.append(redis.Redis(host='172.19.1.13', port=5001, decode_responses=True))
    redis_conns.append(redis.Redis(host='172.19.1.14', port=5001, decode_responses=True))

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        # Submit tasks to the thread pool
        redis_conns_20 = redis_conns * 4
        futures = []
        for i in range(20):
            future = executor.submit(workload, num_operations,redis_conns_20[i],i)
            futures.append(future)


        #futures = [executor.submit(workload, num_operations,redis_conns[i]) for i in range(5)]

        # Collect results as they complete
        count_conn = 0
        for future in concurrent.futures.as_completed(futures):
            print("Ended thread number "+str(count_conn) + "\n")
            result = future.result()
            #print(result+"\n")
            count_conn+=1