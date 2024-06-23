from redis.cluster import RedisCluster as Redis
import random
import string
import sys


# Function to generate random strings
def random_string(length=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def workload(total_ops):
    rc = Redis(host='172.38.0.11', port=6379)
    print(rc.get_nodes())
    # Insert data into the Redis cluster
    for i in range(total_ops):
        key = f"key:{i}"
        value = random_string(20)
        rc.set(key, value)
       #print(f"Set {key} to {value}")
        
        value = rc.get(key)
        #print(f"Got {key} with value {value}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <total_ops>")
        sys.exit(1)
    try:
        total_ops = int(sys.argv[1])
    except ValueError:
        print("Total ops must be an integer.")
        sys.exit(1)

    workload(total_ops)