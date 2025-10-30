import redis
import random
import string
import sys
import signal
import threading
import concurrent.futures

# Global stop flag
stop_event = threading.Event()


def signal_handler(signum, frame):
    print(f"Received signal {signum}, stopping workload...")
    stop_event.set()  # Notify threads to stop


# Register the signal handler
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def generate_random_string(length=5):
    return "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(length)
    )


def workload(num_operations, r, number):
    for i in range(num_operations):
        if stop_event.is_set():  # Check stop flag
            print(f"Thread {number} stopping early")
            break
        key = generate_random_string()
        value = generate_random_string()
        try:
            with r.pipeline() as pipe:
                pipe.multi()
                pipe.set(key, value)
                pipe.get(key)
                pipe.execute()
        except redis.exceptions.RedisError:
            continue


if __name__ == "__main__":
    num_operations = int(sys.argv[1])

    redis_conns = [
        redis.Redis(host="172.19.1.10", port=5001, decode_responses=True),
        redis.Redis(host="172.19.1.11", port=5001, decode_responses=True),
        redis.Redis(host="172.19.1.12", port=5001, decode_responses=True),
        redis.Redis(host="172.19.1.13", port=5001, decode_responses=True),
        redis.Redis(host="172.19.1.14", port=5001, decode_responses=True),
    ]

    # Repeat connections to fill 20 threads
    redis_conns_20 = redis_conns * 4

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for i in range(20):
            futures.append(
                executor.submit(workload, num_operations, redis_conns_20[i], i)
            )

        # Wait for threads to complete or stop early
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            try:
                future.result()
            except Exception as e:
                print(f"Thread {i} ended with exception: {e}")
