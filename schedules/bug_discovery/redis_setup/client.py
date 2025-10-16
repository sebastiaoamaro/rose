#!/usr/bin/env python3
import time
import random
import redis
from redis.exceptions import (
    ConnectionError,
    TimeoutError,
    BusyLoadingError,
    ResponseError,
    RedisError,
)

# --- CONFIGURATION ---
USE_CLUSTER = True  # Set to False for standalone Redis
OPS_PER_SECOND = 5  # 0 for max speed, >0 to throttle
RETRY_DELAY = 0.1  # seconds between retries on failure

# --- CLIENT SETUP ---
if USE_CLUSTER:
    from redis.cluster import RedisCluster

    client = RedisCluster(
        host="127.0.0.1",  # one seed node
        port=6371,
        decode_responses=True,
        socket_timeout=None,
        max_connections=32,
        socket_connect_timeout=None,
    )

# --- WORKLOAD LOOP ---
print("🚀 Starting resilient Redis workload...")
print(
    f"Mode: {'Cluster' if USE_CLUSTER else 'Standalone'} | Target ops/sec: {OPS_PER_SECOND}"
)

i = 0
while True:
    try:
        # Example operation pattern
        key = f"key:{i % 10000}"
        value = f"value:{random.randint(0, 10_000_000)}"

        # 50/50 read/write
        if random.random() < 0.5:
            client.set(key, value)
            print("Set", key, value)
        else:
            value = client.get(key)
            print(value)
        i += 1

        # Throttle ops/sec
        if OPS_PER_SECOND > 0:
            time.sleep(1 / OPS_PER_SECOND)

    except (ConnectionError, TimeoutError, BusyLoadingError) as e:
        print(f"[WARN] Redis connection issue: {e}. Retrying in {RETRY_DELAY}s...")
        time.sleep(RETRY_DELAY)
        continue

    except ResponseError as e:
        print(f"[WARN] Redis response error: {e}. Skipping operation.")
        continue

    except RedisError as e:
        print(f"[ERROR] General Redis error: {e}.")
        time.sleep(RETRY_DELAY)
        continue

    except KeyboardInterrupt:
        print("\n🛑 Stopping workload.")
        break

    except Exception as e:
        print(f"[FATAL] Unexpected exception: {e}")
        time.sleep(RETRY_DELAY)
        continue
