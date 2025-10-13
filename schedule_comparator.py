from signal import Handlers
import sys
from rose import run_reproduction, collect_and_parse
from analyzer.trace_analysis import History
import random
from openai import OpenAI


def main():
    schedule_pre_change = sys.argv[1]
    schedule_post_change = sys.argv[2]

    #Run both schedules
    run_reproduction(schedule_pre_change)
    history_pre_change = collect_and_parse("/tmp/history.txt","/tmp/",schedule_pre_change,"pre_change")
    history_pre_change.discover_faults(None)

    run_reproduction(schedule_post_change)
    history_post_change = collect_and_parse("/tmp/history.txt","/tmp/",schedule_post_change,"post_change")
    history_post_change.discover_faults(None)
    compare_traces(history_pre_change, history_post_change)

def compare_traces(history_pre_change, history_post_change):
    network_trace_pre = history_pre_change.collect_network_info()
    network_trace_post = history_post_change.collect_network_info()
    changes = calculate_fluctuations(network_trace_pre, network_trace_post)
    print(changes)

def calculate_fluctuations(network_trace_pre, network_trace_post):
    fluctuations = {}
    for node in network_trace_pre:
        pre_neighbors = network_trace_pre[node]
        post_neighbors = network_trace_post[node]
        all_neighbors = set(pre_neighbors.keys()) | set(post_neighbors.keys())
        node_fluctuations = {}
        for neighbor in all_neighbors:
            pre_val = pre_neighbors.get(neighbor, 0)
            post_val = post_neighbors.get(neighbor, 0)
            node_fluctuations[neighbor] = abs(post_val - pre_val)
        fluctuations[node] = node_fluctuations
    return fluctuations


if __name__ == "__main__":
    main()
