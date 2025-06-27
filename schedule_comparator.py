import sys
from rose import run_reproduction, collect_and_parse
from analyzer.trace_analysis import History
def main():
    schedule_pre_change = sys.argv[1]
    schedule_post_change = sys.argv[2]

    #Run both schedules
    run_reproduction(schedule_pre_change)
    history_pre_change = collect_and_parse("/tmp/history.txt","/tmp/",schedule_pre_change,"pre_change")

    run_reproduction(schedule_post_change)
    history_post_change = collect_and_parse("/tmp/history.txt","/tmp/",schedule_post_change,"post_change")


    #Compare the traces
    compare_traces(history_pre_change, history_post_change)


def compare_traces(history_pre_change, history_post_change):
    history_pre_change.collect_network_info()
    history_post_change.collect_network_info()


if __name__ == "__main__":
    main()
