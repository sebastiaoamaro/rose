## FUNCTION ANALYZER

###Redpanda
For redpanda run:
./get_symbols_by_keyword.sh redpanda/keywords.txt ../rw/redpanda/binaries/21.10.1/redpanda/libexec/redpanda redpanda/functions.txt

###Redis
For redis run:
./get_symbols_by_file.sh redis/relevant_files.txt redis/redis-server redis/functions.txt

./get_symbols_by_keyword.sh redis/relevant_files.txt redis/redis-server redis/functions.txt

###RedisRaft

./get_symbols_by_file.sh redisraft/relevant_files.txt *binary* redisraft/functions.txt
