import time
import os
import sys
file_test = open("test.txt","a")


if sys.argv[1] == "limit":
    pid = os.getpid()
    
start = time.time()
for i in range (0,100_000_000):
    #file_test.write("Line " + str(i))
    file_test = open("test.txt","a")
    file_test.close()
end = time.time()

print("Done in " + str(end-start) + " seconds")
os.remove("test.txt")