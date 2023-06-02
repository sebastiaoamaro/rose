import time
import os
import sys
from time import sleep
file_test = open("test.txt","a")


def readfunc():
    sleep(3)

    
start = time.time()
pid = os.getpid()
for i in range (0,100_000_000):
    readfunc()
    print(pid)
    #file_test.write("Line " + str(i))
    #file_test = open("test.txt","a")
    file_test.close()
end = time.time()

print("Done in " + str(end-start) + " seconds")
os.remove("test.txt")
