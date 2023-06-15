import time
import os
import sys
from time import sleep
file_test = open("test.txt","a")


def uprobing():
    sleep(3)
    print("Running function uprobing")

    
start = time.time()
pid = os.getpid()
print(pid)
file_test = open("test.txt","a")
for i in range (0,1000):
    sleep(3)
    #uprobing()
    #print(pid)
    file_test.write("Line " + str(i))
file_test.close()

end = time.time()
print("Done in " + str(end-start) + " seconds")
os.remove("test.txt")
