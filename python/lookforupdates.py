import os, time, xmltodict, json
from NiktoFormat import *

def process(f, d):
    print("Found changed file!")
    i = 1
    with open(f, "r") as fp:
        j = xmltodict.parse(fp.read())
        scan = NiktoScan(j)

        with open("/out/out.json", "w") as jfp:
            scan.Serialize(jfp)

        with open("/out/out.nikto", "wb") as jfp:
            scan.SerializePB(jfp)

    os.remove(f)
    os.remove(d)
    print("Files processed")


f="/tmp/out.xml"
d="/tmp/done"
last_change=None

while 1:
    time.sleep(10)
    if os.path.isfile(d):
        process(f, d)
