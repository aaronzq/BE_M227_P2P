import json
import os
import shutil
import glob
import datetime
from securep2p227 import keys as sp

# delete the existing key
for path in glob.glob("test-data/keys/*"):
	shutil.rmtree(path)
for path in glob.glob("test-data/permissions/*"):
	os.remove(path)

# create a host object to connect to specify the server name
host = sp.Host("securep2p.fivebillionmph.com")

# create a new key with test fake data
key1 = sp.genKey("test-data/keys", "test1", "Dr. Leonard McCoy", "NCC-1701 USS Enterprise")

# register our key to the host
key1.register(host)

# create a new session object with the host and key
session1 = sp.Session(host, key1)

# start the session on the server
session1.startSession(8080)

# create a second key and session
key2 = sp.genKey("test-data/keys", "test2", "Dr. Beverly Crusher", "NCC-1701-D USS Enterprise")
key2.register(host)
session2 = sp.Session(host, key2)
session2.startSession(8081)

aaa = session1.getActiveSessions()
print(aaa)
# print(session2.getActiveSessions())
# print(session1.getActiveSessions())
# pass
# # create a third session
# key3 = sp.genKey("test-data/keys", "test3", "Dr. Alexander Siddig", "Deep Space Nine")
# key3.register(host)
# session3 = sp.Session(host, key3)
# session3.startSession(8082)

# # create a fouth session
# key4 = sp.genKey("test-data/keys", "test4", "Dr. Evil", "Starbucks")
# key4.register(host)
# session4 = sp.Session(host, key4)
# session4.startSession(8083)

# # sign a key
# now = datetime.datetime.now()
# tomorrow = now + datetime.timedelta(days=1)
# session1.signKeyAndSubmit(key2._public_key, now, tomorrow)

# # get the active sessions
# active_sessions = session1.getActiveSessions()

# # get my signatures
# my_signatures = session2.getSignatures()

# permission3 = sp.Permission("test-data/permissions", "ds9-files")
# permission3.addAuthorizedKey(sp.publicKeyToPemString(key1._public_key), "Dr. McCoy", "USS Enterprise")
# # print(permission3.getAuthorizedKeys())
# print("Dr. McCoy", permission3.authorize(sp.publicKeyToPemString(key1._public_key), None, None, None))
# print("Dr. Crusher", permission3.authorize(sp.publicKeyToPemString(key2._public_key), my_signatures["signatures"][0]["signature"], json.loads(my_signatures["signatures"][0]["message"]), my_signatures["signatures"][0]["signer"]["public_key"]))
# print("Dr. Evil", permission3.authorize(sp.publicKeyToPemString(key4._public_key), my_signatures["signatures"][0]["signature"], json.loads(my_signatures["signatures"][0]["message"]), my_signatures["signatures"][0]["signer"]["public_key"]))
