from xmlrpc.client import ServerProxy

fileName = 'testfile.txt'

url1 = 'http://192.168.0.21:8080'
key1 = '123456'
server1 = ServerProxy(url1)
print(server1.query(fileName,key1,[]))

url2 = 'http://192.168.0.21:8090'
key2 = '654321'
server2 = ServerProxy(url2)
print(server2.query(fileName,key2,[]))

print(server2.addSearchList(url1,key1))
print(server2.query(fileName,key2,[]))

print(server2.fetch(fileName,key2))