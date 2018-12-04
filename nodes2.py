from xmlrpc.server import SimpleXMLRPCServer  # create server
from xmlrpc.client import ServerProxy # access server
from urllib.parse import urlparse
from os.path import join, isfile

MAX_HISTORY_LENGTH = 6  
OK = 1  # flag : success
FAIL = 2  # flag : fail
EMPTY = ''  # null package


def get_port(url):  # extract port number from url
    result = urlparse(url)[1]  
    port = result.split(':')[-1]  
    return int(port)  

# class NodesInfo:
#     def __init__(self, url, key ):
#         self.urlList = url
#         self.keyList = key

#     def infoPair(self):
#         return url,key 

class Node:
    def __init__(self, url, dir_name, key ):
        self.url = url
        self.dirName = dir_name
        self.key = key
        self.searchList = set()
        self.keyDict = {}

    def _start(self):   # start the server
        server = SimpleXMLRPCServer(('',get_port(self.url)),logRequests=False)
        server.register_instance(self)
        server.serve_forever()

    def _localHandler(self,fileName):  #search for requiring file in local repo
        filePath = join(self.dirName,fileName)
        if not isfile(filePath):
            print('Local Handler: no requiring file in local repo')
            return FAIL, EMPTY
        else:
            print('Local Handler: Found requiring file in local repo')
            return OK, open(filePath).read()

    def _broadcast(self, fileName, history ):
        for other in self.searchList.copy():
            if other in history:
                continue
            try:
                server = ServerProxy(other)
                flag, data = server.query(fileName, self.keyDict.get(other),history)
                if flag == OK:
                    print('Broadcast: Found file in ', other)
                    return OK, data
            except OSError:
                self.searchList.remove(other)
                self.keyDict.pop(other)
        print('Broadcast: No requiring files in all known nodes')
        return FAIL, EMPTY

    def query(self, fileName, key, history=[]):  # history should be a blank list for a initial query
        if key != self.key:
            print('Key not matched')
            return FAIL, EMPTY
        else:
            flag, data = self._localHandler(fileName)
            if flag == OK:
                return flag, data
            else:
                history.append(self.url)
                if len(history) >= MAX_HISTORY_LENGTH:
                    print('Search exceed max times: ',MAX_HISTORY_LENGTH)
                    return FAIL, EMPTY
                else:
                    flag, data = self._broadcast(fileName,history)
                    return flag, data

    def addSearchList(self, other, key):
        self.searchList.add(other)
        self.keyDict[other] = key
        print('Add node to Searchlist: ', other)
        return OK

    def fetch(self, fileName, key ):
        flag, data = self.query(fileName,key,[])
        if flag == OK:
            with open(join(self.dirName, fileName), 'w') as file:  
                file.write(data)  # write files
            return OK  
        else:
            return FAIL  

         
if __name__ == '__main__':
    url = 'http://192.168.0.21:8090'
    directory = 'NodeFiles02'
    key = '654321'
    node = Node(url, directory, key)
    node._start()   




