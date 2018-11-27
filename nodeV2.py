from xmlrpc.server import SimpleXMLRPCServer  # create server
from xmlrpc.client import ServerProxy,Fault # access server
from urllib.parse import urlparse
from os.path import join, isfile, abspath
import sys

import json
import os
import shutil
import glob
import datetime
from securep2p227 import keys as sp

from cryptography.fernet import Fernet

SimpleXMLRPCServer.allow_reuse_address = 1
MAX_HISTORY_LENGTH = 6  

OK = 1  # flag : success
FAIL = 2  # flag : fail

PERMISSION_DENY = 3
NO_SUCH_FILE = 4

EMPTY = ''  # null package

def inside(dirPath, filePath):  
    directory = abspath(dirPath) 
    filep = abspath(filePath)  
    return filep.startswith(join(directory, ''))  

def get_url(url):
    result = urlparse(url)[1]
    url = result.split(':')[0]
    return url

def get_port(url):  # extract port number from url
    result = urlparse(url)[1]  
    port = result.split(':')[-1]  
    return int(port)  


class Node:
    def __init__(self, localUrl, userName, organization, dirName):
        self.localUrl = localUrl
        self.userName = userName
        self.organization = organization
        self.dirName = dirName
        self.session = None
        self.host = sp.Host("securep2p.fivebillionmph.com")

        for path in glob.glob("./keys/*"):
	        shutil.rmtree(path)
        for path in glob.glob("./permissions/*"):
	        os.remove(path)
        for path in glob.glob("./log/*"):
            os.remove(path)

        self.permission = sp.Permission("./permissions", self.userName)
        self.myKey = sp.genKey("./keys","myKey",self.userName,self.organization)

        self.permission.addAuthorizedKey(sp.publicKeyToPemString(self.myKey._public_key), self.userName, self.organization)
        
        with open('./keys/myKey/private-key') as f:
            self.internalKey = f.read()

        self.log = open("./log/log.txt","w+")
        self.log.write("Client Server log: {:} {:}\n".format(self.userName,self.organization))
        self.log.write("==================================================\n")
        self.log.close()
        
        

        self.searchList = set()
        
    def _start(self):   # start the server
        self.myKey.register(self.host)
        server = SimpleXMLRPCServer((get_url(self.localUrl),get_port(self.localUrl)),logRequests=False)
        server.register_instance(self) 
        print("===========================================================")
        print("Create Client at ", self.localUrl)
        print("User: ", self.userName)
        print("Organization: ", self.organization)
        print("RSA 2048 keys generated.")
        print("===========================================================")
        server.serve_forever()

    # internal function, prohibited for external user
    # Input: extPubKey(pem str), fileName(str)
    # Output: flag, msg_file(str) ad msg_randomKey(str)
    def _localFileHandler(self, extPubKey, fileName):
        filePath = join(self.dirName, fileName)
        if not isfile(filePath):
            print('Bad Request: no requiring file in local repo')
            return NO_SUCH_FILE, EMPTY, EMPTY
        if not inside(self.dirName, filePath):
            print('Bad Request: This folder is not shared')
            return NO_SUCH_FILE, EMPTY, EMPTY
        
        f = open(filePath).read()

        randomKey = Fernet.generate_key()
        cipher_suite = Fernet(randomKey)
        msg_file = cipher_suite.encrypt(f.encode())
        msg_randomKey = sp.encryptMessageB64(sp.pemStringToPublicKey(extPubKey), randomKey.decode())

        print('Good Request: file transmitted.')
        return OK, msg_file.decode(), msg_randomKey

    # internal function, prohibited for external user
    # Input: extPubKey(pem str)
    # Output flag, msg_folder(str) and msg_randomKey(str)
    def _localFolderHandler(self,extPubKey):
        folderInfo = self.dirName
        for e in os.listdir(self.dirName):
            folderInfo = folderInfo + '|' + e

        randomKey = Fernet.generate_key()
        cipher_suite = Fernet(randomKey)
        msg_folder = cipher_suite.encrypt(folderInfo.encode())
        msg_randomKey = sp.encryptMessageB64(sp.pemStringToPublicKey(extPubKey), randomKey.decode())
        
        print('Good Request: file transmitted.')
        return  OK, msg_folder.decode(), msg_randomKey

    def startSession(self,internalKey):
        #Restriction: each Client can only register with one session
        #each Client has to end its session before starting another one
        #Make sure each Username is unique to session
        time = str(datetime.datetime.now())
        self.log = open("./log/log.txt","a+")
        if not internalKey == self.internalKey:
            print('Operation Illegal')
            self.log.write("Operation Illegal [Start Session]. Time: {:}\n".format(time))
            self.log.close()
            return PERMISSION_DENY

        if self.session is None:
            self.session = sp.Session(self.host, self.myKey)
            self.session.startSession(get_port(self.localUrl))
            print("Your session has been created.")
            print("Registered as User: ", self.userName)
            print("Registered as Organization: ", self.organization)
            print("Client listening on port: ", get_port(self.localUrl))
            print("Sharing Folder: ", self.dirName)
            print("===========================================================")
            self.log.write("Start Session. IP: {:} Sharing Folder: {:} Time: {:}\n".format(self.localUrl,self.dirName,time))            
            self.log.close()
            return OK
        else:
            print('You already have one session running on Server!')
            print("Registered as User: ", self.userName)
            print("Registered as Organization: ", self.organization)
            print("Client listening on port: ", get_port(self.localUrl))
            print("Sharing Folder: ", self.dirName)
            print("===========================================================")
            self.log.write("Fail [Start Session].Time: {:}\n".format(time))
            self.log.close()
            return FAIL

    def endSession(self,internalKey):
        time = str(datetime.datetime.now())
        self.log = open("./log/log.txt","a+")
        if not internalKey == self.internalKey:
            print('Operation Illegal')
            self.log.write("Operation Illegal [End Session]. Time: {:}\n".format(time))
            self.log.close()
            return PERMISSION_DENY

        if self.session is None:
            print("Before ending session, you have to start one.")
            self.log.write("Fail [End Session].Time: {:}\n".format(time))
            self.log.close()
            return FAIL
        else:
            self.session.stopSession()
            self.session = None
            print("Your session has been stopped.")
            print("Client NO MORE listening on port: ", get_port(self.localUrl))
            print("===========================================================")
            self.log.write("End Session. IP: {:} Sharing Folder: {:} Time: {:}\n".format(self.localUrl,self.dirName,time))            
            self.log.close()
            return OK

    # For Client Usage
    # return a PublicKey(pem str) of my own public key
    def getMyPublicKey(self, internalKey):
        time = str(datetime.datetime.now())
        self.log = open("./log/log.txt","a+")
        if not internalKey == self.internalKey:
            print('Operation Illegal')
            self.log.write("Operation Illegal [get My Public Key]. Time: {:}\n".format(time))
            self.log.close()
            return PERMISSION_DENY

        self.log.write("Get my public key. Time:{:}".format(time))
        self.log.close()
        return sp.publicKeyToPemString(self.myKey._public_key)

    # For CLient Usage
    # return a dict for my own signature [!Signature can be passed by XmlRPC server]
    def getMySignature(self, internalKey):
        time = str(datetime.datetime.now())
        self.log = open("./log/log.txt","a+")
        if not internalKey == self.internalKey:
            print('Operation Illegal')
            self.log.write("Operation Illegal [get My Signature]. Time: {:}\n".format(time))
            self.log.close()
            return PERMISSION_DENY

        if not self.session == None :
            self.log.write("Get my signature. Time: {:}\n".format(time))
            self.log.close()
            return self.session.getSignatures()   
        else:
            self.log.write("Fail [get My Signature]. Time: {:}\n".format(time))
            print("You need a registered session bofore getting your signatures")
            self.log.close()
            return PERMISSION_DENY    

    # For Client Usage
    # For user to look those running sessions on Cloud Server
    # No return value
    def getActiveSessions(self,internalKey):
        time = str(datetime.datetime.now())
        self.log = open("./log/log.txt","a+")
        if not internalKey == self.internalKey:
            print('Operation Illegal')
            self.log.write("Operation Illegal [get Active Sessions]. Time: {:}\n".format(time))
            self.log.close()
            return PERMISSION_DENY

        activeSessionsALL = sp.searchSessions(self.host)
        activeSessionsALL = activeSessionsALL['sessions']
        activeSessionNum = len(activeSessionsALL)
        self.log.write("Get active sessions. Time: {:}\n".format(time))
        print(str(activeSessionNum), 'sessions running on server currently...')
        for session in activeSessionsALL:
            print('Username: {:>25} | Organization: {:>30} | IP: {:>15} | Port: {:>5}'.format(session['name'],session['organization'],session['ip'],session['port']))
        self.log.close()
        return OK

    # For Client Usage
    # supposing there are no repetitive usernames on the Cloud Server
    # Each name is corresponding to each running sessions/Client/IP
    # Dont need to spell the whole username e.g. for 'admin', 'ad' will also work
    # Input: userName(str)
    # Output: IP(str), Username(str), Organization(str) 
    def getSessionIP(self,userName,internalKey):
        time = str(datetime.datetime.now())
        self.log = open("./log/log.txt","a+")
        if not internalKey == self.internalKey:
            print('Operation Illegal')
            self.log.write("Operation Illegal [get Session IP]. Time: {:}\n".format(time))
            self.log.close()
            return PERMISSION_DENY, EMPTY, EMPTY, EMPTY

        tarSession = sp.searchSessions(self.host,userName)
        tarSession = tarSession['sessions']
        if len(tarSession) == 0:
            print('No such session running on Cloud Server!')
            self.log.write("Fail [get Session IP][no user]. Time: {:}\n".format(time))
            self.log.close()
            return FAIL, EMPTY, EMPTY, EMPTY
        elif len(tarSession) == 1:
            tar = tarSession[0]
            self.log.write("Get Session IP of user {:}. Time: {:}\n".format(tar['name'],time))
            print('Located session successfully.')
            print('Username: {:>25} | Organization: {:>30} | IP: {:>15} | Port: {:>5}'.format(tar['name'],tar['organization'],tar['ip'],tar['port']))
            self.log.close()
            return OK, ('http://' + tar['ip'] + ':' + str(tar['port'])), tar['name'], tar['organization']
        elif len(tarSession) > 1:
            print('Selected multiple sessions. Please specify the Username with more character')
            for session in tarSession:
                print('Username: {:>25} | Organization: {:>30} | IP: {:>15} | Port: {:>5}'.format(session['name'],session['organization'],session['ip'],session['port']))
            self.log.write("Fail [get Session IP][too many users]. Time: {:}\n".format(time))
            self.log.close()
            return FAIL, EMPTY, EMPTY, EMPTY
        else:
            self.log.write("Fail [get Session IP]. Time: {:}\n".format(time))
            self.log.close()
            return FAIL, EMPTY, EMPTY, EMPTY

    # For Client Usage
    # supposing there are no repetitive usernames on the Cloud Server    # Dont need to spell the whole username e.g. for 'admin', 'ad' will also work
    # Each name is corresponding to each public key
    # Input: userName(str)
    # Output: Public Key(pem str), name(str), organization(str)
    def getPubKey(self,userName,internalKey):
        time = str(datetime.datetime.now())
        self.log = open("./log/log.txt","a+")
        if not internalKey == self.internalKey:
            print('Operation Illegal')
            self.log.write("Operation Illegal [get Public Key]. Time: {:}\n".format(time))
            self.log.close()
            return PERMISSION_DENY, EMPTY, EMPTY, EMPTY

        tarPubKey = sp.searchKeys(self.host, userName)
        tarPubKey = tarPubKey['users']
        if len(tarPubKey) == 0:
            print('No such Public Key on Cloud Server!')
            self.log.write("Fail [get Public Key][no user]. Time: {:}\n".format(time))
            self.log.close()           
            return FAIL, EMPTY, EMPTY, EMPTY
        elif len(tarPubKey) == 1:
            tar = tarPubKey[0]
            print('Located Public Key successfully.')
            print('Username: {:>25} | Organization: {:>30} | PubKey: {:}'.format(tar['name'],tar['organization'],sp.prettyFingerprint(sp.publicKeyFingerprint(sp.pemStringToPublicKey(tar['public_key'])))))
            self.log.write("Get Public Key of {:}. Time: {:}\n".format(tar['name'],time))
            self.log.close()
            return OK, tar['public_key'], tar['name'], tar['organization']
        elif len(tarPubKey) > 1:
            print('Selected multiple Public Keys. Please specify the Username with more character')
            for key in tarPubKey:
                print('Username: {:>25} | Organization: {:>30} | PubKey: {:}'.format(key['name'],key['organization'],sp.prettyFingerprint(sp.publicKeyFingerprint(sp.pemStringToPublicKey(key['public_key'])))))
            self.log.write("Fail [get Public Key][too many users]. Time: {:}\n".format(time))
            self.log.close()
            return FAIL, EMPTY, EMPTY, EMPTY
        else:
            self.log.write("Fail [get Public Key][too many users]. Time: {:}\n".format(time))
            self.log.close()
            return FAIL, EMPTY, EMPTY, EMPTY


    # For Client Usage
    # Input: pubKey(pem str), returned by getPubKey() above
    def signPubKey(self, pubKey, dayNum, internalKey):
        time = str(datetime.datetime.now())
        self.log = open("./log/log.txt","a+")
        if not internalKey == self.internalKey:
            print('Operation Illegal')
            self.log.write("Operation Illegal [sign Public Key]. Time: {:}\n".format(time))
            self.log.close()
            return PERMISSION_DENY

        now = datetime.datetime.now()
        tomorrow = now + datetime.timedelta(days=dayNum)
        self.myKey.signKeyAndSubmit(sp.pemStringToPublicKey(pubKey), self.host, now, tomorrow)
        print('Signed. Expiration at ', str(tomorrow))
        self.log.write("Sign Public Key . Time: {:}\n".format(time))
        self.log.close()
        return OK


    # For Client Usage
    # Input: pubKey(pem str), returned by getPubKey() above
    # Input: userName, organization(str), returned by getPubKey() above
    def addAuthorizedKey(self, pubKey, userName, organization, internalKey):
        time = str(datetime.datetime.now())
        self.log = open("./log/log.txt","a+")
        if not internalKey == self.internalKey:
            print('Operation Illegal')
            self.log.write("Operation Illegal [add Authorized Key]. Time: {:}\n".format(time))
            self.log.close()
            return PERMISSION_DENY

        self.permission.addAuthorizedKey(pubKey, userName, organization)
        print('Added authorized key in local permission list.')
        self.log.write("Add Authorized Key from user: {:}. Time: {:}\n".format(userName,time))
        self.log.close()
        return OK

    # This is an internal function. Only for this node's calling.
    # Checking the request's authorization
    # Input: pubKey: pem str, passed by the other node
    # Input: signature: a signature dict(a colletion of all signature), passed by the other node    
    def _checkPermission(self, pubKey, signature):

        return self.permission.authorize(pubKey, signature["signatures"][0]["signature"], json.loads(signature["signatures"][0]["message"]), signature["signatures"][0]["signer"]["public_key"])
   
    # this function is for external nodes
    # extPubKey: pem str
    # extSignature: dict
    # extURL: str , only for log record
    # return flag, msg_folder(str) and msg_randomKey(str)
    def requestFolder(self, extPubKey, extSignature, extURL):
        time = str(datetime.datetime.now())
        self.log = open("./log/log.txt","a+")
        flag = self._checkPermission(extPubKey, extSignature)
        if flag is True:
            self.log.write("Success! Folder request from URL: {:}. Time: {:}\n".format(extURL,time))
            self.log.close()
            return self._localFolderHandler(extPubKey)
        else:
            self.log.write("Fail! Folder request from URL: {:}. Time: {:}\n".format(extURL,time))
            self.log.close()
            return PERMISSION_DENY, EMPTY, EMPTY

    # For external Client usage
    # return the sharing file
    # this function is for external nodes
    def requestFile(self, extPubKey, extSignature, fileName, extURL):
        time = str(datetime.datetime.now())
        self.log = open("./log/log.txt","a+")
        flag = self._checkPermission(extPubKey, extSignature)
        if flag is True:
            self.log.write("Success! File [{:}] request from URL: {:}. Time: {:}\n".format(fileName,extURL,time))
            self.log.close()
            return self._localFileHandler(extPubKey, fileName)
        else:
            self.log.write("Fail! File [{:}] request from URL: {:}. Time: {:}\n".format(fileName,extURL,time))
            self.log.close()
            return PERMISSION_DENY, EMPTY, EMPTY
  
    # For local Client usage
    # Inteprete the encrypted msg returned by the other Node
    # Input: msg(str), msg_randomKey(str), internalKey
    # Output: f(str)
    def msgInterpreter(self, msg, msg_randomKey, internalKey):
        if not internalKey == self.internalKey:
            print('Operation Illegal')
            return PERMISSION_DENY

        randomKey = self.myKey.decryptMessageB64(msg_randomKey)
        randomKey = randomKey.encode()
        cipher_suite = Fernet(randomKey)
        f = cipher_suite.decrypt(msg.encode())
        f = f.decode()
        return f       



    # def _localHandler(self,fileName):  #search for requiring file in local repo
    #     filePath = join(self.dirName,fileName)
    #     if not isfile(filePath):
    #         print('Local Handler: no requiring file in local repo')
    #         return FAIL, EMPTY
    #     if not inside(self.dirName,filePath):
    #         print('Access Denied: This folder is not shared')
    #         return FAIL, EMPTY        
    #     print('Local Handler: Found requiring file in local repo')
    #     return OK, open(filePath).read()

    # def _broadcast(self, fileName, history ):
    #     for other in self.searchList.copy():
    #         if other in history:
    #             continue
    #         try:
    #             server = ServerProxy(other)
    #             flag, data = server.query(fileName, self.keyDict.get(other),history)
    #             if flag == OK:
    #                 print('Broadcast: Found file in ', other)
    #                 return OK, data
    #         except OSError:
    #             self.searchList.remove(other)
    #             self.keyDict.pop(other)
    #     print('Broadcast: No requiring files in all known nodes')
    #     return FAIL, EMPTY

    # def query(self, fileName, key, history=None):  # history should be a blank list for a initial query
    #     if history == None:
    #         history = []
            
    #     if key != self.key:
    #         print('Key not matched')
    #         return FAIL, EMPTY
    #     else:
    #         flag, data = self._localHandler(fileName)
    #         if flag == OK:
    #             return flag, data
    #         else:
    #             history.append(self.localUrl)
    #             if len(history) >= MAX_HISTORY_LENGTH:
    #                 print('Search exceed max times: ',MAX_HISTORY_LENGTH)
    #                 return FAIL, EMPTY
    #             else:
    #                 flag, data = self._broadcast(fileName,history)
    #                 return flag, data

    # def addSearchList(self, other, key):
    #     self.searchList.add(other)
    #     self.keyDict[other] = key
    #     print('Add node to Searchlist: ', other)
    #     return OK

    # def fetch(self, fileName, key ):
    #     flag, data = self.query(fileName,key,[])
    #     if flag == OK:
    #         with open(join(self.dirName, fileName), 'w') as file:  
    #             file.write(data)  # write files
    #         return OK  
    #     else:
    #         return FAIL  

def main():
    # localurl, username, organization, directory = sys.argv[1:]
    localurl = 'http://192.168.0.21:8080'
    username = 'aaron'
    organization = 'ucla'
    directory = 'NodeFiles02'
    
    node = Node(localurl, username, organization, directory)

    with open('./keys/myKey/private-key') as f:
        internalKey = f.read()

    node._start()  
            
if __name__ == '__main__':

    main()



