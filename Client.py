# -*- coding: utf-8 -*-
from xmlrpc.client import ServerProxy, Fault  # 导入服务器代理类和故障类
from random import choice  # 导入随机选取的方法
from string import ascii_lowercase  # 导入小写字母列表对象
from time import sleep  # 导入延迟方法
from nodeV2 import Node, OK, FAIL, PERMISSION_DENY, NO_SUCH_FILE, EMPTY #  import node server
from threading import Thread  # 导入线程类
from cmd import Cmd  # 导入命令类
import sys  # 导入系统模块
from os.path import join
import requests

HEAD_START =  2 # 等待服务器启动时长
SECRET_LENGTH = 10 # 密钥长度

def random_string(length):  # 定义随机密钥的函数
    key = ''
    while length > 0:
        length -= 1
        key += choice(ascii_lowercase)  # 随机获取小写字母叠加到变量
    return key

class Client(Cmd):
    prompt = '>>>'  # 重写超类中的命令提示符

    def __init__(self, localUrl, dirName):  # 定义构造方法
        Cmd.__init__(self)  # 重载超类的构造方法
   	    r = requests.get("http://ip.42.pl/raw")
        self.localUrl = r.text
        self.dirName = dirName
        self.sessionON = False
        node = Node(localUrl, dirName)  # 创建节点对象
        thread = Thread(target=node._start)  # 在独立的线程中启动服务器
        thread.setDaemon(True)  # 将线程设置为守护线程
        thread.start()  # 启动线程
        sleep(HEAD_START)  # 等待服务器启动
        with open('./keys/myKey/private-key') as f:
            self.internalKey = f.read()
        self.server = ServerProxy(self.localUrl)  # 创建服务器代理对象

    # register the session on the cloud server
    def do_startSession(self,arg):
        try:
            self.server.startSession(self.internalKey)
            self.sessionON = True
        except Exception as e:
            print("error:", e)

    # de-register the session on the cloud server
    def do_endSession(self,arg):
        try:
            self.server.endSession(self.internalKey)
            self.sessionON = False
        except Exception as e:
            print("error:", e)

    def do_activeSessions(self,arg):
        try:
            self.server.getActiveSessions(self.internalKey)
        except Exception as e:
            print("error:", e)

    # arg: userName, expirationDay
    def do_sign(self, arg):
        try:
            try:
                userName, expirationDay = arg.split()
                modifier = None
                modifierValue = None
            except:
                userName, expirationDay, modifier, modifierValue = arg.split()
            flag, pubk, username, organization = self.server.getPubKey(userName, self.internalKey)
            if flag == OK:
                user_response = input("Are you sure that you want to sign this user. y/N?").lower()
                if user_response == 'y':
                    self.server.signPubKey(pubk, int(expirationDay), modifier, modifierValue, self.internalKey)
                elif user_response == 'n':
                    print('Signing aborted')
                else:
                    print('Wrong input. Please sign again.')
            else:
                pass
        except Exception as e:
            print("error:", e)

    # 
    def do_authorize(self, userName):
        try:
            flag, pubk, username, organization = self.server.getPubKey(userName, self.internalKey)
            if flag == OK:
                user_response = input("Are you sure that you want to authorize this user. y/N?").lower()
                if user_response == 'y':
                    self.server.addAuthorizedKey(pubk, username, organization, self.internalKey)
                elif user_response == 'n':
                    print('Signing aborted')
                else:
                    print('Wrong input. Please authorize again.')
            else:
                pass
        except Exception as e:
            print("error:", e)

    def do_viewAuthorized(self, args):
        try:
            self.server.viewAuthorized()
        except Exception as e:
            print("error:", e)

    def do_deleteAuthorized(self, name):
        try:
            self.server.deleteAuthorized(name)
        except Exception as e:
            print("error:", e)

    def do_requestFolder(self, userName):
        try:
            flag, url, username, organization = self.server.getSessionIP(userName, self.internalKey)
            if flag == OK:
                user_response = input("Are you sure that you want to request this user's folder info. y/N?").lower()
                if user_response == 'y':
                    myPubKey = self.server.getMyPublicKey(self.internalKey)
                    mySignature = self.server.getMySignature(self.internalKey)
                    Target = ServerProxy(url)
                    flag, msg_folder, msg_randomKey = Target.requestFolder(myPubKey,mySignature,self.localUrl)
                    if flag == OK:
                        folderInfo = self.server.msgInterpreter(msg_folder,msg_randomKey,self.internalKey)
                        print('Request Success!')
                        InfoList = folderInfo.split('|')
                        print('Folder Name: ', InfoList[0])
                        for i in range(1,len(InfoList)):
                            print('        Files ', str(i),  ' : ', InfoList[i])
                    else:
                        print('Request Fail!')
                elif user_response == 'n':
                    print('Request aborted')
                else:
                    print('Wrong input. Please request again.')
            else:
                pass       
        except Exception as e:
            print("error:", e)

    # arg: userName, fileName
    def do_requestFile(self, arg):
        try:
            userName, fileName = arg.split()
            flag, url, username, organization = self.server.getSessionIP(userName, self.internalKey)
            if flag == OK:
                user_response = input("Are you sure that you want to request this user's file. y/N?").lower()
                if user_response == 'y':
                    myPubKey = self.server.getMyPublicKey(self.internalKey)
                    mySignature = self.server.getMySignature(self.internalKey)
                    Target = ServerProxy(url)
                    flag, msg_file, msg_randomKey = Target.requestFile(myPubKey,mySignature,fileName,self.localUrl)
                    if flag == OK:
                        tar_File = self.server.msgInterpreter(msg_file,msg_randomKey,self.internalKey)
                        print('Request Success!')
                        with open(join(self.dirName, fileName), 'w') as f:
                            f.write(tar_File)
                    else:
                        print('Request Fail!')
                elif user_response == 'n':
                    print('Request aborted')
                else:
                    print('Wrong input. Please request again.')
            else:
                pass         
        except Exception as e:
            print("error:", e)


    # def do_addNode(self, otherNode):
    #     url, key = otherNode.split()
    #     self.server.addSearchList(url, key)

    # def do_fetch(self, filename):  # 定义下载命令的方法   
    #     flag = self.server.fetch(filename, self.key)  # 调用服务器代理对象的下载方法
    #     if flag == OK:
    #         print('Fetch finished')
    #     else:
    #         print('Fetch failed: ', filename)

    def do_exit(self, arg):  # 定义退出命令的方法
        try:
            print('------------------Exit Application------------------')
            if self.sessionON == True:
                self.server.endSession(self.internalKey)
            sys.exit()  # 系统退出
        except Exception as e:
            print("error:", e)

def main():  # 定义主程序函数
    port, dirName = sys.argv[1:3]  # 获取通过命令行输入的参数
    if len(sys.argv) >= 4:
        localUrl = "http://" + sys.argv[3] + ":" + port
    else:
        localUrl = "http://0.0.0.0:" + port
    client = Client(localUrl, dirName)  # 创建客户端对象
    client.cmdloop()  # 启动命令行循环执行

if __name__ == '__main__':
    main()
