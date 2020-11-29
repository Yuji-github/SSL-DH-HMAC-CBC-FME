# -*- coding: utf-8 -*-
"""
Created on Sat Nov  7 23:29:18 2020

@author: Yugi
"""

from RSA import RSA
from DH import DH
from HMAC import HMAC
from CBC import CBC
import random
import socket
import sys


Port = 1234
Header = 1024
Format = "utf-8"

class Server:
    
    def __int__(self):
            
        self.bits = 0        
        self.IDs = 0        
        self.serverID = None
        self.message = None        
        self.demoRSA = None
        
        """
        pirvate key components must be hidden 
        """
        self.p_RSA = 0
        self.q_RSA = 0
        self.d_RSA = 0
        
        """
        public key components
        """
        self.n_RSA = 0 # n = p*q
        self.e_RSA = 0 # this value is given         
        self.sigG_RSA = 0 #sigG = hash(message)^d mod n, I use SHA 256 for the hash
        self.hashedMessage_RSA = 0 #for verification phase
        self.sigV_RSA = None #sigV = 1 is if hash(message) = sigG^e mod n 
        
        self.demoDH = None
        
        """
        DH components
        """
        self.p_DH = 0
        self.q_DH = 0
        self.public_DH = 0
        
        """
        private key components of the user DH
        """
        self.private_DH = 0
        self.sessionKey = 0
        
        """
        HMAC 
        """
        self.demoHMAC = None
        self.messageHMAC = None
        
        self.swiftArray = []
        
    # set up phase 
        
    def updateRSAKeys(self):
        
        """
        pirvate key components must be hidden 
        """
        self.p_RSA = self.demoRSA.getP()
        self.q_RSA = self.demoRSA.getQ()
        self.d_RSA = self.demoRSA.getD()
        
        """
        public key components
        """
        self.n_RSA = self.demoRSA.getN()
        
        self.sigG_RSA = self.demoRSA.getSigG() #sigG = hash(message)^d mod n, I use SHA 256 for the hash
        self.hashedMessage_RSA = self.demoRSA.getHashedM() #for verification phase
        
        self.sigV_RSA = None #sigV = 1 is if hash(message) = sigG^e mod n 
        
        
    def setKey(self, message, new_bits): #generate the RSA ans IDs 
        
        self.message = message
        
        self.bits = new_bits        
        
        self.e_RSA = 65537 # this value is given 
        
        self.demoRSA = RSA()
        
        self.demoRSA.RSA(self.bits, self.e_RSA)
        
        self.demoRSA.sigGeneration(self.message)
        
        self.updateRSAKeys()
        
        self.IDs = int (1780119054 * random.random()) #not necessary to generate 
        
        self.serverID = 1780119054 #just give -> can change any numbers 
    
    """
    public key components
    """    
    def getN(self):  
        return self.n_RSA
    
    def getE(self):
        return self.e_RSA
    
    def getSigG(self):
        return self.sigG_RSA    
   
    def getIDs(self):
        return self.IDs
    
    def getServerID(self):
        return self.serverID

    #handshake phase

    def setDH(self, new_p, new_q): #p and q are given
        self.p = new_p
        self.q = new_q  
        
    def handshake(self, p, q): # generate DH 
        self.demoDH = DH()        
        self.setDH(p, q) #not necessary to do this 
        self.demoDH.setSytemPrameters(self.p, self.q)
        self.private_DH = self.demoDH.setPrivate() #private first and public after private is random select 
        self.public_DH = self.demoDH.setPublic() # for create session key and this goes to the user 
    
    def session(self, public_key_U): 
        self.sessionKey = self.demoDH.setSession(public_key_U) #generate by User public key
        
    def getPublic_DH(self):
        return self.public_DH
    
    def getSession_HD(self):
        return self.sessionKey   
    
    #data exchange phase
    
    def dataExchange(self): #generate components no need to create session and IV as the user does 
        self.demoHMAC = HMAC()
        self.demoCBC = CBC()
        
    def setData(self, sessionkey, IVA): #this must be top-secret 
        self.demoCBC.setkey(sessionkey, IVA)
        
    def setHMAC(self, m): #for the user verfication message
        self.messageHMAC = m
        
    def dataExchange2(self, taylor): #decrypt the partial messages, para is arrray    
        msg = self.demoCBC.decrypt(taylor) # return as string 
        if self.messageHMAC == self.demoHMAC.HMAC(self.sessionKey, msg): #check verification
            print("Authorized User")
        else: 
            print("Who are you?")
    
    def HMAC1(self): #for the server verfication message 
        swift = "at shined In the sky, the pretty lights. And our daddies used to"
        m = self.demoHMAC.HMAC(self.sessionKey, swift) 
        return m # string type
       
    def dataExchange3(self): #encrypt the message 
        swift = "at shined In the sky, the pretty lights. And our daddies used to"
        self.swiftArray = self.demoCBC.encrypt(swift)
        return self.swiftArray 
        
        
if __name__ == "__main__": #python main is here 
    
    myServer = Server()
    p = int(178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239)
    q = int(174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730)
    
    try: #try to connect a user 
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # creating socket 
        server.bind((socket.gethostname(), Port)) #hosting local machine, port number is 1234
        
        server.listen() #using default 
        print("Setup Phase")
        print("-" * 30)
    except BaseException as b:
        print(b)
        sys.exit(1)
    
    while True: #assume connected 
        
       userSocket, address = server.accept()  #server must acceot the user offer and store user socket and user address
       
       message = userSocket.recv(264) #recv size is 264 might be too big for "hello"
       print("Server Received")
       userSocket.send(message) #server send back to byte "hello" to the user
       message = message.decode(Format) #converting to string ('utf-8')
       
       #generate RSA 
       myServer.setKey(message, 2048) #RSA is 2048 bits long is given
       myServer.updateRSAKeys() #the server set the RSA values
       
       #send to the client order matter DO NOT change the orders 
       userSocket.sendall((myServer.getE().to_bytes(5046, 'big')))
       userSocket.sendall((myServer.getN().to_bytes(5046, 'big')))
       userSocket.sendall((myServer.getSigG().to_bytes(5046, 'big')))
       
       message = userSocket.recv(264) 
       message = message.decode(Format)
       print("Server Received")
       
       print("\nClient to Server: Public Key = \n" + str(myServer.getE() + myServer.getN())) #no meaning to display Public Key
              
       print("Server Received")
        
       print("\nHandShake Phase")

       print("-" * 30)
       print("UserID: " +message)
       
       userSocket.sendall((myServer.getIDs().to_bytes(5046, 'big'))) #send session ID 
       userSocket.sendall((myServer.getServerID().to_bytes(5046, 'big'))) #send server ID 
       
       message = userSocket.recv(264) #recv is User ID
       message = message.decode(Format)
       
       if message == "True": #if the user verified the sigG and hashed 'Hello'
           
           #handshake phase
           print("Creating DH")
           
           userSocket.sendall((p.to_bytes(5046, 'big'))) #these values are given 
           userSocket.sendall((q.to_bytes(5046, 'big')))
           
           myServer.handshake(p, q) #creating DH here 
           
           userSocket.sendall((myServer.getPublic_DH().to_bytes(5046, 'big'))) #send the Server Public DH key for the session key
           userDH = int.from_bytes(userSocket.recv(5046), 'big')
           myServer.session(userDH) #generate session key by the user public key
               
           print("\nData Exchange")
           print("-" * 30)
           
           try: #this must be top-secreat
               myServer.dataExchange() #generate CBC and HMAC
               
               key = userSocket.recv(5046)
               
               userSocket.send(bytes("Okay", 'utf-8'))
               
               IV = userSocket.recv(5046)
               
               print("Server Received Keys")
           except socket.error as msg:
               print ("Socket Error: %s" % msg)
               sys.exit(1)           
          
           myServer.setData(key, IV) #set the key here for CBC and HMAC
           
           '''
           Server recieves First 
           ------------------------------
           '''
           
           try: 
               m = userSocket.recv(264)
               m = m.decode(Format)
               
               myServer.setHMAC(m) #for the user message verification 
               userSocket.send(bytes("Okay", 'utf-8'))
               
           except UnicodeDecodeError as u: #depends on HMAC values
               print (u)
               userSocket.send(bytes("Exit", 'utf-8'))
               sys.exit(1)
               
           print("Server Received")
           
           
           receive = [] #for store the partial messages from the user 
           try:
               recive1 = userSocket.recv(5046) #can do receive[0] = user.recv(5046)??
               userSocket.send(bytes("Okay", 'utf-8')) #prevent server recieve errors
               
               recive2 = userSocket.recv(5046)
               userSocket.send(bytes("Okay", 'utf-8')) #prevent server recieve errors
               
               recive3 = userSocket.recv(5046)
               userSocket.send(bytes("Okay", 'utf-8')) #prevent server recieve errors
               
               recive4 = userSocket.recv(5046)
               
               receive.append(recive1) 
               receive.append(recive2)
               receive.append(recive3) 
               receive.append(recive4)
               print("Server Received Message") 
           except RuntimeError as r:
               print(r)
               sys.exit(1)
           except socket.error as msg:
               print ("Socket Error: %s" % msg)
               sys.exit(1)           
           
           myServer.dataExchange2(receive) #decrypt the messages
           
           '''
           Server sends message 
           ------------------------------
           '''
           
           try:
               userSocket.send(bytes(myServer.HMAC1(), 'utf-8')) #send HMAC for the verification
               
               message = userSocket.recv(264)  #prevent server recieve errors
               message = message.decode(Format)
           except RuntimeError as r:
               print(r)
               sys.exit(1) 
           if message == "Exit":
               print("Server Down") 
               break
           
           exchange = myServer.dataExchange3() #16 bytes return as array type
           try:
               userSocket.sendall(exchange[0])
               message = userSocket.recv(264)  #prevent user recieve errors
               message = message.decode(Format)
               
               userSocket.sendall(exchange[1])
               message = userSocket.recv(264)  #prevent user recieve errors
               message = message.decode(Format)
               
               userSocket.sendall(exchange[2])
               message = userSocket.recv(264)  #prevent user recieve errors
               message = message.decode(Format)
               
               userSocket.sendall(exchange[3])
               print("Server Sent")
           except socket.error as msg:
               print ("Socket Error: %s" % msg)
               sys.exit(1)
           
           message = userSocket.recv(264) #assume the message is Exit
           message = message.decode(Format)
           
           if message == "Exit":
               print("Finish Exchange")
               break
           
       else: 
         break 
        
       break
   
    server.close()
                    