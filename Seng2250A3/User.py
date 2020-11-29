# -*- coding: utf-8 -*-
"""
Created on Sat Nov  7 23:23:29 2020

@author: Yugi
"""

from FME import FME 
from DH import DH
from HMAC import HMAC
from CBC import CBC
from Crypto.Hash import SHA256
import socket
import sys


Port = 1234
Header = 1024
Format = "utf-8"

class User:
    
    def __int__(self): #construct the components NOT give values as Python returns no attributes...don't know why
        self.userID = None
        self.message = None        
        
        """
        public key components of the server
        """
        self.n_RSA = 0 # n = p*q
        self.e_RSA = 0        
        self.sigG_RSA = 0        
        
        """
        public key components of the user DH
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
        
        self.taylorArray = []
        
    #setup phase     
        
    def setUser(self, new_ID, new_message): #update user here because of no attributes error
        self.userID = new_ID
        self.message = new_message
        
    def setRSA(self, new_e, new_N, new_sigG): #update RSA 
        self.e_RSA = new_e 
        self.n_RSA = new_N
        self.sigG_RSA = new_sigG
        
    def sigVerfication(self): #verify by the user 
        hash = SHA256.new(data = self.message.encode('utf-8'))
        hash = hash.digest()
        hash = int.from_bytes(hash, byteorder = 'big' ) 
        if hash == FME(self.sigG_RSA, self.e_RSA, self.n_RSA): #if hashed "hello" is sigG
            return True            
        
    def getMessage(self): #for printing out "Hello" can replace 
        return self.message
    
    def getUserID(self): #for sending USerID, that's all
        return self.userID
    
    #handshake phase
    
    def setDH(self, new_p, new_q): #p and q are given 
        self.p = new_p
        self.q = new_q
     
    def handshake(self, p, q): #generating DH 
        self.demoDH = DH()
        self.setDH(p, q) #not necessary to do this as line 88 
        self.demoDH.setSytemPrameters(self.p, self.q)
        self.private_DH = self.demoDH.setPrivate() #DH: selecting private key first then public key
        self.public_DH = self.demoDH.setPublic() #generate public key, this goes to the server
        
    def session(self, public_key_S): 
        self.sessionKey = self.demoDH.setSession(public_key_S) #by Server Public key
        
    def getPublic_DH(self):
        return self.public_DH
    
    def getSession_DH(self):
        return self.sessionKey
            
    #data exchange phase
    
    def dataExchange(self): #generate data exchange components here 
        self.demoHMAC = HMAC()
        self.demoCBC = CBC()
        self.demoCBC.createKey(self.sessionKey) #user generate CBC keys: neither Server or User is okay, but only one of them
    
    def getKey(self): 
        return self.demoCBC.getKey() #16 bytes Assume the connection is secured and this must be top-secret
    
    def getIV(self): 
        return self.demoCBC.getIV() #16 bytes Assume the connection is secured and this must be top-secret
    
    def HMAC1(self): #Before exchange the message original one goes to the server for authorization
        taylor = "I was seven, and you were nine I looked at you like the stars th"
        m = self.demoHMAC.HMAC(self.sessionKey, taylor) # assume this is tag
        return m # string type
        
    def dataExchange2(self): #encrypting the message return as array
        taylor = "I was seven, and you were nine I looked at you like the stars th"                
        self.taylorArray = self.demoCBC.encrypt(taylor) #already session and IV are created in line 106
        return self.taylorArray       
        
    def setHMAC(self, m): #set the server HMAC value for decrypted message
        self.messageHMAC = m
    
    def dataExchange3(self, swift): #decrypt partial messages and return as string 
        msg = self.demoCBC.decrypt(swift)
        if  self.messageHMAC == self.demoHMAC.HMAC(self.sessionKey, msg): # verification check 
            print("Authorized Server")
        else: 
            print("Who are you?")
        
        
if __name__ == "__main__": #Python main is this way
        
    myUser = User()
    myUser.setUser("Demo12345", "Hello")
    
    try: #try to connect the server 
        user = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        
        user.connect((socket.gethostname(), Port)) #connect(address and port) local computer address is gethostname()
    except BaseException as b:
        print(b)
        sys.exit(1)
    
    while True: #assume connected here
        
        '''
        Setup Phase
        ------------------------------
        '''
        user.send(bytes("Hello", 'utf-8')) # sending the value should(must?) be byte
        print("Server to Client: " + myUser.getMessage())
        
        msg = user.recv(Header) #recv needs recv size
        msg = msg.decode(Format) #byte to string need format like 'utf-8'
        
        E = int.from_bytes(user.recv(5046), 'big') #receive the from the server
        
        N = int.from_bytes(user.recv(5046), 'big')
        
        G = int.from_bytes(user.recv(5046), 'big')        
        
        myUser.setRSA(E, N, G) #set the value, do nto change the para orders otherwise cannot work
        print("User Received")
        user.send(bytes(myUser.getUserID(), 'utf-8')) #send user ID, no meaning this session 
        
        msgS = int.from_bytes(user.recv(5046), 'big') #recv is session ID no meaning this session
        
        msgE = int.from_bytes(user.recv(5046), 'big') #recv is server ID no meaning this session
        
        print("User Recived SessionID and ServreId") #just display the IDs
        print(str(msgS) + " : " + str(msgE))
        
        if myUser.sigVerfication(): #check if the sigG and my hashed "hello" is the same 
            
            '''
            HandShake Phase
            ------------------------------
            '''
            
            user.send(bytes("True", 'utf-8')) #send the verified message to the server 
            print("Server to Client: Checking Verfication For ShakeHand")
            p = int.from_bytes(user.recv(5046), 'big') #recv is for DH
        
            q = int.from_bytes(user.recv(5046), 'big') #recv is for DH          
            
            myUser.handshake(p, q) #generate DH values
            serverDH = int.from_bytes(user.recv(5046), 'big') #recv is server public key (DH) for the session key  
            user.sendall((myUser.getPublic_DH().to_bytes(5046, 'big'))) #for the session key  
            myUser.session(serverDH)
            
            
            '''
            Data Exchange Phase
            ------------------------------
            '''
            
            print("\nData Exchange")
            print("-" * 30)
            
            
            
            #sharing keys must be top-secret 
            myUser.dataExchange() #generate the keys by the user 
            user.send(myUser.getKey()) #16 bytes type
            
            message = user.recv(264)
            message = message.decode(Format) #prevent server recieve errors
            
            user.send(myUser.getIV())
            print("User Sent Keys")
            
            
            '''
            User sends message first 
            ------------------------------
            '''            
            
            try:
                user.send(bytes(myUser.HMAC1(), 'utf-8')) #send HMAC for verification             
                message = user.recv(264)
                message = message.decode(Format)
            except RuntimeError as r:
               print(r)
               sys.exit(1)  
            
            if message == "Exit":
               print("Server Down") 
               break
            
            exchange = myUser.dataExchange2() #16 bytes encryt the message here return as array  
            
            try: 
                user.sendall(exchange[0]) #sends byte type 
                message = user.recv(264)
                message = message.decode(Format) #prevent server recieve errors
                
                user.sendall(exchange[1])
                message = user.recv(264)
                message = message.decode(Format) #prevent server recieve errors
                
                user.sendall(exchange[2])
                message = user.recv(264)
                message = message.decode(Format) #prevent server recieve errors
                
                user.sendall(exchange[3])
                print("User Sent Message")
                
            except socket.error as msg:
               print ("Socket Error: %s" % msg)
               sys.exit(1)
            
            
            '''
            User receives message  
            ------------------------------
            '''  
            
            try:   
                m = user.recv(264)
                m = m.decode(Format) #for verification the server message
                myUser.setHMAC(m) #set the value
                user.send(bytes("Okay", 'utf-8'))
            except UnicodeDecodeError as u: #depends on HMAC values
                print(u)
                user.send(bytes("Exit", 'utf-8'))
                sys.exit(1)
               
            receive = [] #receives 4 parts of messgaes
            try:
                receive1 = user.recv(5046) #can do receive[0] = user.recv(5046)??
                user.send(bytes("Okay", 'utf-8')) #prevent the recieve error
                receive2 = user.recv(5046)
                user.send(bytes("Okay", 'utf-8'))
                receive3 = user.recv(5046)
                user.send(bytes("Okay", 'utf-8'))
                receive4 = user.recv(5046)
                
                receive.append(receive1) #the message stores to the array    
                receive.append(receive2)            
                receive.append(receive3)           
                receive.append(receive4)                
                print("User Received")
            except RuntimeError as r:
               print(r)
               sys.exit(1)                
            except socket.error as msg:
               print ("Socket Error: %s" % msg)
               sys.exit(1)
               
            myUser.dataExchange3(receive) #decrypt the message and verify the server here 
            
            user.send(bytes("Exit", 'utf-8'))
            
            print("Finish Exchange")
            break
        else: 
            print("You are not my Server")
            break
        break
    user.close()
    
    