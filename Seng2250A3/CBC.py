# -*- coding: utf-8 -*-
"""
Created on Thu Nov 12 01:55:30 2020

@author: Yugi
"""

from Crypto.Cipher import AES
import os
import sys

BLOCK_SIZE = 16

class CBC:
    
    def __int__(self):
        self.key = 0
        self.IVA = 0
        
    def bigKey(self, key):
        try:
            big = key%16
            s ='1'
            max = s*big
            max = int(max)
            result = key%max
            bresult = result.to_bytes(16, 'big')
            return bresult
        except ValueError as v:
            print(v)
            sys.exit(1)
    
    def createKey(self, sessionkey): #generating IV and converting to bytes for XOR
        key = sessionkey #session key
        self.key = self.bigKey(key) #return 16 bytes
        self.IVA = os.urandom(BLOCK_SIZE) # 16 bytes
        
    def setkey(self, sessionkey, IVA):
        self.key = sessionkey
        self.IVA = IVA
        
    def getKey(self): # bytes
        return self.key
    
    def getIV(self): # bytes
        return self.IVA 
        
    def encrypt(self, message): 
        
        IV = int.from_bytes(self.IVA, 'big') #int type
        
        #creating blocks and converting to bytes for XOR
        blocks = []
        start = 0
        end = 16
        for i in range(4):
            text = message[start:end]
            btext = str.encode(text)
            intText = int.from_bytes(btext, 'big')
            blocks.append(intText)
            start = end
            end = end +16
            
        #IV XOR text Int
        cbc1 = blocks[0] ^ IV # int
        cbc1 = cbc1.to_bytes(16, 'big') #16 bytes
        
        #Encrypting the blocked messages by AES with session key
        aes_mode = AES.MODE_CBC # creating mode
        
        cipher = AES.new(self.key, aes_mode, self.IVA) # 3 args (bytes) 
        ct_bytes = []
        ct_bytes.append(cipher.encrypt(cbc1)) # this is for the next encryption store as 16 bytes        
       
        i = 0
        
        for x in range (3):
             
            temp = int.from_bytes(ct_bytes[i], 'big') # ct_bytes[i]
            
            cbc = blocks[i+1] ^ temp  #int 
            
            ciphertext = cbc.to_bytes(16, 'big') #bytes cbc[i]           
            
            NIV = ct_bytes[i] #16 bytes for encryption
            
            cipher = AES.new(self.key, aes_mode, NIV) 
           
            temp = cipher.encrypt(ciphertext) 
            
            ct_bytes.append(temp) #16 bytes
            
            i += 1 
        return ct_bytes
       
    def decrypt(self, message): #already shared the keys
        '''
        necessary compoments
        '''
        msg = '' #for return message as string type
        original = [] #store the decrypted message as array 
        IVd = [] #for decrypt
        XOR = [] #CBC exclusive 
        IV = int.from_bytes(self.IVA, 'big') #int 
        
        #initial decrypt with IV
        
        aes_mode = AES.MODE_CBC #decrypt as CBC
        cipher = AES.new(self.key, aes_mode, self.IVA) #creating cipher mode
        text = cipher.decrypt(message[0]) #decrypt the message, but not readable
        IVd.append(text) # for next decryption 16 bytes
        
        inttext = int.from_bytes(text, 'big') #int
        XOR.append(inttext) #for next decryption (XOR) phase
        text = inttext ^ IV # XOR IV and first text --> readable when convert to "utf-8" !!now just INT
        
        text = text.to_bytes(16, 'big') #converting to bytes for 'utf-8'
        
        text = text.decode('utf-8') #back to the original message[1]     
        
        original.append(text) #append for the return
        
        i = 0 #not necessary to have i as x can work
        for x in range(3): 
                        
            cipher = AES.new(self.key, aes_mode, IVd[i]) #creating this time cipher mode !!each time different cipher values
            
            text = cipher.decrypt(message[i+1]) #decrypt partial messages
            IVd.append(text) # for the next session             
            
            inttext = int.from_bytes(text, 'big') #convert to int for XOR
            XOR.append(inttext) # for the next XOR
            text = inttext ^ XOR[i] #XOR the previous value and now readable, but Int
            
            text = text.to_bytes(16, 'big') #convert to byte for 'utf-8'
            
            text = text.decode('utf-8') #now readable
            
            original.append(text) #append for the return 
            i += 1             
        
        for i in range(len(original)): #append the partial messsge             
            msg += original[i]        
            
        msg =str(msg) # to make sure 
        
        print("Your Messgage is: " +msg) 
        return msg