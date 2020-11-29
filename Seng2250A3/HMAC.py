# -*- coding: utf-8 -*-
"""
Created on Tue Nov 10 20:37:50 2020

@author: Yugi
"""

import hashlib as h1
import sys

class HMAC:
    
    def __int__(self):
        self.hashedkey = 0
        self.Hmac = 0 
        
    def Hash(self, x):
        return h1.sha3_256(x).hexdigest()       
   
    def bigKey(self, key): #session key cannot convert to 16 bytes as too big. Here is reduce the value
        try:
            big = key % 16
            s = "1"
            max = s*big
            max = int(max)
            result = key % (128*max) #sometime error happens here, depends on session key
            bresult = result.to_bytes(16, 'big')
            return bresult
        except ValueError as v:
            print(v)
            sys.exit(1)
    
    def HMAC(self, hashedK, message): # asstume this value is tag = HMAC(K', m)
        hashedK = int(self.bigKey(hashedK).hex(), 16)
        message = bytes(message, 'utf-8').hex()
        
        opad = int("5c"*32, 16)
        ipad = int("69"*32, 16)
        return self.Hash( bytes.fromhex ( hex(hashedK ^ opad)[2:] + 
                                         self.Hash(bytes.fromhex(hex(hashedK^ipad)[2:])) + 
                                         message))
                