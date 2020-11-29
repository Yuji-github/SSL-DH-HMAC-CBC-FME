
# -*- coding: utf-8 -*-
"""
Created on Sat Nov  7 17:17:30 2020

@author: Yugi
"""

import Crypto.Util.number #calculate RSA 
from Crypto.Hash import SHA256

import os

from FME import FME 

class RSA:    
    
    def __init__(self):
        
        """
        pirvate key components must be hidden 
        """
        self.p = 0
        self.q = 0
        self.d = 0
        
        self.m = 0 # m = (p-1)*(q-1)
        
        """
        public key components
        """
        self.e = 0 # this value is given 
        self.n = 0 # n = p*q
        
        self.sigG = 0 #sigG = hash(message)^d mod n, I use SHA 256 for the hash
        self.hashedMessage = 0 #for verification phase

    def RSA(self, bits, new_e):
        
        self.e = new_e # this value is given 
        
        # |n| = |p| + |q| ---> |2048| = |1024| + |1024|
        # these P and q are private key 
        self.p = Crypto.Util.number.getPrime(int(bits/2), randfunc = os.urandom)       
    
        self.q = Crypto.Util.number.getPrime(int(bits/2), randfunc = os.urandom)
        
        #calcualte public key 
        
        self.n = self.p * self.q
        
        #calcualte private key 
        
        self.m = (self.p-1) * (self.q-1)
        
        # ed = 1 mod m
        
        self.d = Crypto.Util.number.inverse(self.e, self.m)
         
    def sigGeneration(self, message):        
        hash = SHA256.new(data = message.encode('utf-8'))        
        hash = hash.digest()
        hash = int.from_bytes(hash, byteorder = 'big') 
        self.hashedMessage = hash
        self.sigG = FME(hash, self.d, self.n) #(base, exponemt, modulus) 
    

    """
    pirvate key components 
    """    
    def getP(self):
        return self.p
    
    def getQ(self):
        return self.q
  
    def getD(self):
        return self.d  
    
    
    """
    public key components
    """
    
    def getN(self): # e is given, I assume the user know e is 65537
        return self.n 
    
    """
    Signatures
    """
    
    def getSigG(self):
        return self.sigG
    
    def getHashedM(self):
        return self.hashedMessage