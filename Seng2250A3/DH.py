# -*- coding: utf-8 -*-
"""
Created on Mon Nov  9 15:14:11 2020

@author: Yugi
"""
import random
from FME import FME 


class DH: 
    
    def __int__(self): 
        self.p = 0
        self.q = 0
        self.private = 0
       
    def setSytemPrameters(self, new_P, new_Q):        
        self.p = new_P
        self.q = new_Q
        
    def setPrivate(self):
        self.private = int(random.randrange(1, self.p-1))        
        return self.private
    
    def setPublic(self):
        return FME(self.q , self.private, self.p) #(base, exponemt, modulus) 
    
    def setSession(self, new_public):
        return FME(new_public, self.private, self.p)