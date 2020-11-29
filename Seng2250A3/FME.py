# -*- coding: utf-8 -*-
"""
Created on Sat Nov  7 16:50:08 2020

@author: Yugi
"""

b = 0
e = 0
n = 0


def FME(base, exponemt, modulus):
     b = base
     e = exponemt
     n = modulus
     
     if (n == 1):         
            return 0 # end of if (n == 1):  
        
     rs = 1 #
     
     while(e > 0):
         
        if(e & 1) == 1:
            rs =( (rs * b) % n) #end of if(e & 1) == 1:
         
        e = e >> 1
        b = ((b*b) % n) #end of while loop
       
     return rs  

