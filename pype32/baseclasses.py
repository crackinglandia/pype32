#!/usr/bin/python
# -*- coding: utf-8 -*- 

# Copyright (c) 2013, Nahuel Riva 
# All rights reserved. 
# 
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met: 
# 
#     * Redistributions of source code must retain the above copyright notice, 
#       this list of conditions and the following disclaimer. 
#     * Redistributions in binary form must reproduce the above copyright 
#       notice,this list of conditions and the following disclaimer in the 
#       documentation and/or other materials provided with the distribution. 
#     * Neither the name of the copyright holder nor the names of its 
#       contributors may be used to endorse or promote products derived from 
#       this software without specific prior written permission. 
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE. 

"""
Base classes.
"""

__revision__ = "$Id$"

class BaseStructClass(object):
    """ Base class containing methods used by many others classes in the library."""
    def __init__(self,  shouldPack = True):
        """
        @type shouldPack: bool
        @param shouldPack: (Optional) If the value is set to C{True}, the class will be packed. If the value is
        set to C{False}, the class will not be packed.
        """
        self.shouldPack = shouldPack
        self._attrsList = []
        
    def __str__(self):
        s = ""
        for i in self._attrsList:
            attr = getattr(self,  i)
            if attr.shouldPack:
                s += str(attr)
        return s
        
    def __len__(self):
        return len(str(self))
            
    def sizeof(self):
        return len(self)
        
    def getFields(self):
        """
        Returns all the class attributues.
        
        @rtype: dict
        @return: A dictionary containing all the class attributes.
        """
        d = {}
        for i in self._attrsList:
            key = i
            value = getattr(self,  i)
            d[key] = value
        return d
        
    def getType(self):
        """
        This method should be implemented in the inherited classes. When implemented, returns
        an integer value to identified the corresponding class.
        
        @raise NotImplementedError: The method wasn't implemented in the inherited class.
        """
        raise NotImplementedError("getType() method not implemented.")
        
class DataTypeBaseClass(object):
    def __init__(self, value = 0, endianness = "<", signed = False, shouldPack = True):
        """
        @type value: int
        @param value: The value used to build the L{BYTE} object.
        
        @type endianness: str
        @param endianness: (Optional) Indicates the endianness of the L{BYTE} object. The C{<} indicates little-endian while C{>} indicates big-endian.
        
        @type signed: bool
        @param signed: (Optional) If set to C{True} the L{BYTE} object will be packed as signed. If set to C{False} it will be packed as unsigned.
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        self.value = value
        self.endianness = endianness
        self.signed = signed
        self.shouldPack = shouldPack

    def __eq__(self, other):
        result = None
        
        if isinstance(other, self.__class__):
            result = self.value == other.value
        else:
            result = self.value == other
        return result
    
    def __ne__(self, other):
        result = None
        
        if isinstance(other, self.__class__):
            result = self.value != other.value
        else:
            result = self.value != other
        return result
    
    def __lt__(self, other):
        result = None
        
        if isinstance(other, self.__class__):
            result = self.value < other.value
        else:
            result = self.value < other
        return result        
    
    def __gt__(self, other):
        result = None
        
        if isinstance(other, self.__class__):
            result = self.value > other.value
        else:
            result = self.value > other
        return result
    
    def __le__(self, other):
        result = None
        
        if isinstance(other, self.__class__):
            result = self.value <= other.value
        else:
            result = self.value <= other
        return result
    
    def __ge__(self, other):
        result = None
        
        if isinstance(other, self.__class__):
            result = self.value >= other.value
        else:
            result = self.value >= other
        return result
        
    def __add__(self, other):
        result = None

        if isinstance(other,  self.__class__):
            try:
                result = self.value + other.value
            except TypeError, e:
                raise e
        else:
            try:
                result = self.value + other
            except TypeError, e:
                raise e
        return result
    
    def __sub__(self, other):
        result = None
        if isinstance(other,  self.__class__):
            try:
                result = self.value - other.value
            except TypeError, e:
                raise e
        else:
            try:
                result = self.value - other
            except TypeError, e:
                raise e
        return result
    
    def __mul__(self, other):
        result = None
        if isinstance(other,  self.__class__):
            result = self.value * other.value
        else:
            try:
                result = self.value * other
            except TypeError, e:
                raise e
        return result
        
    def __div__(self, other):
        result = None
        if isinstance(other,  self.__class__):
            try:
                result = self.value / other.value
            except (TypeError, ZeroDivisionError) as e:
                raise e
        else:
            try:
                result = self.value / other
            except (TypeError, ZeroDivisionError) as e:
                raise e
        return result

    def __xor__(self, other):
        result = None
        if isinstance(other,  self.__class__):
            result = self.value ^ other.value
        else:
            try:
                result = self.value ^ other
            except TypeError, e:
                raise e
        return result
        
    def __rshift__(self, other):
        result = None
        if isinstance(other,  self.__class__):
            result = self.value >> other.value
        else:
            try:
                result = self.value >> other
            except TypeError, e:
                raise e
        return result
        
    def __lshift__(self, other):
        result = None
        if isinstance(other,  self.__class__):
            result = self.value << other.value
        else:
            try:
                result = self.value << other
            except TypeError, e:
                raise e
        return result
        
    def __and__(self, other):
        result = None
        if isinstance(other,  self.__class__):
            result = self.value & other.value
        else:
            try:
                result = self.value & other
            except TypeError, e:
                raise e
        return result

    def __or__(self, other):
        result = None
        if isinstance(other,  self.__class__):
            result = self.value | other.value
        else:
            try:
                result = self.value | other
            except TypeError, e:
                raise e
        return result
