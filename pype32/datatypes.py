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
Data types objects.

@group Strings: 
    String, AlignedString

@group Native:
    BYTE, WORD, DWORD, QWORD, Array
"""

__revision__ = "$Id$"

__all__ = [
           "String", 
           "AlignedString", 
           "BYTE",  
           "WORD",  
           "DWORD",  
           "QWORD", 
           "Array", 
           ]

import utils
import excep

from baseclasses import DataTypeBaseClass
from struct import pack,  unpack

TYPE_QWORD = 0xFECAFECA
TYPE_DWORD = 0xDEADBEEF
TYPE_WORD = 0xCAFECAFE
TYPE_BYTE = 0xC00FEE
TYPE_ARRAY = 0xFECA
UNKNOWN_ARRAY_TYPE = 0xFFFF

class String(object):
    """String object."""
    def __init__(self, value = "", shouldPack = True):
        """
        @type value: str
        @param value: the string to be built.
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        
        @todo: Add a UnicodeString class.
        """
        self.value = value
        self.shouldPack = shouldPack
    
    def __str__(self):
        return self.value
        
    def __len__(self):
        return len(self.value)

    def sizeof(self):
        """
        Returns the size of the string.
        """
        return len(self)
        
class AlignedString(String):
    """Aligned string object."""
    def __init__(self, value, shouldPack = True, align = 4):
        """
        This object represent an aligned ASCII string.
        
        @type value: str
        @param value: The string to be built.
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        
        @type align: int
        @param align: (Optional) The alignment to be used. The default alignment is 4.
        """
        String.__init__(self,  value)
        
        self.align = align
        self.value = value + "\x00" * (self.align - len(value) % self.align)
        self.shouldPack = shouldPack
        
class Array(list):
    """Array object."""
    def __init__(self, arrayType,  shouldPack = True):
        """
        @type arrayType: int
        @param arrayType: The type of array to be built. This value can be C{TYPE_BYTE}, C{TYPE_WORD}, C{TYPE_DWORD} or C{TYPE_QWORD}.
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        
        @todo: Before to add an element to the array we must check if the type of that element is one we are expecting.
        """
        list.__init__(self)

        self.arrayType = arrayType
        self.shouldPack = shouldPack
        
        if not self.arrayType in [TYPE_BYTE,  TYPE_WORD,  TYPE_DWORD,  TYPE_QWORD]:
            raise TypeError("Couldn\'t create an Array of type %r" % self.arrayType)
            
    def __str__(self):
        return ''.join([str(x) for x in self])

    def sizeof(self):
        """
        Returns the size of the array.
        """
        return len(self)
        
    @staticmethod
    def parse(readDataInstance,  arrayType,  arrayLength):
        """
        Returns a new L{Array} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: The L{ReadData} object containing the array data.
        
        @type arrayType: int
        @param arrayType: The type of L{Array} to be built.
        
        @type arrayLength: int
        @param arrayLength: The length of the array passed as an argument.
        
        @rtype: L{Array}
        @return: New L{Array} object.
        """
        newArray = Array(arrayType)
        
        dataLength = len(readDataInstance)
        
        if arrayType is TYPE_DWORD:
            toRead = arrayLength * 4
            if dataLength >= toRead: 
                for i in range(arrayLength):
                    newArray.append(DWORD(readDataInstance.readDword()))
            else:
                raise excep.DataLengthException("Not enough bytes to read.")
                
        elif arrayType is TYPE_WORD:
            toRead = arrayLength * 2
            if dataLength >= toRead:
                for i in range(arrayLength):
                    newArray.append(DWORD(readDataInstance.readWord()))
            else:
                raise excep.DataLengthException("Not enough bytes to read.")
                
        elif arrayType is TYPE_QWORD:
            toRead = arrayLength * 8
            if dataLength >= toRead:
                for i in range(arrayLength):
                    newArray.append(QWORD(readDataInstance.readQword()))
            else:
                raise excep.DataLengthException("Not enough bytes to read.")
                
        elif arrayType is TYPE_BYTE:
            for i in range(arrayLength):
                newArray.append(BYTE(readDataInstance.readByte()))
        
        else:
            raise excep.ArrayTypeException("Could\'t create an array of type %d" % arrayType)
            
        return newArray
    
    def getType(self):
        """
        Returns an integer value identifying the type of object.
        """
        return TYPE_ARRAY
        
class BYTE(DataTypeBaseClass):
    """Byte object."""
    def __init__(self,  value = 0,  endianness = "<",  signed = False,  shouldPack = True):
        DataTypeBaseClass.__init__(self, value, endianness, signed, shouldPack)        
        
    def __str__(self):
        return pack(self.endianness  + ("b" if self.signed else "B"),  self.value)
        
    def __len__(self):
        return len(str(self))

    def getType(self):
        """
        Returns L{TYPE_BYTE}.
        """
        return TYPE_BYTE
    
    def sizeof(self):
        """
        Returns the size of L{BYTE}.
        """
        return len(self)
        
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{BYTE} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with the corresponding data to generate a new L{BYTE} object.
        
        @rtype: L{BYTE}
        @return: A new L{BYTE} object.
        """
        return BYTE(readDataInstance.readByte())
        
class WORD(DataTypeBaseClass):
    """Word object."""
    def __init__(self,  value = 0,  endianness = "<",  signed = False,  shouldPack = True):
        DataTypeBaseClass.__init__(self, value, endianness, signed, shouldPack)    
        
    def __str__(self):
        return pack(self.endianness + ("h" if self.signed else "H"),  self.value)
    
    def __len__(self):
        return len(str(self))

    def getType(self):
        """
        Returns L{TYPE_WORD}.
        """
        return TYPE_WORD
    
    def sizeof(self):
        """Returns the size of L{WORD}."""
        return len(self)
        
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{WORD} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object containing the necessary data to build a new L{WORD} object.
        
        @rtype: L{WORD}
        @return: A new L{WORD} object.
        """
        return WORD(readDataInstance.readWord())
        
class DWORD(DataTypeBaseClass):
    """Dword object."""
    def __init__(self,  value = 0,  endianness = "<",  signed = False,  shouldPack = True):
        DataTypeBaseClass.__init__(self, value, endianness, signed, shouldPack)    
        
    def __str__(self):
        return pack(self.endianness  + ("l" if self.signed else "L"),  self.value)
    
    def __len__(self):
        return len(str(self))

    def getType(self):
        """Returns L{TYPE_DWORD}."""
        return TYPE_DWORD
    
    def sizeof(self):
        """Returns the size of L{DWORD}."""
        return len(self)
        
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{DWORD} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with the necessary data to build a new L{DWORD} object.
        
        @rtype: L{DWORD}
        @return: A new L{DWORD} object.
        """
        return DWORD(readDataInstance.readDword())
        
class QWORD(DataTypeBaseClass):
    """Qword object."""
    def __init__(self,  value = 0,  endianness = "<",  signed = False,  shouldPack = True):
        DataTypeBaseClass.__init__(self, value, endianness, signed, shouldPack)        
        
    def __str__(self):
        return pack(self.endianness + ("q" if self.signed else "Q"),  self.value)
        
    def __len__(self):
        return len(str(self))
    
    def getType(self):
        """Returns L{TYPE_QWORD}."""
        return TYPE_QWORD
    
    def sizeof(self):
        """Returns the size of L{QWORD}."""
        return len(self)
        
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{QWORD} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with the necessary data to build a new L{QWORD} object.
        
        @rtype: L{QWORD}
        @return: A new L{QWORD} object.
        """
        return QWORD(readDataInstance.readQword())
        
