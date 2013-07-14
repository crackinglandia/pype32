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
Auxiliary classes and functions.

@group Read/Write data stream objects:
    ReadData, WriteData
"""

__revision__ = "$Id$"

__all__ = [
           "ReadData", 
           "WriteData", 
           ]
           
import excep

from cStringIO import StringIO as cstringio
from StringIO import StringIO
from struct import pack, unpack

def powerOfTwo(value):
    """
    Tries to determine if a given value is a power of two.
    
    @type value: int
    @param value: Value to test if it is power of two.
       
    @rtype: bool
    @return: C{True} if the value is power of two, 
        C{False} if it doesn't.
    """
    return value != 0 and (value & (value - 1)) == 0

def allZero(buffer):
    """
    Tries to determine if a buffer is empty.
    
    @type buffer: str
    @param buffer: Buffer to test if it is empty.
        
    @rtype: bool
    @return: C{True} if the given buffer is empty, i.e. full of zeros,
        C{False} if it doesn't.
    """
    allZero = True
    for byte in buffer:
        if byte != "\x00":
            allZero = False
            break
    return allZero

class WriteData(object):
    """Return a WriteData-like stream object for writing."""
    def __init__(self, data, endianness = "<", signed = False):
        """
        @type data: str
        @param data: Data to create the L{WriteData} object.

        @type endianness: str
        @param endianness: (Optional) Indicates the endianness used to write the data. The C{<} indicates little-endian while C{>} indicates big-endian.
        
        @type signed: bool
        @param signed: (Optional) If set to C{True} the data will be treated as signed. If set to C{False} it will be treated as unsigned.
        """
        self.data = StringIO(data)
        self.endianness = endianness
        self.signed = signed
    
    def __len__(self):
        return len(self.data.buf[self.data.tell():])
    
    def __str__(self):
        return self.data.getvalue()
        
    def writeByte(self, byte):
        """
        Writes a byte into the L{WriteData} stream object.
        
        @type byte: int
        @param byte: Byte value to write into the stream.
        """
        self.data.write(pack("B" if not self.signed else "b", byte))
        
    def writeWord(self, word):
        """
        Writes a word value into the L{WriteData} stream object.
        
        @type word: int
        @param word: Word value to write into the stream.
        """
        self.data.write(pack(self.endianness + ("H" if not self.signed else "h"), word)) 
        
    def writeDword(self, dword):
        """
        Writes a dword value into the L{WriteData} stream object.
        
        @type dword: int
        @param dword: Dword value to write into the stream.
        """        
        self.data.write(pack(self.endianness + ("L" if not self.signed else "l"), dword))
        
    def writeQword(self, qword):
        """
        Writes a qword value into the L{WriteData} stream object.
        
        @type qword: int
        @param qword: Qword value to write into the stream.
        """
        self.data.write(pack(self.endianness + ("Q" if not self.signed else "q"),  qword))
        
    def write(self, dataToWrite):
        """
        Writes data into the L{WriteData} stream object.
        
        @type dataToWrite: str
        @param dataToWrite: Data to write into the stream.
        """
        self.data.write(dataToWrite)
    
    def setOffset(self, value):
        """
        Sets the offset of the L{WriteData} stream object in wich the data is written.
        
        @type value: int
        @param value: Integer value that represent the offset we want to start writing in the L{WriteData} stream.
            
        @raise WrongOffsetValueException: The value is beyond the total length of the data. 
        """
        if value >= len(self.data.getvalue()):
            raise excep.WrongOffsetValueException("Wrong offset value. Must be less than %d" % len(self.data))
        self.data.seek(value)
        
    def skipBytes(self, nroBytes):
        """
        Skips the specified number as parameter to the current value of the L{WriteData} stream.
        
        @type nroBytes: int
        @param nroBytes: The number of bytes to skip.
        """
        self.data.seek(nroBytes + self.data.tell())

    def tell(self):
        """
        Returns the current position of the offset in the L{WriteData} sream object.
        
        @rtype: int
        @return: The value of the current offset in the stream.
        """
        return self.data.tell()
    
    def __del__(self):
        self.data.close()
        del self.data
        
class ReadData(object):
    """Returns a ReadData-like stream object."""
    def __init__(self, data, endianness = "<",  signed = False):
        """
        @type data: str
        @param data: The data from which we want to read.
        
        @type endianness: str
        @param endianness: (Optional) Indicates the endianness used to read the data. The C{<} indicates little-endian while C{>} indicates big-endian.
        
        @type signed: bool
        @param signed: (Optional) If set to C{True} the data will be treated as signed. If set to C{False} it will be treated as unsigned.
        """
        self.data = data
        self.offset = 0
        self.endianness = endianness
        self.signed = signed
        self.log = False

    def __len__(self):
        return len(self.data[self.offset:])
        
    def readDword(self):
        """
        Reads a dword value from the L{ReadData} stream object.
        
        @rtype: int
        @return: The dword value read from the L{ReadData} stream.
        """
        dword = unpack(self.endianness + ('L' if not self.signed else 'l'), self.readAt(self.offset,  4))[0]
        self.offset += 4
        return dword

    def readWord(self):
        """
        Reads a word value from the L{ReadData} stream object.
        
        @rtype: int
        @return: The word value read from the L{ReadData} stream.
        """
        word = unpack(self.endianness + ('H' if not self.signed else 'h'), self.readAt(self.offset, 2))[0]
        self.offset += 2
        return word
        
    def readByte(self):
        """
        Reads a byte value from the L{ReadData} stream object.
        
        @rtype: int
        @return: The byte value read from the L{ReadData} stream.
        """
        byte = unpack('B' if not self.signed else 'b', self.readAt(self.offset,  1))[0]
        self.offset += 1
        return byte
    
    def readQword(self):
        """
        Reads a qword value from the L{ReadData} stream object.
        
        @rtype: int
        @return: The qword value read from the L{ReadData} stream.
        """
        qword = unpack(self.endianness + ('Q' if not self.signed else 'b'),  self.readAt(self.offset, 8))[0]
        self.offset += 8
        return qword
        
    def readString(self):
        """
        Reads an ASCII string from the L{ReadData} stream object.
        
        @rtype: str
        @return: An ASCII string read form the stream.
        """
        resultStr = ""
        while self.data[self.offset] != "\x00":
            resultStr += self.data[self.offset]
            self.offset += 1
        return resultStr

    def readAlignedString(self, align = 4):
        """ 
        Reads an ASCII string aligned to the next align-bytes boundary.
        
        @type align: int
        @param align: (Optional) The value we want the ASCII string to be aligned.
        
        @rtype: str
        @return: A 4-bytes aligned (default) ASCII string.
        """
        s = self.readString()
        r = align - len(s) % align
        while r:
            s += self.data[self.offset]
            self.offset += 1
            r -= 1
        return s
        
    def read(self, nroBytes):
        """
        Reads data from the L{ReadData} stream object.
        
        @type nroBytes: int
        @param nroBytes: The number of bytes to read.
        
        @rtype: str
        @return: A string containing the read data from the L{ReadData} stream object.
        
        @raise DataLengthException: The number of bytes tried to be read are more than the remaining in the L{ReadData} stream.
        """
        if nroBytes > len(self.data[self.offset:]):
            if self.log:
                print "Warning: Trying to read: %d bytes - only %d bytes left" % (nroBytes,  len(self.data[self.offset:]))
            nroBytes = len(self.data[self.offset:])

        resultStr = self.data[self.offset:self.offset + nroBytes]
        self.offset += nroBytes
        return resultStr
        
    def skipBytes(self, nroBytes):
        """
        Skips the specified number as parameter to the current value of the L{ReadData} stream.
        
        @type nroBytes: int
        @param nroBytes: The number of bytes to skip.        
        """
        self.offset += nroBytes
        
    def setOffset(self, value):
        """
        Sets the offset of the L{ReadData} stream object in wich the data is read.
        
        @type value: int
        @param value: Integer value that represent the offset we want to start reading in the L{ReadData} stream.
            
        @raise WrongOffsetValueException: The value is beyond the total length of the data. 
        """
        #if value >= len(self.data):
        #    raise excep.WrongOffsetValueException("Wrong offset value. Must be less than %d" % len(self.data))
        self.offset = value
    
    def readAt(self, offset, size):
        """
        Reads as many bytes indicated in the size parameter at the specific offset.

        @type offset: int
        @param offset: Offset of the value to be read.

        @type size: int
        @param size: This parameter indicates how many bytes are going to be read from a given offset.

        @rtype: str
        @return: A packed string containing the read data.
        """
        if offset > len(self.data):
            if self.log:
                print "Warning: Trying to read: %d bytes - only %d bytes left" % (nroBytes,  len(self.data[self.offset:]))
            offset = len(self.data[self.offset:])
        tmpOff = self.tell()
        self.setOffset(offset)
        r = self.read(size)
        self.setOffset(tmpOff)
        return r
        
    def tell(self):
        """
        Returns the current position of the offset in the L{ReadData} sream object.
        
        @rtype: int
        @return: The value of the current offset in the stream.
        """        
        return self.offset
        