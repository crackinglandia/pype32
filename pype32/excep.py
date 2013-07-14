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
Exceptions used by the entire library.

@group Base exceptions: 
    PyPe32Exception, PyPe32Warning

@group Warnings: 
    PEWarning
    
@group Exceptions: 
    PEException,NotValidPathException,WrongOffsetValueException,DirectoryEntriesLengthException,
    TypeNotSupportedException,ArrayTypeException,DataLengthException,ReadDataOffsetException,
    WriteDataOffsetException,InstanceErrorException,DataMismatchException,SectionHeadersException,
    DirectoryEntryException,InvalidParameterException
"""

__revision__ = "$Id$"

__all__ = [
           "PyPe32Exception",
            "PyPe32Warning", 
            "PEWarning", 
            "PEException", 
            "NotValidPathException", 
            "WrongOffsetValueException", 
            "DirectoryEntriesLengthException", 
            "TypeNotSupportedException", 
            "ArrayTypeException", 
            "DataLengthException", 
            "ReadDataOffsetException", 
            "WriteDataOffsetException", 
            "InstanceErrorException",
            "DataMismatchException", 
            "SectionHeadersException", 
            "DirectoryEntryException", 
            "InvalidParameterException", 
           ]
           
class PyPe32Exception(Exception):
    """Base exception class."""
    pass

class PyPe32Warning(Exception):
    """Base warning class."""
    pass

class PEWarning(PyPe32Warning):
    """Raised when a suspicious value is found into the PE instance."""
    pass
    
class PEException(PyPe32Exception):
    """Raised when an invalid field on the PE instance was found."""
    pass
    
class NotValidPathException(PyPe32Exception):
    """Raised when a path wasn't found or it is an invalid path."""
    pass
    
class WrongOffsetValueException(PyPe32Exception):
    """
    Used primary by the L{ReadData} and L{WriteData} object in read/write operations when an invalid
    offset value was used.
    """
    pass
    
class DirectoryEntriesLengthException(PyPe32Exception):
    """Raised when the the number of entries in a L{DataDirectory} object is different from L{consts.IMAGE_NUMBEROF_DIRECTORY_ENTRIES}."""
    pass

class TypeNotSupportedException(PyPe32Exception):
    """This exception must be used when an invalid data type is used within the library."""
    pass
    
class ArrayTypeException(PyPe32Exception):
    """Raised when creating an unsupported type of array."""
    pass

class DataLengthException(PyPe32Exception):
    """Raised when data lengths does not match."""
    pass
    
class ReadDataOffsetException(PyPe32Exception):
    """This exception must be raised when reading from an invalid offset."""
    pass

class WriteDataOffsetException(PyPe32Exception):
    """This exception must be raised when writing to an invalid offset."""
    pass
    
class InstanceErrorException(PyPe32Exception):
    """This exception is raised when an instance parameter was not specified."""
    pass
    
class DataMismatchException(PyPe32Exception):
    """Raised when two different types of data does not match."""
    pass
    
class SectionHeadersException(PyPe32Exception):
    """Raised when an error related to a L{pype32.SectionHeader} or L{pype32.SectionHeaders} is found."""
    pass

class DirectoryEntryException(PyPe32Exception):
    """This exception must be raised when an error with the L{Directory} is found."""
    pass
    
class InvalidParameterException(PyPe32Exception):
    """Raised when an invalid parameter is received."""
    pass
    
