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
Data directory classes.
"""

__revision__ = "$Id$"

__all__ = [
           "Directory", 
           "DataDirectory", 
           ]
           
import consts
import excep
import datatypes

from struct import pack

dirs = ["EXPORT_DIRECTORY","IMPORT_DIRECTORY","RESOURCE_DIRECTORY","EXCEPTION_DIRECTORY","SECURITY_DIRECTORY",\
"RELOCATION_DIRECTORY","DEBUG_DIRECTORY","ARCHITECTURE_DIRECTORY","RESERVED_DIRECTORY","TLS_DIRECTORY",\
"CONFIGURATION_DIRECTORY","BOUND_IMPORT_DIRECTORY","IAT_DIRECTORY","DELAY_IMPORT_DIRECTORY","NET_METADATA_DIRECTORY",\
"RESERVED_DIRECTORY"]

class Directory(object):
    """Directory object."""
    def __init__(self, shouldPack = True):
        """
        Class representation of the C{IMAGE_DATA_DIRECTORY} structure. 
        @see: U{http://msdn.microsoft.com/es-es/library/windows/desktop/ms680305%28v=vs.85%29.aspx}
        
        @type shouldPack: bool
        @param shouldPack: If set to C{True} the L{Directory} object will be packed. If set to C{False} the object won't be packed.
        """
        self.name = datatypes.String("")
        self.rva = datatypes.DWORD(0) #: L{DWORD} rva.
        self.size = datatypes.DWORD(0) #: L{DWORD} size.
        self.info = None #: This variable holds the information of the directory.
        self.shouldPack = shouldPack
        
    def __str__(self):
        return str(self.rva) + str(self.size)

    def __len__(self):
        return len(str(self))

    def __dir__(self):
        return sorted(self.__dict__.keys())
        
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a L{Directory}-like object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: L{ReadData} object to read from.
        
        @rtype: L{Directory}
        @return: L{Directory} object.
        """
        d = Directory()
        d.rva.value = readDataInstance.readDword()
        d.size.value = readDataInstance.readDword()
        return d

    def getType(self):
        """Returns a value that identifies the L{Directory} object."""
        return consts.IMAGE_DATA_DIRECTORY
        
class DataDirectory(list):
    """DataDirectory object."""
    def __init__(self,  shouldPack = True):
        """
        Array of L{Directory} objects.
        
        @type shouldPack: bool
        @param shouldPack: If set to C{True} the L{DataDirectory} object will be packed. If set to C{False} the object won't packed.
        """
        self.shouldPack = shouldPack
        
        for i in range(consts.IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
            dir = Directory()
            dir.name.value = dirs[i]
            self.append(dir)
    
    def __str__(self):
        packedRvasAndSizes = ""
        for directory in self:
            packedRvasAndSizes += str(directory)
        return packedRvasAndSizes
        
    @staticmethod
    def parse(readDataInstance):
        """Returns a L{DataDirectory}-like object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: L{ReadData} object to read from.
        
        @rtype: L{DataDirectory}
        @return: The L{DataDirectory} object containing L{consts.IMAGE_NUMBEROF_DIRECTORY_ENTRIES} L{Directory} objects.
        
        @raise DirectoryEntriesLengthException: The L{ReadData} instance has an incorrect number of L{Directory} objects.
        """
        if len(readDataInstance) == consts.IMAGE_NUMBEROF_DIRECTORY_ENTRIES * 8:
            newDataDirectory = DataDirectory()
            for i in range(consts.IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
                newDataDirectory[i].name.value = dirs[i]
                newDataDirectory[i].rva.value = readDataInstance.readDword()
                newDataDirectory[i].size.value = readDataInstance.readDword()
        else:
            raise excep.DirectoryEntriesLengthException("The IMAGE_NUMBEROF_DIRECTORY_ENTRIES does not match with the length of the passed argument.")
        return newDataDirectory
    
