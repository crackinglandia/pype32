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
Yet another Python library to work with PE32 and PE64 file formats.

by Nahuel Riva (crackinglandia at gmail.com)

Project: U{http://code.google.com/p/pype32}

Blog: U{http://crackinglandia.blogspot.com}

@group PE:
    PE, DosHeader, NtHeaders, OptionalHeader, SectionHeader, SectionHeaders, OptionalHeader64, FileHeader, Sections

@group Data type objects:
    String, AlignedString, Array, BYTE, WORD, DWORD, QWORD

@group Utilities:
    ReadData, WriteData
    
@group Exceptions:
    PyPe32Exception,NotValidPathException,WrongOffsetValueException,DirectoryEntriesLengthException,
    TypeNotSupportedException,ArrayTypeException,DataLengthException,ReadDataOffsetException,
    WriteDataOffsetException,InstanceErrorException,DataMismatchException,SectionHeadersException,
    DirectoryEntryException,InvalidParameterException
    
@group Directories:
    Directory, DataDirectory, ImageBoundForwarderRefEntry, ImageBoundForwarderRef,
    ImageBoundImportDescriptor, ImageBoundImportDescriptorEntry, TLSDirectory, TLSDirectory64, ImageBaseRelocationEntry, 
    ImageBaseRelocation, ImageDebugDirectory, ImageDebugDirectories, ImageImportDescriptorMetaData, ImageImportDescriptorEntry,
    ImageImportDescriptor, ImportAddressTableEntry, ImportAddressTableEntry64, ImportAddressTable, ExportTable, ExportTableEntry, 
    ImageExportTable, NETDirectory, NetDirectory, NetMetaDataHeader, NetMetaDataStreamEntry, NetMetaDataStreams, NetMetaDataTableHeader, 
    NetMetaDataTables
    
@type version: str
@var version: This pype32 release version.
"""

__revision__ = "$Id$"

__all__ = [
           # Lirabry version
           "version", 
           "version_number", 
           
           # from pype32 import *
           "PE", 
           "DosHeader", 
           "NtHeaders", 
           "OptionalHeader",
           "OptionalHeader64",  
           "SectionHeader", 
           "SectionHeaders",
           "FileHeader", 
           "Sections", 
           
           # from datatypes import *
            "String", 
            "AlignedString", 
            "Array", 
            "BYTE", 
            "WORD", 
            "DWORD", 
            "QWORD", 
            
            # from utils import *
            "ReadData",  
            "WriteData", 
            
            # from excep import *
            "PyPe32Exception", 
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
            
            # from datadirs import *
            "DataDirectory", 
            "Directory", 
            
            # from directories import *
            "Directory",
            "DataDirectory",
            "ImageImportDescriptor",
            "ImageBoundForwarderRefEntry",
            "ImageBoundForwarderRef",
            "ImageBoundImportDescriptor",
            "ImageBoundImportDescriptorEntry",
            "TLSDirectory",
            "TLSDirectory64",
            "ImageBaseRelocationEntry",
            "ImageBaseRelocation",
            "ImageDebugDirectory",
            "ImageDebugDirectories",
            "ImageImportDescriptorMetaData",
            "ImageImportDescriptorEntry",
            "ImageImportDescriptor",
            "ImportAddressTableEntry",
            "ImportAddressTableEntry64",
            "ImportAddressTable",
            "ExportTable",
            "ExportTableEntry",
            "ImageExportTable",
            "NETDirectory",
            "NetDirectory",
            "NetMetaDataHeader",
            "NetMetaDataStreamEntry",
            "NetMetaDataStreams",
            "NetMetaDataTableHeader",
            "NetMetaDataTables", 
           ]

from datadirs import Directory, DataDirectory
from datatypes import String, AlignedString, Array, BYTE, WORD, DWORD, QWORD
from directories import *
from excep import *
from utils import ReadData, WriteData
from pype32 import *

# Library version
version_number = 0.1
version = "Version %s" % version_number
