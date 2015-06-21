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
PE directory classes.
"""

__revision__ = "$Id$"
           
import datatypes
import consts
import datadirs
import excep
import utils
import baseclasses
import dotnet

# typedef struct IMAGE_BOUND_FORWARDER_REF
# {
#    DWORD   TimeDateStamp;
#    WORD    OffsetModuleName;
#    WORD    Reserved;
# }
class ImageBoundForwarderRefEntry(baseclasses.BaseStructClass):
    """ImageBoundForwarderRefEntry object."""
    def __init__(self,  shouldPack = True):
        """
        This class represents an element of type C{IMAGE_BOUND_FORWARDER_REF}.
        @see: U{http://msdn.microsoft.com/en-us/magazine/cc301808.aspx}
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self,  shouldPack)
        
        self.timeDateStamp = datatypes.DWORD(0) #: L{DWORD} timeDateStamp.
        self.offsetModuleName = datatypes.WORD(0) #: L{WORD} offsetModuleName.
        self.reserved = datatypes.WORD(0) #: L{WORD} reserved.
        self.moduleName = datatypes.String(shouldPack = False) #: moduleName is metadata, not part of the structure.
        
        self._attrsList = ["timeDateStamp",  "offsetModuleName",  "reserved",  "moduleName"]
    
    def getType(self):
        """Returns L{consts.IMAGE_BOUND_FORWARDER_REF_ENTRY}."""
        return consts.IMAGE_BOUND_FORWARDER_REF_ENTRY
    
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{ImageBoundForwarderRefEntry} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with the corresponding data to generate a new L{ImageBoundForwarderRefEntry} object.
        
        @rtype: L{ImageBoundForwarderRefEntry}
        @return: A new L{ImageBoundForwarderRefEntry} object.
        """
        boundForwarderEntry = ImageBoundForwarderRefEntry()
        boundForwarderEntry.timeDateStamp.value = readDataInstance.readDword()
        boundForwarderEntry.offsetModuleName.value = readDataInstance.readWord()
        boundForwarderEntry.reserved.value = readDataInstance.readWord()
        return boundForwarderEntry

class ImageBoundForwarderRef(list):
    """ImageBoundForwarderRef array object."""
    def __init__(self, shouldPack = True):
        """
        This class is a wrapper over an array of C{IMAGE_BOUND_FORWARDER_REF}.
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        list.__init__(self)
        self.shouldPack = shouldPack
    
    def __str__(self):
        return ''.join([str(x) for x in self if x.shouldPack])
    
    @staticmethod
    def parse(readDataInstance,  numberOfEntries):
        """
        Returns a L{ImageBoundForwarderRef} array where every element is a L{ImageBoundForwarderRefEntry} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with the corresponding data to generate a new L{ImageBoundForwarderRef} object.
        
        @type numberOfEntries: int
        @param numberOfEntries: The number of C{IMAGE_BOUND_FORWARDER_REF} entries in the array.
        
        @rtype: L{ImageBoundForwarderRef}
        @return: A new L{ImageBoundForwarderRef} object.
        
        @raise DataLengthException: If the L{ReadData} instance has less data than C{NumberOfEntries} * sizeof L{ImageBoundForwarderRefEntry}.
        """
        imageBoundForwarderRefsList = ImageBoundForwarderRef()
        dLength = len(readDataInstance)
        entryLength = ImageBoundForwarderRefEntry().sizeof()
        toRead = numberOfEntries * entryLength
        
        if dLength >= toRead:
            for i in range(numberOfEntries):
                entryData = readDataInstance.read(entryLength)
                rd = utils.ReadData(entryData)
                imageBoundForwarderRefsList.append(ImageBoundForwarderRefEntry.parse(rd))
        else:
            raise excep.DataLengthException("Not enough bytes to read.")
        
        return imageBoundForwarderRefsList

class ImageBoundImportDescriptor(list):
    """ImageBoundImportDescriptor object."""
    def __init__(self, shouldPack = True):
        """
        Array of L{ImageBoundImportDescriptorEntry} objects.
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        list.__init__(self)
        self.shouldPack = shouldPack

    def __str__(self):
        return ''.join([str(x) for x in self if x.shouldPack])

    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{ImageBoundImportDescriptor} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object containing the data to create a new L{ImageBoundImportDescriptor} object.
        
        @rtype: L{ImageBoundImportDescriptor}
        @return: A new {ImageBoundImportDescriptor} object.
        """
        ibd = ImageBoundImportDescriptor()
        
        entryData = readDataInstance.read(consts.SIZEOF_IMAGE_BOUND_IMPORT_ENTRY32)
        readDataInstance.offset = 0
        while not utils.allZero(entryData):
            prevOffset = readDataInstance.offset
            
            boundEntry = ImageBoundImportDescriptorEntry.parse(readDataInstance)
            
            # if the parsed entry has numberOfModuleForwarderRefs we must adjust the value in the readDataInstance.offset field
            # in order to point after the last ImageBoundForwarderRefEntry.
            if boundEntry.numberOfModuleForwarderRefs.value:
                readDataInstance.offset = prevOffset + (consts.SIZEOF_IMAGE_BOUND_FORWARDER_REF_ENTRY32 * boundEntry.numberOfModuleForwarderRefs.value)
            else:
                readDataInstance.offset = prevOffset
            
            ibd.append(boundEntry)
            entryData = readDataInstance.read(consts.SIZEOF_IMAGE_BOUND_IMPORT_ENTRY32)
            
        return ibd

# typedef struct IMAGE_BOUND_IMPORT_DESCRIPTOR
# {
#    DWORD   TimeDateStamp;
#    WORD    OffsetModuleName;
#    WORD    NumberOfModuleForwarderRefs;
# }
class ImageBoundImportDescriptorEntry(baseclasses.BaseStructClass):
    """ImageBoundImportDescriptorEntry object."""
    def __init__(self,  shouldPack = True):
        """
        This class represents a C{IMAGE_BOUND_IMPORT_DESCRIPTOR} structure.
        @see: U{http://msdn.microsoft.com/en-us/magazine/cc301808.aspx}
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self,  shouldPack)
        
        self.timeDateStamp = datatypes.DWORD(0) #: L{DWORD} timeDateStamp.
        self.offsetModuleName = datatypes.WORD(0) #: L{WORD} offsetModuleName.
        self.numberOfModuleForwarderRefs = datatypes.WORD(0)#: L{WORD} numberOfModuleForwarderRefs.
        self.forwarderRefsList = ImageBoundForwarderRef() #: L{ImageBoundForwarderRef} forwarderRefsList.
        self.moduleName = datatypes.String(shouldPack = False) #: moduleName is metadata, not part of the structure.
        
        self._attrsList = ["timeDateStamp",  "offsetModuleName",  "numberOfModuleForwarderRefs",  "forwarderRefsList",  "moduleName"]
    
    def getType(self):
        """Returns L{consts.IMAGE_BOUND_IMPORT_DESCRIPTOR_ENTRY}"""
        return consts.IMAGE_BOUND_IMPORT_DESCRIPTOR_ENTRY
     
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{ImageBoundImportDescriptorEntry} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object containing data to create a new L{ImageBoundImportDescriptorEntry}.
        
        @rtype: L{ImageBoundImportDescriptorEntry}
        @return: A new {ImageBoundImportDescriptorEntry} object.
        """
        boundEntry = ImageBoundImportDescriptorEntry()
        boundEntry.timeDateStamp.value = readDataInstance.readDword()
        boundEntry.offsetModuleName.value = readDataInstance.readWord()
        boundEntry.numberOfModuleForwarderRefs.value = readDataInstance.readWord()
        
        numberOfForwarderRefsEntries = boundEntry.numberOfModuleForwarderRefs .value
        if numberOfForwarderRefsEntries:
            bytesToRead = numberOfForwarderRefsEntries * ImageBoundForwarderRefEntry().sizeof()
            rd = utils.ReadData(readDataInstance.read(bytesToRead))
            boundEntry.forwarderRefsList = ImageBoundForwarderRef.parse(rd,  numberOfForwarderRefsEntries)
            
        return boundEntry
        
class TLSDirectory(baseclasses.BaseStructClass):
    """TLS directory object."""
    def __init__(self, shouldPack = True):
        """
        Class representation of a C{IMAGE_TLS_DIRECTORY} structure.
        
        @see: Figure 11 U{http://msdn.microsoft.com/en-us/magazine/bb985996.aspx}

        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self, shouldPack)
        
        self.startAddressOfRawData = datatypes.DWORD(0) #: L{DWORD} startAddressOfRawData.
        self.endAddressOfRawData = datatypes.DWORD(0) #: L{DWORD} endAddressOfRawData.
        self.addressOfIndex = datatypes.DWORD(0) #: L{DWORD} addressOfIndex.
        self.addressOfCallbacks = datatypes.DWORD(0) #: L{DWORD} addressOfCallbacks.
        self.sizeOfZeroFill = datatypes.DWORD(0) #: L{DWORD} sizeOfZeroFill.
        self.characteristics = datatypes.DWORD(0) #:L{DWORD} characteristics.
        
        self._attrsList = ["startAddressOfRawData", "endAddressOfRawData", "addressOfIndex", "addressOfCallbacks",\
                           "sizeOfZeroFill", "characteristics"]

    def getType(self):
        """Returns L{consts.TLS_DIRECTORY}."""
        return consts.TLS_DIRECTORY32
    
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{TLSDirectory} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object containing data to create a new L{TLSDirectory} object.
        
        @rtype: L{TLSDirectory}
        @return: A new {TLSDirectory} object.
        """
        tlsDir = TLSDirectory()
        
        tlsDir.startAddressOfRawData.value = readDataInstance.readDword()
        tlsDir.endAddressOfRawData.value = readDataInstance.readDword()
        tlsDir.addressOfIndex.value = readDataInstance.readDword()
        tlsDir.addressOfCallbacks.value = readDataInstance.readDword()
        tlsDir.sizeOfZeroFill.value = readDataInstance.readDword()
        tlsDir.characteristics.value = readDataInstance.readDword()
        return tlsDir

class TLSDirectory64(baseclasses.BaseStructClass):
    """TLSDirectory64 object."""
    def __init__(self,  shouldPack = True):
        """
        Class representation of a C{IMAGE_TLS_DIRECTORY} structure in 64 bits systems.

        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self, shouldPack)
        
        self.startAddressOfRawData = datatypes.QWORD(0) #: L{QWORD} startAddressOfRawData.
        self.endAddressOfRawData = datatypes.QWORD(0) #: L{QWORD} endAddressOfRawData.
        self.addressOfIndex = datatypes.QWORD(0) #: L{QWORD} addressOfIndex.
        self.addressOfCallbacks = datatypes.QWORD(0) #: L{QWORD} addressOfCallbacks.
        self.sizeOfZeroFill = datatypes.DWORD(0) #: L{DWORD} sizeOfZeroFill.
        self.characteristics = datatypes.DWORD(0) #: L{DWORD} characteristics.
        
        self._attrsList = ["startAddressOfRawData", "endAddressOfRawData", "addressOfIndex", "addressOfCallbacks",\
                           "sizeOfZeroFill", "characteristics"]

    def getType(self):
        """Returns L{consts.TLS_DIRECTORY64}."""
        return consts.TLS_DIRECTORY64
    
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{TLSDirectory64} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object containing data to create a new L{TLSDirectory64} object.
        
        @rtype: L{TLSDirectory64}
        @return: A new L{TLSDirectory64} object.
        """
        tlsDir = TLSDirectory64()
        
        tlsDir.startAddressOfRawData.value = readDataInstance.readQword()
        tlsDir.endAddressOfRawData.value = readDataInstance.readQword()
        tlsDir.addressOfIndex.value = readDataInstance.readQword()
        tlsDir.addressOfCallbacks.value = readDataInstance.readQword()
        tlsDir.sizeOfZeroFill.value = readDataInstance.readDword()
        tlsDir.characteristics.value = readDataInstance.readDword()
        return tlsDir

# http://msdn.microsoft.com/en-us/library/windows/desktop/ms680328%28v=vs.85%29.aspx
class ImageLoadConfigDirectory(baseclasses.BaseStructClass):
    "IMAGE_LOAD_CONFIG_DIRECTORY32 object aka CONFIGURATION_DIRECTORY"
    def __init__(self, shouldPack = True):
        """
        Class representation of a C{IMAGE_LOAD_CONFIG_DIRECTORY32} structure.

        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self, shouldPack)

        self.size = datatypes.DWORD()
        self.timeDateStamp = datatypes.DWORD()
        self.majorVersion = datatypes.WORD()
        self.minorVersion = datatypes.WORD()
        self.globalFlagsClear = datatypes.DWORD()
        self.globalFlagsSet = datatypes.DWORD()
        self.criticalSectionDefaultTimeout = datatypes.DWORD()
        self.deCommitFreeBlockThreshold = datatypes.DWORD()
        self.deCommitTotalFreeThreshold = datatypes.DWORD()
        self.lockPrefixTable = datatypes.DWORD() # VA
        self.maximumAllocationSize = datatypes.DWORD()
        self.virtualMemoryThreshold = datatypes.DWORD()
        self.processHeapFlags = datatypes.DWORD()
        self.processAffinityMask = datatypes.DWORD()
        self.csdVersion = datatypes.WORD()
        self.reserved1 = datatypes.WORD()
        self.editList = datatypes.DWORD() # VA
        self.securityCookie = datatypes.DWORD() # VA
        self.SEHandlerTable = datatypes.DWORD() # VA
        self.SEHandlerCount = datatypes.DWORD()

        # Fields for Control Flow Guard
        self.GuardCFCheckFunctionPointer = datatypes.DWORD() # VA
        self.Reserved2 = datatypes.DWORD()
        self.GuardCFFunctionTable = datatypes.DWORD() # VA
        self.GuardCFFunctionCount = datatypes.DWORD()
        self.GuardFlags = datatypes.DWORD()

        self._attrsList = ["size", "timeDateStamp", "majorVersion", "minorVersion", "globalFlagsClear", "globalFlagsSet", "criticalSectionDefaultTimeout", "deCommitFreeBlockThreshold",\
                            "deCommitTotalFreeThreshold", "lockPrefixTable", "maximumAllocationSize", "virtualMemoryThreshold", "processHeapFlags", "processAffinityMask", "csdVersion",\
                            "reserved1", "editList", "securityCookie", "SEHandlerTable","SEHandlerCount", "GuardCFCheckFunctionPointer", "Reserved2", "GuardCFFunctionTable",\
                            "GuardCFFunctionCount", "GuardFlags"]

    def getType(self):
        """Returns L{consts.IMAGE_LOAD_CONFIG_DIRECTORY32}."""
        return consts.IMAGE_LOAD_CONFIG_DIRECTORY32

    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{ImageLoadConfigDirectory} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object containing data to create a new L{ImageLoadConfigDirectory} object.
        
        @rtype: L{ImageLoadConfigDirectory}
        @return: A new L{ImageLoadConfigDirectory} object.
        """
        configDir = ImageLoadConfigDirectory()

        configDir.size.value = readDataInstance.readDword()
        configDir.timeDateStamp.value = readDataInstance.readDword()
        configDir.majorVersion.value = readDataInstance.readWord()
        configDir.minorVersion.value = readDataInstance.readWord()
        configDir.globalFlagsClear.value = readDataInstance.readDword()
        configDir.globalFlagsSet.value = readDataInstance.readDword()
        configDir.criticalSectionDefaultTimeout.value = readDataInstance.readDword()
        configDir.deCommitFreeBlockThreshold.value = readDataInstance.readDword()
        configDir.deCommitTotalFreeThreshold.value = readDataInstance.readDword()
        configDir.lockPrefixTable.value = readDataInstance.readDword() # VA
        configDir.maximumAllocationSize.value = readDataInstance.readDword()
        configDir.virtualMemoryThreshold.value = readDataInstance.readDword()
        configDir.processHeapFlags.value = readDataInstance.readDword()
        configDir.processAffinityMask.value = readDataInstance.readDword()
        configDir.csdVersion.value = readDataInstance.readWord()
        configDir.reserved1.value = readDataInstance.readWord()
        configDir.editList.value = readDataInstance.readDword() # VA
        configDir.securityCookie.value = readDataInstance.readDword() # VA
        configDir.SEHandlerTable.value = readDataInstance.readDword() # VA
        configDir.SEHandlerCount.value = readDataInstance.readDword()

        # Fields for Control Flow Guard
        configDir.GuardCFCheckFunctionPointer.value = readDataInstance.readDword() # VA
        configDir.Reserved2.value = readDataInstance.readDword()
        configDir.GuardCFFunctionTable.value = readDataInstance.readDword() # VA
        configDir.GuardCFFunctionCount.value = readDataInstance.readDword()
        configDir.GuardFlags.value = readDataInstance.readDword()
        return configDir

class ImageLoadConfigDirectory64(baseclasses.BaseStructClass):
    "IMAGE_LOAD_CONFIG_DIRECTORY64 object"
    def __init__(self, shouldPack = True):
        """
        Class representation of a C{IMAGE_LOAD_CONFIG_DIRECTORY64} structure in 64 bits systems.

        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self, shouldPack)

        self.size = datatypes.DWORD()
        self.timeDateStamp = datatypes.DWORD()
        self.majorVersion = datatypes.WORD()
        self.minorVersion = datatypes.WORD()
        self.globalFlagsClear = datatypes.DWORD()
        self.globalFlagsSet = datatypes.DWORD()
        self.criticalSectionDefaultTimeout = datatypes.DWORD()
        self.deCommitFreeBlockThreshold = datatypes.QWORD()
        self.deCommitTotalFreeThreshold = datatypes.QWORD()
        self.lockPrefixTable = datatypes.QWORD()
        self.maximumAllocationSize = datatypes.QWORD()
        self.virtualMemoryThreshold = datatypes.QWORD()
        self.processAffinityMask = datatypes.QWORD()
        self.processHeapFlags = datatypes.DWORD()
        self.cdsVersion = datatypes.WORD()
        self.reserved1 = datatypes.WORD()
        self.editList = datatypes.QWORD()
        self.securityCookie = datatypes.QWORD()
        self.SEHandlerTable = datatypes.QWORD()
        self.SEHandlerCount = datatypes.QWORD()

        # Fields for Control Flow Guard
        self.GuardCFCheckFunctionPointer = datatypes.QWORD() # VA
        self.Reserved2 = datatypes.QWORD()
        self.GuardCFFunctionTable = datatypes.QWORD() # VA
        self.GuardCFFunctionCount = datatypes.QWORD()
        self.GuardFlags = datatypes.QWORD()

        self._attrsList = ["size", "timeDateStamp", "majorVersion", "minorVersion", "globalFlagsClear", "globalFlagsSet", "criticalSectionDefaultTimeout", "deCommitFreeBlockThreshold",\
                            "deCommitTotalFreeThreshold", "lockPrefixTable", "maximumAllocationSize", "virtualMemoryThreshold", "processAffinityMask", "processHeapFlags", "cdsVersion",\
                            "reserved1", "editList", "securityCookie", "SEHandlerTable", "SEHandlerCount", "GuardCFCheckFunctionPointer", "Reserved2", "GuardCFFunctionTable",\
                            "GuardCFFunctionCount", "GuardFlags"]


    def getType(self):
        """Returns L{consts.IMAGE_LOAD_CONFIG_DIRECTORY64}."""
        return consts.IMAGE_LOAD_CONFIG_DIRECTORY64

    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{ImageLoadConfigDirectory64} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object containing data to create a new L{ImageLoadConfigDirectory64} object.
        
        @rtype: L{ImageLoadConfigDirectory64}
        @return: A new L{ImageLoadConfigDirectory64} object.
        """
        configDir = ImageLoadConfigDirectory64()

        configDir.size.value = readDataInstance.readDword()
        configDir.timeDateStamp.value = readDataInstance.readDword()
        configDir.majorVersion.value = readDataInstance.readWord()
        configDir.minorVersion.value = readDataInstance.readWord()
        configDir.globalFlagsClear.value = readDataInstance.readDword()
        configDir.globalFlagsSet.value = readDataInstance.readDword()
        configDir.criticalSectionDefaultTimeout.value = readDataInstance.readDword()
        configDir.deCommitFreeBlockThreshold.value = readDataInstance.readQword()
        configDir.deCommitTotalFreeThreshold.value = readDataInstance.readQword()
        configDir.lockPrefixTable.value = readDataInstance.readQword()
        configDir.maximumAllocationSize.value = readDataInstance.readQword()
        configDir.virtualMemoryThreshold.value = readDataInstance.readQword()
        configDir.processAffinityMask.value = readDataInstance.readQword()
        configDir.processHeapFlags.value = readDataInstance.readDword()
        configDir.cdsVersion.value = readDataInstance.readWord()
        configDir.reserved1.value = readDataInstance.readWord()
        configDir.editList.value = readDataInstance.readQword()
        configDir.securityCookie.value = readDataInstance.readQword()
        configDir.SEHandlerTable.value = readDataInstance.readQword()
        configDir.SEHandlerCount.value = readDataInstance.readQword()

        # Fields for Control Flow Guard
        configDir.GuardCFCheckFunctionPointer.value = readDataInstance.readQword() # VA
        configDir.Reserved2.value = readDataInstance.readQword()
        configDir.GuardCFFunctionTable.value = readDataInstance.readQword() # VA
        configDir.GuardCFFunctionCount.value = readDataInstance.readQword()
        configDir.GuardFlags.value = readDataInstance.readQword()
        return configDir

class ImageBaseRelocationEntry(baseclasses.BaseStructClass):
    """ImageBaseRelocationEntry object."""
    def __init__(self,  shouldPack = True):
        """
        A class representation of a C{IMAGE_BASE_RELOCATION} structure.
        @see: U{http://msdn.microsoft.com/en-us/magazine/cc301808.aspx}
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self,  shouldPack)
        
        self.virtualAddress = datatypes.DWORD(0) #: L{DWORD} virtualAddress.
        self.sizeOfBlock = datatypes.DWORD(0) #: L{DWORD} sizeOfBlock
        self.items = datatypes.Array(datatypes.TYPE_WORD) #: L{Array} items.
        
        self._attrsList = ["virtualAddress", "sizeOfBlock", "items"]
    
    def getType(self):
        """Returns L{consts.IMAGE_BASE_RELOCATION_ENTRY}."""
        return consts.IMAGE_BASE_RELOCATION_ENTRY
    
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{ImageBaseRelocationEntry} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to parse as a L{ImageBaseRelocationEntry} object.
        
        @rtype: L{ImageBaseRelocationEntry}
        @return: A new L{ImageBaseRelocationEntry} object.
        """
        reloc = ImageBaseRelocationEntry()
        reloc.virtualAddress.value = readDataInstance.readDword()
        reloc.sizeOfBlock.value = readDataInstance.readDword()
        toRead = (reloc.sizeOfBlock.value - 8) / len(datatypes.WORD(0))
        reloc.items = datatypes.Array.parse(readDataInstance,  datatypes.TYPE_WORD,  toRead)
        return reloc
        
class ImageBaseRelocation(list):
    """ImageBaseRelocation array."""
    pass
    
class ImageDebugDirectory(baseclasses.BaseStructClass):
    """ImageDebugDirectory object."""
    def __init__(self,  shouldPack = True):
        """
        Class representation of a C{IMAGE_DEBUG_DIRECTORY} structure.
        @see: U{http://msdn.microsoft.com/es-es/library/windows/desktop/ms680307%28v=vs.85%29.aspx}
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self,  shouldPack)
        
        self.characteristics = datatypes.DWORD(0) #: L{DWORD} characteristics.
        self.timeDateStamp = datatypes.DWORD(0) #: L{DWORD} timeDateStamp.
        self.majorVersion = datatypes.WORD(0) #: L{WORD} majorVersion.
        self.minorVersion = datatypes.WORD(0) #: L{WORD} minorVersion.
        self.type = datatypes.DWORD(0) #: L{DWORD} type.
        self.sizeOfData = datatypes.DWORD(0) #: L{DWORD} sizeOfData.
        self.addressOfData = datatypes.DWORD(0) #: L{DWORD} addressOfData.
        self.pointerToRawData = datatypes.DWORD(0) #: L{DWORD} pointerToRawData.
        
        self._attrsList = ["characteristics",  "timeDateStamp",  "majorVersion",  "minorVersion",  "type",  "sizeOfData",\
                           "addressOfData",  "pointerToRawData"]
    
    def getType(self):
        """Returns L{consts.IMAGE_DEBUG_DIRECTORY}."""
        return consts.IMAGE_DEBUG_DIRECTORY
    
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{ImageDebugDirectory} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A new L{ReadData} object with data to be parsed as a L{ImageDebugDirectory} object.
        
        @rtype: L{ImageDebugDirectory}
        @return: A new L{ImageDebugDirectory} object.
        """
        dbgDir = ImageDebugDirectory()

        dbgDir.characteristics.value = readDataInstance.readDword()
        dbgDir.timeDateStamp.value = readDataInstance.readDword()
        dbgDir.majorVersion.value = readDataInstance.readWord()
        dbgDir.minorVersion.value = readDataInstance.readWord()
        dbgDir.type.value = readDataInstance.readDword()
        dbgDir.sizeOfData.value = readDataInstance.readDword()
        dbgDir.addressOfData.value = readDataInstance.readDword()
        dbgDir.pointerToRawData.value = readDataInstance.readDword()
        
        return dbgDir

class ImageDebugDirectories(list):
    """ImageDebugDirectories object."""
    def __init__(self,  shouldPack = True):
        """
        Array of L{ImageDebugDirectory} objects.
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        self.shouldPack = shouldPack
        
    def __str__(self):
        return ''.join([str(x) for x in self if self.shouldPack])
    
    def getType(self):
        """"Returns L{consts.IMAGE_DEBUG_DIRECTORIES}."""
        return consts.IMAGE_DEBUG_DIRECTORIES
        
    @staticmethod
    def parse(readDataInstance,  nDebugEntries):
        """
        Returns a new L{ImageDebugDirectories} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{ImageDebugDirectories} object.
        
        @type nDebugEntries: int
        @param nDebugEntries: Number of L{ImageDebugDirectory} objects in the C{readDataInstance} object.
        
        @rtype: L{ImageDebugDirectories}
        @return: A new L{ImageDebugDirectories} object.
        
        @raise DataLengthException: If not enough data to read in the C{readDataInstance} object.
        """
        dbgEntries = ImageDebugDirectories()
        
        dataLength = len(readDataInstance)
        toRead = nDebugEntries * consts.SIZEOF_IMAGE_DEBUG_ENTRY32
        if dataLength >= toRead:
            for i in range(nDebugEntries):
                dbgEntry = ImageDebugDirectory.parse(readDataInstance)
                dbgEntries.append(dbgEntry)
        else:
            raise excep.DataLengthException("Not enough bytes to read.")
        
        return dbgEntries
        
class ImageImportDescriptorMetaData(baseclasses.BaseStructClass):
    """ImageImportDescriptorMetaData object."""
    def __init__(self,  shouldPack = True):
        """
        Class used to store metadata from the L{ImageImportDescriptor} object.

        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self, shouldPack)
        
        self.moduleName = datatypes.String("") #: L{String} moduleName.
        self.numberOfImports = datatypes.DWORD(0) #: L{DWORD} numberOfImports.
        
        self._attrsList = ["moduleName", "numberOfImports"]
    
    def getType(self):
        """Returns L{consts.IID_METADATA}."""
        return consts.IID_METADATA
        
class ImageImportDescriptorEntry(baseclasses.BaseStructClass):
    """ImageImportDescriptorEntry object."""
    def __init__(self, shouldPack = True):
        """
        Class representation of a C{IMAGE_IMPORT_DESCRIPTOR} structure.
        @see: Figure 5 U{http://msdn.microsoft.com/es-ar/magazine/bb985996%28en-us%29.aspx}
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self, shouldPack)
        
        self.metaData = ImageImportDescriptorMetaData() #: L{ImageImportDescriptorMetaData} metaData.
        
        self.originalFirstThunk = datatypes.DWORD(0) #: L{DWORD} originalFirstThunk.
        self.timeDateStamp = datatypes.DWORD(0) #: L{DWORD} timeDateStamp.
        self.forwarderChain = datatypes.DWORD(0) #: L{DWORD} forwarderChain.
        self.name = datatypes.DWORD(0) #: L{DWORD} name.
        self.firstThunk = datatypes.DWORD(0) #: L{DWORD} firstThunk.
        
        self.iat = ImportAddressTable() #: L{ImportAddressTable} iat.
        
        self._attrsList = ["originalFirstThunk", "timeDateStamp",  "forwarderChain",  "name",  "firstThunk"]
        
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{ImageImportDescriptorEntry} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{ImageImportDescriptorEntry}.
        
        @rtype: L{ImageImportDescriptorEntry}
        @return: A new L{ImageImportDescriptorEntry} object.
        """
        iid = ImageImportDescriptorEntry()
        iid.originalFirstThunk.value = readDataInstance.readDword()
        iid.timeDateStamp.value = readDataInstance.readDword()
        iid.forwarderChain.value = readDataInstance.readDword()
        iid.name.value = readDataInstance.readDword()
        iid.firstThunk.value = readDataInstance.readDword()
        return iid

    def getType(self):
        """Returns C{consts.IMAGE_IMPORT_DESCRIPTOR_ENTRY}."""
        return consts.IMAGE_IMPORT_DESCRIPTOR_ENTRY

class ImageImportDescriptor(list):
    """ImageImportDescriptor object."""
    def __init__(self, shouldPack = True):
        """
        Array of L{ImageImportDescriptorEntry} objects.
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.        
        """
        self.shouldPack = shouldPack
        
    def __str__(self):
        return ''.join([str(x) for x in self if x.shouldPack])
    
    def getType(self):
        """Returns L{consts.IMAGE_IMPORT_DESCRIPTOR}."""
        return consts.IMAGE_IMPORT_DESCRIPTOR
    
    @staticmethod
    def parse(readDataInstance,  nEntries):
        """
        Returns a new L{ImageImportDescriptor} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{ImageImportDescriptor} object.
        
        @type nEntries: int
        @param nEntries: The number of L{ImageImportDescriptorEntry} objects in the C{readDataInstance} object.
        
        @rtype: L{ImageImportDescriptor}
        @return: A new L{ImageImportDescriptor} object.
        
        @raise DataLengthException: If not enough data to read.
        """
        importEntries = ImageImportDescriptor()
        
        dataLength = len(readDataInstance)
        toRead = nEntries * consts.SIZEOF_IMAGE_IMPORT_ENTRY32
        if dataLength >= toRead:
            for i in range(nEntries):
                importEntry = ImageImportDescriptorEntry.parse(readDataInstance)
                importEntries.append(importEntry)
        else:
            raise excep.DataLengthException("Not enough bytes to read.")
            
        return importEntries

class ImportAddressTableEntry(baseclasses.BaseStructClass):
    """ImportAddressTableEntry object."""
    def __init__(self,  shouldPack = True):
        """
        A class representation of a C{} structure.

        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.        
        """
        baseclasses.BaseStructClass.__init__(self, shouldPack)
        
        self.firstThunk = datatypes.DWORD(0) #: L{DWORD} firstThunk.
        self.originalFirstThunk = datatypes.DWORD(0) #: L{DWORD} originalFirstThunk.
        self.hint = datatypes.WORD(0) #: L{WORD} hint.
        self.name = datatypes.String("") #: L{String} name.
        
        self._attrsList = ["firstThunk",  "originalFirstThunk",  "hint",  "name"]
        
    def getType(self):
        """Returns L{consts.IMPORT_ADDRESS_TABLE_ENTRY}."""
        return consts.IMPORT_ADDRESS_TABLE_ENTRY

class ImportAddressTableEntry64(baseclasses.BaseStructClass):
    """ImportAddressTableEntry64 object."""
    def __init__(self,  shouldPack = True):
        """
        A class representation of a C{} structure.

        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.        
        """
        baseclasses.BaseStructClass.__init__(self, shouldPack)
        
        self.firstThunk = datatypes.QWORD(0) #: L{QWORD} firstThunk.
        self.originalFirstThunk = datatypes.QWORD(0) #: L{QWORD} originalFirstThunk.
        self.hint = datatypes.WORD(0) #: L{WORD} hint.
        self.name = datatypes.String("") #: L{String} name.
        
        self._attrsList = ["firstThunk",  "originalFirstThunk",  "hint",  "name"]
        
    def getType(self):
        """Returns L{consts.IMPORT_ADDRESS_TABLE_ENTRY64}."""
        return consts.IMPORT_ADDRESS_TABLE_ENTRY64

class ImportAddressTable(list):
    """Array of L{ImportAddressTableEntry} objects."""
    pass

class ExportTable(list):
    """Array of L{ExportTableEntry} objects."""
    pass
    
class ExportTableEntry(baseclasses.BaseStructClass):
    """ExportTableEntry object."""
    def __init__(self,  shouldPack = True):
        """
        A class representation of a C{} structure.
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.        
        """
        baseclasses.BaseStructClass.__init__(self,  shouldPack)
        
        self.ordinal = datatypes.DWORD(0) #: L{DWORD} ordinal.
        self.functionRva = datatypes.DWORD(0) #: L{DWORD} functionRva.
        self.nameOrdinal = datatypes.WORD(0) #: L{WORD} nameOrdinal.
        self.nameRva = datatypes.DWORD(0) #: L{DWORD} nameRva.
        self.name = datatypes.String("") #: L{String} name.
        
        self._attrsList = ["ordinal", "functionRva",  "nameOrdinal",  "nameRva",  "name"]
    
    def __repr__(self):
        return repr((self.ordinal,  self.functionRva,  self.nameOrdinal,  self.nameRva,  self.name))
        
    def getType(self):
        """Returns L{consts.EXPORT_TABLE_ENTRY}."""
        return consts.EXPORT_TABLE_ENTRY
    
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{ExportTableEntry} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{ExportTableEntry} object.
        
        @rtype: L{ExportTableEntry}
        @return: A new L{ExportTableEntry} object.
        """
        exportEntry = ExportTableEntry()

        exportEntry.functionRva.value = readDataInstance.readDword()
        exportEntry.nameOrdinal.value = readDataInstance.readWord()
        exportEntry.nameRva.value = readDataInstance.readDword()
        exportEntry.name.value = readDataInstance.readString()
        return exportEntry
        
class ImageExportTable(baseclasses.BaseStructClass):
    """ImageExportTable object."""
    def __init__(self,  shouldPack = True):
        """
        Class representation of a C{IMAGE_EXPORT_DIRECTORY} structure.
        @see: Figure 2 U{http://msdn.microsoft.com/en-us/magazine/bb985996.aspx}
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.                
        """
        baseclasses.BaseStructClass.__init__(self,  shouldPack)
        
        self.exportTable = ExportTable()
        
        self.characteristics = datatypes.DWORD(0) #: L{DWORD} characteristics.
        self.timeDateStamp = datatypes.DWORD(0) #: L{DWORD} timeDateStamp.
        self.majorVersion = datatypes.WORD(0) #: L{WORD} majorVersion.
        self.minorVersion = datatypes.WORD(0) #: L{WORD} minorVersion.
        self.name = datatypes.DWORD(0) #: L{DWORD} name.
        self.base = datatypes.DWORD(0) #: L{DWORD} base.
        self.numberOfFunctions = datatypes.DWORD(0) #: L{DWORD} numberOfFunctions.
        self.numberOfNames = datatypes.DWORD(0) #: L{DWORD} numberOfNames.
        self.addressOfFunctions = datatypes.DWORD(0) #: L{DWORD} addressOfFunctions.
        self.addressOfNames = datatypes.DWORD(0) #: L{DWORD} addressOfNames.
        self.addressOfNameOrdinals = datatypes.DWORD(0) #: L{DWORD} addressOfNamesOrdinals.
        
        self._attrsList = ["characteristics",  "timeDateStamp",  "majorVersion",  "minorVersion", "name",  "base",  "numberOfFunctions",\
                           "numberOfNames",  "addressOfFunctions",  "addressOfNames",  "addressOfNameOrdinals"]

    def getType(self):
        """Returns L{consts.EXPORT_DIRECTORY}."""
        return consts.EXPORT_DIRECTORY
    
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{ImageExportTable} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{ImageExportTable} object.
        
        @rtype: L{ImageExportTable}
        @return: A new L{ImageExportTable} object.
        """
        et = ImageExportTable()
        
        et.characteristics.value = readDataInstance.readDword()
        et.timeDateStamp.value = readDataInstance.readDword()
        et.majorVersion.value = readDataInstance.readWord()
        et.minorVersion.value = readDataInstance.readWord()
        et.name.value = readDataInstance.readDword()
        et.base.value = readDataInstance.readDword()
        et.numberOfFunctions.value = readDataInstance.readDword()
        et.numberOfNames.value = readDataInstance.readDword()
        et.addressOfFunctions.value = readDataInstance.readDword()
        et.addressOfNames.value = readDataInstance.readDword()
        et.addressOfNameOrdinals.value = readDataInstance.readDword()
        return et
        
class NETDirectory(baseclasses.BaseStructClass):
    """NETDirectory object."""
    def __init__(self,  shouldPack = True):
        """
        A class to abstract data from the .NET PE format.
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.                
        """
        baseclasses.BaseStructClass.__init__(self, shouldPack)
        
        self.directory = NetDirectory() #: L{NetDirectory} directory.
        self.netMetaDataHeader = NetMetaDataHeader() #: L{NetMetaDataHeader} netMetaDataHeader.
        self.netMetaDataStreams = NetMetaDataStreams() #: L{NetMetaDataStreams} netMetaDataStreams.
    
        self._attrsList = ["directory",  "netMetaDataHeader",  "netMetaDataStreams"]
        
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{NETDirectory} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{NETDirectory} object.
        
        @rtype: L{NETDirectory}
        @return: A new L{NETDirectory} object.
        """
        nd = NETDirectory()
        
        nd.directory = NetDirectory.parse(readDataInstance)
        nd.netMetaDataHeader = NetMetaDataHeader.parse(readDataInstance)
        nd.netMetaDataStreams = NetMetaDataStreams.parse(readDataInstance)
        return nd
        
    def getType(self):
        """Returns L{consts.NET_DIRECTORY}."""
        return consts.NET_DIRECTORY
        
class NetDirectory(baseclasses.BaseStructClass):
    """NetDirectory object."""
    def __init__(self,  shouldPack = True):
        """
        A class representation of the C{IMAGE_COR20_HEADER} structure.
        @see: U{http://www.ntcore.com/files/dotnetformat.htm}

        @type shouldPack: bool
        @param shouldPack: (Optional) If set to c{True}, the object will be packed. If set to C{False}, the object won't be packed.                
        """
        baseclasses.BaseStructClass.__init__(self,  shouldPack)
        
        self.cb = datatypes.DWORD(0) #: L{DWORD} cb.
        self.majorRuntimeVersion = datatypes.WORD(0) #: L{WORD} majorRuntimeVersion.
        self.minorRuntimeVersion = datatypes.WORD(0) #: L{WORD} minorRuntimeVersion.
        self.metaData = datadirs.Directory() #: L{Directory} metaData.
        self.flags = datatypes.DWORD(0) #: L{DWORD} flags.
        self.entryPointToken = datatypes.DWORD(0) #: L{DWORD} entryPointToken.
        self.resources = datadirs.Directory() #: L{Directory} resources.
        self.strongNameSignature = datadirs.Directory() #: L{Directory} strongNameSignature.
        self.codeManagerTable = datadirs.Directory() #: L{Directory} codeManagerTable.
        self.vTableFixups = datadirs.Directory() #: L{Directory} vTableFixups.
        self.exportAddressTableJumps = datadirs.Directory() #: L{Directory} exportAddressTableJumps.
        self.managedNativeHeader = datadirs.Directory() #: L{Directory} managedNativeHeader.
        
        self._attrsList = ["cb","majorRuntimeVersion","minorRuntimeVersion","metaData", \
        "flags","entryPointToken","resources","strongNameSignature",\
        "codeManagerTable","vTableFixups", "exportAddressTableJumps",\
        "managedNativeHeader"]
        
    def getType(self):
        """Returns L{consts.IMAGE_COR20_HEADER}."""
        return consts.IMAGE_COR20_HEADER
    
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{NetDirectory} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{NetDirectory} object.
        
        @rtype: L{NetDirectory}
        @return: A new L{NetDirectory} object.
        """
        nd = NetDirectory()
        
        nd.cb.value = readDataInstance.readDword()
        nd.majorRuntimeVersion.value= readDataInstance.readWord()
        nd.minorRuntimeVersion.value = readDataInstance.readWord()
        
        nd.metaData.rva.value = readDataInstance.readDword()
        nd.metaData.size.value = readDataInstance.readDword()
        nd.metaData.name.value = "MetaData"
        
        nd.flags.value = readDataInstance.readDword()
        nd.entryPointToken.value = readDataInstance.readDword()
        
        nd.resources.rva.value = readDataInstance.readDword()
        nd.resources.size.value = readDataInstance.readDword()
        nd.resources.name.value = "Resources"
        
        nd.strongNameSignature.rva.value = readDataInstance.readDword()
        nd.strongNameSignature.size.value = readDataInstance.readDword()
        nd.strongNameSignature.name.value = "StrongNameSignature"
        
        nd.codeManagerTable.rva.value = readDataInstance.readDword()
        nd.codeManagerTable.size.value = readDataInstance.readDword()
        nd.codeManagerTable.name.value = "CodeManagerTable"
        
        nd.vTableFixups.rva.value = readDataInstance.readDword()
        nd.vTableFixups.size.value = readDataInstance.readDword()
        nd.vTableFixups.name.value = "VTableFixups"
        
        nd.exportAddressTableJumps.rva.value = readDataInstance.readDword()
        nd.exportAddressTableJumps.size.value = readDataInstance.readDword()
        nd.exportAddressTableJumps.name.value = "ExportAddressTableJumps"
        
        nd.managedNativeHeader.rva.value = readDataInstance.readDword()
        nd.managedNativeHeader.size.value = readDataInstance.readDword()
        nd.managedNativeHeader.name.value = "ManagedNativeHeader"
        
        return nd
        
class NetMetaDataHeader(baseclasses.BaseStructClass):
    """NetMetaDataHeader object."""
    def __init__(self,  shouldPack = True):
        baseclasses.BaseStructClass.__init__(self,  shouldPack)
        
        self.signature = datatypes.DWORD(0) #: L{DWORD} signature.
        self.majorVersion = datatypes.WORD(0) #: L{WORD} majorVersion.
        self.minorVersion = datatypes.WORD(0) #: L{WORD} minorVersion.
        self.reserved = datatypes.DWORD(0) #: L{DWORD} reserved.
        self.versionLength = datatypes.DWORD(0) #: L{DWORD} versionLength.
        self.versionString = datatypes.AlignedString("") #: L{AlignedString} versionString.
        self.flags = datatypes.WORD(0) #: L{WORD} flags.
        self.numberOfStreams = datatypes.WORD(0) #: L{WORD} numberOfStreams.
        
        self._attrsList = ["signature","majorVersion","minorVersion","reserved","versionLength","versionString","flags","numberOfStreams"]
        
    def getType(self):
        """Returns L{consts.NET_METADATA_HEADER}."""
        return consts.NET_METADATA_HEADER

    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{NetMetaDataHeader} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{NetMetaDataHeader} object.
        
        @rtype: L{NetMetaDataHeader}
        @return: A new L{NetMetaDataHeader} object.
        """
        nmh = NetMetaDataHeader()
        
        nmh.signature.value = readDataInstance.readDword()
        nmh.majorVersion.value = readDataInstance.readWord()
        nmh.minorVersion.value = readDataInstance.readWord()
        nmh.reserved.value = readDataInstance.readDword()
        nmh.versionLength.value = readDataInstance.readDword()
        nmh.versionString.value = readDataInstance.readAlignedString()
        nmh.flags.value = readDataInstance.readWord()
        nmh.numberOfStreams.value = readDataInstance.readWord()
        return nmh

class NetMetaDataStreamEntry(baseclasses.BaseStructClass):
    """NetMetaDataStreamEntry object."""
    def __init__(self,  shouldPack = True):
        baseclasses.BaseStructClass.__init__(self,  shouldPack)
        
        self.offset = datatypes.DWORD(0) #: L{DWORD} offset.
        self.size = datatypes.DWORD(0) #: L{DWORD} size.
        # this must be aligned to the next 4-byte boundary
        self.name = datatypes.AlignedString("") #: L{AlignedString} name.
        # the "info" attribute does not belong to the NETMetaDataStreamEntry struct. It is just a place holder where the
        # data for every entry will be stored.
        self.info = None
        
        self._attrsList = ["offset",  "size",  "name",  "info"]
        
    def getType(self):
        """Returns L{consts.NET_METADATA_STREAM_ENTRY}."""
        return consts.NET_METADATA_STREAM_ENTRY
    
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{NetMetaDataStreamEntry} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{NetMetaDataStreamEntry}.
        
        @rtype: L{NetMetaDataStreamEntry}
        @return: A new L{NetMetaDataStreamEntry} object.
        """
        n = NetMetaDataStreamEntry()
        n.offset.value = readDataInstance.readDword()
        n.size.value = readDataInstance.readDword()
        n.name.value = readDataInstance.readAlignedString()
        return n
        
class NetMetaDataStreams(dict):
    """NetMetaDataStreams object."""
    def __init__(self,  shouldPack = True):
        self.shouldPack = shouldPack

    def __str__(self):
        return "".join([str(x) for x in self if hasattr(x, "shouldPack") and x.shouldPack])

    def getByNumber(self, number):
        return self.get(name)

    def getByName(self, name):
        return self.get(name)
        
    def getType(self):
        """Returns L{consts.NET_METADATA_STREAMS}."""
        return consts.NET_METADATA_STREAMS
    
    @staticmethod
    def parse(readDataInstance,  nStreams):
        """
        Returns a new L{NetMetaDataStreams} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{NetMetaDataStreams} object.
        
        @type nStreams: int
        @param nStreams: The number of L{NetMetaDataStreamEntry} objects in the C{readDataInstance} object.
        
        @rtype: L{NetMetaDataStreams}
        @return: A new L{NetMetaDataStreams} object.
        """
        streams = NetMetaDataStreams()
        
        for i in range(nStreams):
            streamEntry = NetMetaDataStreamEntry()
            
            streamEntry.offset.value = readDataInstance.readDword()
            streamEntry.size.value = readDataInstance.readDword()
            streamEntry.name.value = readDataInstance.readAlignedString()
            
            #streams.append(streamEntry)
            streams.update({ i: streamEntry, streamEntry.name.value: streamEntry })

        return streams

class NetMetaDataTableHeader(baseclasses.BaseStructClass):
    """NetMetaDataTableHeader object."""
    def __init__(self,  shouldPack = True):
        baseclasses.BaseStructClass.__init__(self,  shouldPack)
        
        self.reserved_1 = datatypes.DWORD(0) #: L{DWORD} reserved_1.
        self.majorVersion = datatypes.BYTE(0) #: L{BYTE} majorVersion.
        self.minorVersion = datatypes.BYTE(0) #: L{BYTE} minorVersion.
        self.heapOffsetSizes = datatypes.BYTE(0) #: L{BYTE} heapOffsetSizes.
        self.reserved_2 = datatypes.BYTE(0) #: L{BYTE} reserved_2.
        self.maskValid = datatypes.QWORD(0) #: L{QWORD} maskValid.
        self.maskSorted = datatypes.QWORD(0) #: L{QWORD} maskSorted.
        
        self._attrsList = ["reserved_1",  "majorVersion",  "minorVersion",  "heapOffsetSizes",  "reserved_2",  "maskValid",  "maskSorted"]
        
    def getType(self):
        """Returns L{consts.NET_METADATA_TABLE_HEADER}."""
        return consts.NET_METADATA_TABLE_HEADER
        
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{NetMetaDataTableHeader} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{NetMetaDataTableHeader} object.
        
        @rtype: L{NetMetaDataTableHeader}
        @return: A new L{NetMetaDataTableHeader} object.
        """
        th = NetMetaDataTableHeader()
        
        th.reserved_1.value = readDataInstance.readDword()
        th.majorVersion.value = readDataInstance.readByte()
        th.minorVersion.value = readDataInstance.readByte()
        th.heapOffsetSizes.value = readDataInstance.readByte()
        th.reserved_2.value = readDataInstance.readByte()
        th.maskValid.value = readDataInstance.readQword()
        th.maskSorted.value = readDataInstance.readQword()

        return th
        
class NetMetaDataTables(baseclasses.BaseStructClass):
    """NetMetaDataTables object."""
    def __init__(self,  shouldPack = True):
        """
        NetMetaDataTables object.
        
        @todo: Parse every table in this struct and store them in the C{self.tables} attribute.
        """
        baseclasses.BaseStructClass.__init__(self,  shouldPack)
        
        self.netMetaDataTableHeader = NetMetaDataTableHeader() #: L{NetMetaDataTableHeader} netMetaDataTableHeader.
        self.tables = None #: C{str} tables.
        
        self._attrsList = ["netMetaDataTableHeader",  "tables"]
        
    def getType(self):
        """Returns L{consts.NET_METADATA_TABLES}."""
        return consts.NET_METADATA_TABLES
        
    @staticmethod
    def parse(readDataInstance, netMetaDataStreams):
        """
        Returns a new L{NetMetaDataTables} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{NetMetaDataTables} object.
        
        @rtype: L{NetMetaDataTables}
        @return: A new L{NetMetaDataTables} object.
        """
        dt = NetMetaDataTables()
        dt.netMetaDataTableHeader = NetMetaDataTableHeader.parse(readDataInstance)
        dt.tables = {}

        metadataTableDefinitions = dotnet.MetadataTableDefinitions(dt, netMetaDataStreams)

        for i in xrange(64):
            dt.tables[i] = { "rows": 0 }
            if dt.netMetaDataTableHeader.maskValid.value >> i & 1:
                dt.tables[i]["rows"] = readDataInstance.readDword()
            if i in dotnet.MetadataTableNames:
                dt.tables[dotnet.MetadataTableNames[i]] = dt.tables[i]

        for i in xrange(64):
            dt.tables[i]["data"] = []
            for j in range(dt.tables[i]["rows"]):
                row = None
                if i in metadataTableDefinitions:
                    row = readDataInstance.readFields(metadataTableDefinitions[i])
                dt.tables[i]["data"].append(row)

        for i in xrange(64):
            if i in dotnet.MetadataTableNames:
                dt.tables[dotnet.MetadataTableNames[i]] = dt.tables[i]["data"]
            dt.tables[i] = dt.tables[i]["data"]

        return dt

class NetResources(baseclasses.BaseStructClass):
    """NetResources object."""
    def __init__(self,  shouldPack = True):
        """
        NetResources object.

        @todo: Parse every resource in this struct and store them in the C{self.resources} attribute.
        """
        baseclasses.BaseStructClass.__init__(self,  shouldPack)

        self.signature = datatypes.DWORD(0)
        self.readerCount = datatypes.DWORD(0)
        self.readerTypeLength = datatypes.DWORD(0)
        self.version = datatypes.DWORD(0)
        self.resourceCount = datatypes.DWORD(0)
        self.resourceTypeCount = datatypes.DWORD(0)
        self.resourceTypes = None
        self.resourceHashes = None
        self.resourceNameOffsets = None
        self.dataSectionOffset = datatypes.DWORD(0)
        self.resourceNames = None
        self.resourceOffsets = None
        self.info = None

        self._attrsList = ["signature", "readerCount", "readerTypeLength", "version", "resourceCount", "resourceTypeCount", "resourceTypes", "resourceHashes", "resourceNameOffsets", "dataSectionOffset", "resourceNames", "resourceOffets", "info"]

    def __str__(self):
        return str(self.info)

    def __repr__(self):
        return repr(self.info)

    def getType(self):
        """Returns L{consts.NET_RESOURCES}."""
        return consts.NET_RESOURCES

    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{NetResources} object.

        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{NetResources} object.

        @rtype: L{NetResources}
        @return: A new L{NetResources} object.
        """
        r = NetResources()

        r.signature = readDataInstance.readDword()
        if r.signature != 0xbeefcace:
            return r

        r.readerCount = readDataInstance.readDword()
        r.readerTypeLength = readDataInstance.readDword()
        r.readerType = utils.ReadData(readDataInstance.read(r.readerTypeLength)).readDotNetBlob()
        r.version = readDataInstance.readDword()
        r.resourceCount = readDataInstance.readDword()
        r.resourceTypeCount = readDataInstance.readDword()

        r.resourceTypes = []
        for i in xrange(r.resourceTypeCount):
            r.resourceTypes.append(readDataInstance.readDotNetBlob())

        # aligned to 8 bytes
        readDataInstance.skipBytes(8 - readDataInstance.tell() & 0x7)

        r.resourceHashes = []
        for i in xrange(r.resourceCount):
            r.resourceHashes.append(readDataInstance.readDword())

        r.resourceNameOffsets = []
        for i in xrange(r.resourceCount):
            r.resourceNameOffsets.append(readDataInstance.readDword())

        r.dataSectionOffset = readDataInstance.readDword()

        r.resourceNames = []
        r.resourceOffsets = []
        base = readDataInstance.tell()
        for i in xrange(r.resourceCount):
            readDataInstance.setOffset(base + r.resourceNameOffsets[i])
            r.resourceNames.append(readDataInstance.readDotNetUnicodeString())
            r.resourceOffsets.append(readDataInstance.readDword())

        r.info = {}
        for i in xrange(r.resourceCount):
            readDataInstance.setOffset(r.dataSectionOffset + r.resourceOffsets[i])
            r.info[i] = readDataInstance.read(len(readDataInstance))
            r.info[r.resourceNames[i]] = r.info[i]

        return r
