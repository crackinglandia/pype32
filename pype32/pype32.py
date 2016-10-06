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
Common PE structures.

@group Main class: 
    PE

@group PE fields:
    FileHeader, DosHeader, NtHeaders, OptionalHeader, OptionalHeader64,
    SectionHeader, SectionHeaders, Sections
"""

__revision__ = "$Id$"

__all__ = [
            "PE",  
            "FileHeader", 
            "DosHeader", 
            "NtHeaders",  
            "OptionalHeader", 
            "OptionalHeader64",  
            "SectionHeader",  
            "SectionHeaders",  
            "Sections",  
           ]
           
import os
import hashlib
import binascii

import datadirs
import datatypes
import consts
import excep
import utils
import directories
import baseclasses

from struct import pack, unpack

class PE(object):
    """PE object."""
    def __init__(self, pathToFile = None, data = None, fastLoad = False, verbose = False):
        """
        A class representation of the Portable Executable format.
        @see: PE format U{http://msdn.microsoft.com/en-us/library/windows/desktop/ms680547%28v=vs.85%29.aspx}
        
        @type pathToFile: str
        @param pathToFile: Path to the file to load. 
        
        @type data: str
        @param data: PE data to process.
        
        @type fastLoad: bool
        @param fastLoad: If set to C{False}, the PE class won't parse the directory data, just headers. 
        The L{fullLoad} method is available to load the directories in case the C{fastLoad} parameter was set to C{False}. 
        If set to C{True}, the entire PE will be parsed.
        
        @type verbose: bool
        @param verbose: Verbose output.
        
        @todo: Parse the Resource directory.
        @todo: Parse the Delay Imports directory.
        @todo: Parse the Exception directory.
        @todo: Add dump() method to show nicely all the structure of the PE file.
        """
        self.dosHeader = DosHeader() #: L{DosHeader} dosHeader.
        self.dosStub = PE.getDosStub() #: C{str} dosStub.
        self.ntHeaders = NtHeaders() #: L{NtHeaders} ntHeaders.
        self.sectionHeaders = SectionHeaders() #: L{SectionHeaders} sectionHeaders.
        self.sections = Sections(self.sectionHeaders) #: L{Sections} sections.
        self.overlay = ""
        self.signature = ""

        self._data = data
        self._pathToFile = pathToFile

        self._verbose = verbose
        self._fastLoad = fastLoad
        self.PE_TYPE = None
        
        if self._data and not isinstance(data,  utils.ReadData):
            rd = utils.ReadData(data)
            self._internalParse(rd)
        elif self._pathToFile:
            if os.path.exists(self._pathToFile):
                
                stat = os.stat(self._pathToFile)
                if stat.st_size == 0:
                    raise PEException("File is empty.")
                    
                self._data = self.readFile(self._pathToFile)
                rd = utils.ReadData(self._data)
                # nasty check to avoid loading a non-PE file
                if self.hasMZSignature(rd) and self.hasPESignature(rd):
                    rd.setOffset(0)
                    self._internalParse(rd)
                else:
                    raise excep.PyPe32Exception("MZ/PE signature not present. Maybe not a PE file?")
            else:
                raise excep.NotValidPathException("The specified path does not exists.")
        
        self.validate()
    
    def hasMZSignature(self, rd): 
        """
        Check for MZ signature.

        @type rd: L{ReadData}
        @param rd: A L{ReadData} object.

        @rtype: bool
        @return: True is the given L{ReadData} stream has the MZ signature. Otherwise, False.
        """
        rd.setOffset(0)
        sign = rd.read(2)
        if sign == "MZ":
            return True
        return False
        
    def hasPESignature(self, rd):
        """
        Check for PE signature.

        @type rd: L{ReadData}
        @param rd: A L{ReadData} object.

        @rtype: bool
        @return: True is the given L{ReadData} stream has the PE signature. Otherwise, False.
        """
        rd.setOffset(0)
        e_lfanew_offset = unpack("<L",  rd.readAt(0x3c, 4))[0]
        sign = rd.readAt(e_lfanew_offset, 2)
        if sign == "PE":
            return True
        return False
        
    def validate(self):
        """
        Performs validations over some fields of the PE structure to determine if the loaded file has a valid PE format.
        
        @raise PEException: If an invalid value is found into the PE instance.
        """
        # Ange Albertini (@angie4771) can kill me for this! :)
        if self.dosHeader.e_magic.value != consts.MZ_SIGNATURE:
            raise excep.PEException("Invalid MZ signature. Found %d instead of %d." % (self.dosHeader.magic.value, consts.MZ_SIGNATURE))
        
        if self.dosHeader.e_lfanew.value > len(self):
            raise excep.PEException("Invalid e_lfanew value. Probably not a PE file.")
            
        if self.ntHeaders.signature.value != consts.PE_SIGNATURE: 
            raise excep.PEException("Invalid PE signature. Found %d instead of %d." % (self.ntHeaders.optionaHeader.signature.value, consts.PE_SIGNATURE))
            
        if self.ntHeaders.optionalHeader.numberOfRvaAndSizes.value > 0x10:
            print excep.PEWarning("Suspicious value for NumberOfRvaAndSizes: %d." % self.ntHeaders.optionaHeader.numberOfRvaAndSizes.value)
            
    def readFile(self, pathToFile):
        """
        Returns data from a file.
        
        @type pathToFile: str
        @param pathToFile: Path to the file.
        
        @rtype: str
        @return: The data from file.
        """
        fd = open(pathToFile,  "rb")
        data = fd.read()
        fd.close()
        return data
    
    def write(self, filename = ""):
        """
        Writes data from L{PE} object to a file.
        
        @rtype: str
        @return: The L{PE} stream data.

        @raise IOError: If the file could not be opened for write operations.
        """
        file_data = str(self)
        if filename:
            try:
                self.__write(filename, file_data)
            except IOError:
                raise IOError("File could not be opened for write operations.")
        else:
            return file_data
            
    def __write(self, thePath, theData):
        """
        Write data to a file.
        
        @type thePath: str
        @param thePath: The file path.
        
        @type theData: str
        @param theData: The data to write.
        """    
        fd = open(thePath, "wb")
        fd.write(theData)
        fd.close()
                        
    def __len__(self):
        return len(str(self))
        
    def __str__(self):
        if self._data is None and self._pathToFile is None:
            padding = "\x00" * (self.sectionHeaders[0].pointerToRawData.value - self._getPaddingToSectionOffset())
        else:
            padding = self._getPaddingDataToSectionOffset()
        
        pe = str(self.dosHeader) + str(self.dosStub) + str(self.ntHeaders) + str(self.sectionHeaders) + str(padding) + str(self.sections) + str(self.overlay)
        #if not self._fastLoad:
            #pe = self._updateDirectoriesData(pe)
        return pe

    def _updateDirectoriesData(self, peStr):
        """
        Updates the data in every L{Directory} object.
        
        @type peStr: str
        @param peStr: C{str} representation of the L{PE} object.
        
        @rtype: str
        @return: A C{str} representation of the L{PE} object.
        """
        dataDirs = self.ntHeaders.optionalHeader.dataDirectory
        wr = utils.WriteData(data)
        
        for dir in dataDirs:
            dataToWrite = str(dir.info)
            if len(dataToWrite) != dir.size.value and self._verbose:
                print excep.DataLengthException("Warning: current size of %s directory does not match with dataToWrite length %d." % (dir.size.value, len(dataToWrite)))
            wr.setOffset(self.getOffsetFromRva(dir.rva.value))
            wr.write(dataToWrite)
        return str(wr)
        
    def _getPaddingDataToSectionOffset(self):
        """
        Returns the data between the last section header and the begenning of data from the first section.
        
        @rtype: str
        @return: Data between last section header and the begenning of the first section.
        """
        start = self._getPaddingToSectionOffset()
        end = self.sectionHeaders[0].pointerToRawData.value - start
        return self._data[start:start+end]
        
    def _getSignature(self, readDataInstance, dataDirectoryInstance):
        """
        Returns the digital signature within a digital signed PE file.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} instance containing a PE file data.
        
        @type dataDirectoryInstance: L{DataDirectory}
        @param dataDirectoryInstance: A L{DataDirectory} object containing the information about directories. 
        
        @rtype: str
        @return: A string with the digital signature.
        
        @raise InstanceErrorException: If the C{readDataInstance} or the C{dataDirectoryInstance} were not specified.
        """
        signature = ""

        if readDataInstance is not None and dataDirectoryInstance is not None:        
            securityDirectory = dataDirectoryInstance[consts.SECURITY_DIRECTORY]
            
            if(securityDirectory.rva.value and securityDirectory.size.value):
                readDataInstance.setOffset(self.getOffsetFromRva(securityDirectory.rva.value))
                
                signature = readDataInstance.read(securityDirectory.size.value)
        else:
            raise excep.InstanceErrorException("ReadData instance or DataDirectory instance not specified.")
            
        return signature

    def _getOverlay(self, readDataInstance, sectionHdrsInstance):
        """
        Returns the overlay data from the PE file.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} instance containing the PE file data.
        
        @type sectionHdrsInstance: L{SectionHeaders}
        @param sectionHdrsInstance: A L{SectionHeaders} instance containing the information about the sections present in the PE file.
        
        @rtype: str
        @return: A string with the overlay data from the PE file.
        
        @raise InstanceErrorException: If the C{readDataInstance} or the C{sectionHdrsInstance} were not specified.
        """
        if readDataInstance is not None and sectionHdrsInstance is not None:            
            # adjust the offset in readDataInstance to the RawOffset + RawSize of the last section
            try:
                offset = sectionHdrsInstance[-1].pointerToRawData.value + sectionHdrsInstance[-1].sizeOfRawData.value
                readDataInstance.setOffset(offset)
            except excep.WrongOffsetValueException:
                if self._verbose:
                    print "It seems that the file has no overlay data."
        else:
            raise excep.InstanceErrorException("ReadData instance or SectionHeaders instance not specified.")
            
        return readDataInstance.data[readDataInstance.offset:]
        
    def getOffsetFromRva(self, rva):
        """
        Converts an offset to an RVA.
        
        @type rva: int
        @param rva: The RVA to be converted.
        
        @rtype: int
        @return: An integer value representing an offset in the PE file.
        """
        offset = -1
        s = self.getSectionByRva(rva)
        
        if s != offset:
            offset = (rva - self.sectionHeaders[s].virtualAddress.value) + self.sectionHeaders[s].pointerToRawData.value
        else:
            offset = rva
        
        return offset
        
    def getRvaFromOffset(self, offset):
        """
        Converts a RVA to an offset.
        
        @type offset: int
        @param offset: The offset value to be converted to RVA.
        
        @rtype: int
        @return: The RVA obtained from the given offset.
        """
        rva = -1
        s = self.getSectionByOffset(offset)
        
        if s:
            rva = (offset - self.sectionHeaders[s].pointerToRawData.value) + self.sectionHeaders[s].virtualAddress.value
            
        return rva
        
    def getSectionByOffset(self, offset):
        """
        Given an offset in the file, tries to determine the section this offset belong to.
        
        @type offset: int
        @param offset: Offset value.
        
        @rtype: int
        @return: An index, starting at 0, that represents the section the given offset belongs to.
        """
        index = -1
        for i in range(len(self.sectionHeaders)):
            if (offset < self.sectionHeaders[i].pointerToRawData.value + self.sectionHeaders[i].sizeOfRawData.value):
                index = i
                break
        return index
    
    def getSectionIndexByName(self, name):
        """
        Given a string representing a section name, tries to find the section index.

        @type name: str
        @param name: A section name.

        @rtype: int
        @return: The index, starting at 0, of the section.
        """
        index = -1
        
        if name:
            for i in range(len(self.sectionHeaders)):
                if self.sectionHeaders[i].name.value.find(name) >= 0:
                    index = i
                    break
        return index

    def getSectionByRva(self, rva):
        """
        Given a RVA in the file, tries to determine the section this RVA belongs to.
        
        @type rva: int
        @param rva: RVA value.
        
        @rtype: int
        @return: An index, starting at 1, that represents the section the given RVA belongs to.
        """
        
        index = -1
        if rva < self.sectionHeaders[0].virtualAddress.value:
            return index
        
        for i in range(len(self.sectionHeaders)):
            fa = self.ntHeaders.optionalHeader.fileAlignment.value
            prd = self.sectionHeaders[i].pointerToRawData.value
            srd = self.sectionHeaders[i].sizeOfRawData.value
            if len(str(self)) - self._adjustFileAlignment(prd,  fa) < srd:
                size = self.sectionHeaders[i].misc.value
            else:
                size = max(srd,  self.sectionHeaders[i].misc.value)
            if (self.sectionHeaders[i].virtualAddress.value <= rva) and rva < (self.sectionHeaders[i].virtualAddress.value + size):
                index = i
                break

        return index
        
    @staticmethod
    def getDosStub():
        """
        Returns a default DOS stub.
        
        @rtype: str
        @return: A defaul DOS stub.
        """
        return "0E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A240000000000000037E338C97382569A7382569A7382569A6DD0D29A6982569A6DD0C39A6382569A6DD0D59A3A82569A54442D9A7482569A7382579A2582569A6DD0DC9A7282569A6DD0C29A7282569A6DD0C79A7282569A526963687382569A000000000000000000000000000000000000000000000000".decode("hex")

    def _getPaddingToSectionOffset(self):
        """
        Returns the offset to last section header present in the PE file.
        
        @rtype: int
        @return: The offset where the end of the last section header resides in the PE file.
        """
        return len(str(self.dosHeader) + str(self.dosStub) + str(self.ntHeaders) + str(self.sectionHeaders))

    def fullLoad(self):
        """Parse all the directories in the PE file."""
        self._parseDirectories(self.ntHeaders.optionalHeader.dataDirectory, self.PE_TYPE)
        
    def _internalParse(self, readDataInstance):
        """
        Populates the attributes of the L{PE} object. 
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} instance with the data of a PE file.
        """
        self.dosHeader = DosHeader.parse(readDataInstance)
        
        self.dosStub = readDataInstance.read(self.dosHeader.e_lfanew.value - readDataInstance.offset)
        self.ntHeaders = NtHeaders.parse(readDataInstance)
        
        if self.ntHeaders.optionalHeader.magic.value == consts.PE32:
            self.PE_TYPE = consts.PE32
        elif self.ntHeaders.optionalHeader.magic.value == consts.PE64:
            self.PE_TYPE = consts.PE64
            readDataInstance.setOffset(readDataInstance.tell() - OptionalHeader().sizeof())
            self.ntHeaders.optionalHeader = OptionalHeader64.parse(readDataInstance)
            
        self.sectionHeaders = SectionHeaders.parse(readDataInstance,  self.ntHeaders.fileHeader.numberOfSections.value)

        # as padding is possible between the last section header and the beginning of the first section
        # we must adjust the offset in readDataInstance to point to the first byte of the first section.
        readDataInstance.setOffset(self.sectionHeaders[0].pointerToRawData.value)
        
        self.sections = Sections.parse(readDataInstance,  self.sectionHeaders)
        
        self.overlay = self._getOverlay(readDataInstance,  self.sectionHeaders)
        self.signature = self._getSignature(readDataInstance,  self.ntHeaders.optionalHeader.dataDirectory)
        
        if not self._fastLoad:
            self._parseDirectories(self.ntHeaders.optionalHeader.dataDirectory, self.PE_TYPE)
            
    def addSection(self, data, name =".pype32\x00", flags = 0x60000000):
        """
        Adds a new section to the existing L{PE} instance.
        
        @type data: str
        @param data: The data to be added in the new section.
        
        @type name: str
        @param name: (Optional) The name for the new section.
        
        @type flags: int
        @param flags: (Optional) The attributes for the new section.
        """
        fa = self.ntHeaders.optionalHeader.fileAlignment.value
        sa = self.ntHeaders.optionalHeader.sectionAlignment.value

        padding = "\xcc" * (fa - len(data))
        sh = SectionHeader()
        
        if len(self.sectionHeaders):
            # get the va, vz, ra and rz of the last section in the array of section headers
            vaLastSection = self.sectionHeaders[-1].virtualAddress.value
            sizeLastSection = self.sectionHeaders[-1].misc.value
            pointerToRawDataLastSection = self.sectionHeaders[-1].pointerToRawData.value
            sizeOfRawDataLastSection = self.sectionHeaders[-1].sizeOfRawData.value
            
            sh.virtualAddress.value = self._adjustSectionAlignment(vaLastSection + sizeLastSection,  fa, sa)
            sh.pointerToRawData.value = self._adjustFileAlignment(pointerToRawDataLastSection + sizeOfRawDataLastSection,  fa)

        sh.misc.value = self._adjustSectionAlignment(len(data),  fa,  sa) or consts.DEFAULT_PAGE_SIZE
        sh.sizeOfRawData.value = self._adjustFileAlignment(len(data),  fa) or consts.DEFAULT_FILE_ALIGNMENT            
        sh.characteristics.value = flags
        sh.name.value = name
        
        self.sectionHeaders.append(sh)
        self.sections.append(data + padding)
        
        self.ntHeaders.fileHeader.numberOfSections.value += 1
        
    def extendSection(self, sectionIndex, data):
        """
        Extends an existing section in the L{PE} instance.
        
        @type sectionIndex: int
        @param sectionIndex: The index for the section to be extended.
        
        @type data: str
        @param data: The data to include in the section.
        
        @raise IndexError: If an invalid C{sectionIndex} was specified.
        @raise SectionHeadersException: If there is not section to extend.
        """
        
        fa = self.ntHeaders.optionalHeader.fileAlignment.value
        sa = self.ntHeaders.optionalHeader.sectionAlignment.value 
        
        if len(self.sectionHeaders):
            if len(self.sectionHeaders) == sectionIndex:
                try:
                    # we are in the last section or self.sectionHeaders has only 1 sectionHeader instance
                    vzLastSection = self.sectionHeaders[-1].misc.value 
                    rzLastSection = self.sectionHeaders[-1].sizeOfRawData.value
                    
                    self.sectionHeaders[-1].misc.value = self._adjustSectionAlignment(vzLastSection + len(data), fa,  sa)
                    self.sectionHeaders[-1].sizeOfRawData.value = self._adjustFileAlignment(rzLastSection + len(data),  fa)
                    
                    vz = self.sectionHeaders[-1].misc.value 
                    rz = self.sectionHeaders[-1].sizeOfRawData.value
                    
                except IndexError:
                    raise IndexError("list index out of range.")
                    
                if vz < rz:
                    print "WARNING: VirtualSize (%x) is less than SizeOfRawData (%x)" % (vz,  rz)
                    
                if len(data) % fa == 0:
                    self.sections[-1] += data
                else:
                    self.sections[-1] += data + "\xcc" * (fa - len(data) % fa)
                
            else:
                # if it is not the last section ...
                try:
                    # adjust data of the section the user wants to extend
                    counter = sectionIndex - 1
                    
                    vzCurrentSection = self.sectionHeaders[counter].misc.value
                    rzCurrentSection = self.sectionHeaders[counter].sizeOfRawData.value
                    
                    self.sectionHeaders[counter].misc.value = self._adjustSectionAlignment(vzCurrentSection + len(data),  fa,  sa)
                    self.sectionHeaders[counter].sizeOfRawData.value = self._adjustFileAlignment(rzCurrentSection + len(data),  fa)

                    if len(data) % fa == 0:
                        self.sections[counter] += data
                    else:
                        self.sections[counter] += data + "\xcc" * (fa - len(data) % fa)
                         
                    counter += 1
                    
                    while(counter != len(self.sectionHeaders)):
                        vzPreviousSection = self.sectionHeaders[counter - 1].misc.value
                        vaPreviousSection = self.sectionHeaders[counter - 1].virtualAddress.value
                        rzPreviousSection = self.sectionHeaders[counter - 1].sizeOfRawData.value
                        roPreviousSection = self.sectionHeaders[counter - 1].pointerToRawData.value
                        
                        # adjust VA and RO of the next section
                        self.sectionHeaders[counter].virtualAddress.value = self._adjustSectionAlignment(vzPreviousSection + vaPreviousSection,  fa,  sa)
                        self.sectionHeaders[counter].pointerToRawData.value = self._adjustFileAlignment(rzPreviousSection + roPreviousSection,  fa)
                        
                        vz = self.sectionHeaders[counter].virtualAddress.value 
                        rz = self.sectionHeaders[counter].pointerToRawData.value
                        
                        if vz < rz:
                            print "WARNING: VirtualSize (%x) is less than SizeOfRawData (%x)" % (vz,  rz)
                            
                        counter += 1
                    
                except IndexError:
                    raise IndexError("list index out of range.")
                
        else:
            raise excep.SectionHeadersException("There is no section to extend.")
            
    def _fixPe(self):
        """
        Fixes the necessary fields in the PE file instance in order to create a valid PE32. i.e. SizeOfImage.
        """
        sizeOfImage = 0
        for sh in self.sectionHeaders:
            sizeOfImage += sh.misc
        self.ntHeaders.optionaHeader.sizeoOfImage.value = self._sectionAlignment(sizeOfImage + 0x1000)
    
    def _adjustFileAlignment(self, value, fileAlignment):
        """
        Align a value to C{FileAligment}.
       
        @type value: int
        @param value: The value to align.
        
        @type fileAlignment: int
        @param fileAlignment: The value to be used to align the C{value} parameter.
        
        @rtype: int
        @return: The aligned value.
        """
        if fileAlignment > consts.DEFAULT_FILE_ALIGNMENT:
            if not utils.powerOfTwo(fileAlignment):
                print "Warning: FileAlignment is greater than DEFAULT_FILE_ALIGNMENT (0x200) and is not power of two."
        
        if fileAlignment < consts.DEFAULT_FILE_ALIGNMENT:
            return value
            
        if fileAlignment and value % fileAlignment:
            return ((value / fileAlignment) + 1) * fileAlignment
            
        return value
        
    def _adjustSectionAlignment(self, value, fileAlignment, sectionAlignment):
        """
        Align a value to C{SectionAligment}.
        
        @type value: int
        @param value: The value to be aligned. 
        
        @type fileAlignment: int
        @param fileAlignment: The value to be used as C{FileAlignment}.
        
        @type sectionAlignment: int
        @param sectionAlignment: The value to be used as C{SectionAlignment}.
        
        @rtype: int
        @return: The aligned value.
        """
        if fileAlignment < consts.DEFAULT_FILE_ALIGNMENT:
            if fileAligment != sectionAlignment:
                print "FileAlignment does not match SectionAlignment."
        
        if sectionAlignment < consts.DEFAULT_PAGE_SIZE:
            sectionAlignment = fileAlignment
            
        if sectionAlignment and value % sectionAlignment:
            return sectionAlignment * ((value / sectionAlignment) + 1)
        return value
    
    def getDwordAtRva(self, rva):
        """
        Returns a C{DWORD} from a given RVA. 
        
        @type rva: int
        @param rva: The RVA to get the C{DWORD} from.
        
        @rtype: L{DWORD}
        @return: The L{DWORD} obtained at the given RVA.
        """
        return datatypes.DWORD.parse(utils.ReadData(self.getDataAtRva(rva,  4)))
        
    def getWordAtRva(self, rva):
        """
        Returns a C{WORD} from a given RVA. 
        
        @type rva: int
        @param rva: The RVA to get the C{WORD} from.
        
        @rtype: L{WORD}
        @return: The L{WORD} obtained at the given RVA.
        """
        return datatypes.WORD.parse(utils.ReadData(self.getDataAtRva(rva,  2)))
        
    def getDwordAtOffset(self, offset):
        """
        Returns a C{DWORD} from a given offset. 
        
        @type offset: int
        @param offset: The offset to get the C{DWORD} from.
        
        @rtype: L{DWORD}
        @return: The L{DWORD} obtained at the given offset.
        """
        return datatypes.DWORD.parse(utils.ReadData(self.getDataAtOffset(offset,  4)))
        
    def getWordAtOffset(self, offset):
        """
        Returns a C{WORD} from a given offset. 
        
        @type offset: int
        @param offset: The offset to get the C{WORD} from.
        
        @rtype: L{WORD}
        @return: The L{WORD} obtained at the given offset.
        """
        return datatypes.WORD.parse(utils.ReadData(self.getDataAtOffset(offset, 2)))
    
    def getQwordAtRva(self, rva):
        """
        Returns a C{QWORD} from a given RVA. 
        
        @type rva: int
        @param rva: The RVA to get the C{QWORD} from.
        
        @rtype: L{QWORD}
        @return: The L{QWORD} obtained at the given RVA.
        """
        return datatypes.QWORD.parse(utils.ReadData(self.getDataAtRva(rva,  8)))
        
    def getQwordAtOffset(self, offset):
        """
        Returns a C{QWORD} from a given offset. 
        
        @type offset: int
        @param offset: The offset to get the C{QWORD} from.
        
        @rtype: L{QWORD}
        @return: The L{QWORD} obtained at the given offset.
        """
        return datatypes.QWORD.parse(utils.ReadData(self.getDataAtOffset(offset,  8)))
        
    def getDataAtRva(self, rva, size):
        """
        Gets binary data at a given RVA.
        
        @type rva: int
        @param rva: The RVA to get the data from.
        
        @type size: int
        @param size: The size of the data to be obtained. 
        
        @rtype: str
        @return: The data obtained at the given RVA.
        """
        return self.getDataAtOffset(self.getOffsetFromRva(rva),  size)
    
    def getDataAtOffset(self, offset, size):
        """
        Gets binary data at a given offset.
        
        @type offset: int
        @param offset: The offset to get the data from.
        
        @type size: int
        @param size: The size of the data to be obtained.
        
        @rtype: str
        @return: The data obtained at the given offset.
        """
        data = str(self)
        return data[offset:offset+size]
    
    def readStringAtRva(self, rva):
        """
        Returns a L{String} object from a given RVA. 
        
        @type rva: int
        @param rva: The RVA to get the string from.
        
        @rtype: L{String}
        @return: A new L{String} object from the given RVA.
        """
        d = self.getDataAtRva(rva,  1)
        resultStr = datatypes.String("")
        while d != "\x00":
            resultStr.value += d
            rva += 1
            d = self.getDataAtRva(rva, 1)
        return resultStr
        
    def isExe(self):
        """
        Determines if the current L{PE} instance is an Executable file.
        
        @rtype: bool
        @return: C{True} if the current L{PE} instance is an Executable file. Otherwise, returns C{False}.
        """
        if not self.isDll() and not self.isDriver() and ( consts.IMAGE_FILE_EXECUTABLE_IMAGE & self.ntHeaders.fileHeader.characteristics.value) == consts.IMAGE_FILE_EXECUTABLE_IMAGE:
            return True
        return False
    
    def isDll(self):
        """
        Determines if the current L{PE} instance is a Dynamic Link Library file.
        
        @rtype: bool
        @return: C{True} if the current L{PE} instance is a DLL. Otherwise, returns C{False}.
        """
        if (consts.IMAGE_FILE_DLL & self.ntHeaders.fileHeader.characteristics.value) == consts.IMAGE_FILE_DLL:
            return True
        return False
    
    def isDriver(self):
        """
        Determines if the current L{PE} instance is a driver (.sys) file.
        
        @rtype: bool
        @return: C{True} if the current L{PE} instance is a driver. Otherwise, returns C{False}.
        """
        modules = []
        imports = self.ntHeaders.optionalHeader.dataDirectory[consts.IMPORT_DIRECTORY].info
        for module in imports:
            modules.append(module.metaData.moduleName.value.lower())
        
        if set(["ntoskrnl.exe", "hal.dll", "ndis.sys", "bootvid.dll", "kdcom.dll"]).intersection(modules):
            return True
        return False
    
    def isPe32(self):
        """
        Determines if the current L{PE} instance is a PE32 file.
        
        @rtype: bool
        @return: C{True} if the current L{PE} instance is a PE32 file. Otherwise, returns C{False}.
        """
        if self.ntHeaders.optionalHeader.magic.value == consts.PE32:
            return True
        return False
    
    def isPe64(self):
        """
        Determines if the current L{PE} instance is a PE64 file.
        
        @rtype: bool
        @return: C{True} if the current L{PE} instance is a PE64 file. Otherwise, returns C{False}.
        """
        if self.ntHeaders.optionalHeader.magic.value == consts.PE64:
            return True
        return False
    
    def isPeBounded(self):
        """
        Determines if the current L{PE} instance is bounded, i.e. has a C{BOUND_IMPORT_DIRECTORY}.
        
        @rtype: bool
        @return: Returns C{True} if the current L{PE} instance is bounded. Otherwise, returns C{False}.
        """
        boundImportsDir = self.ntHeaders.optionalHeader.dataDirectory[consts.BOUND_IMPORT_DIRECTORY]
        if boundImportsDir.rva.value and boundImportsDir.size.value:
            return True
        return False

    def isNXEnabled(self):
        """
        Determines if the current L{PE} instance has the NXCOMPAT (Compatible with Data Execution Prevention) flag enabled.
        @see: U{http://msdn.microsoft.com/en-us/library/ms235442.aspx}

        @rtype: bool
        @return: Returns C{True} if the current L{PE} instance has the NXCOMPAT flag enabled. Otherwise, returns C{False}.
        """
        return self.ntHeaders.optionalHeader.dllCharacteristics.value & consts.IMAGE_DLL_CHARACTERISTICS_NX_COMPAT == consts.IMAGE_DLL_CHARACTERISTICS_NX_COMPAT

        # http://www.powerofcommunity.net/poc2014/mj0011.pdf
        # https://github.com/DarthTon/Blackbone/blob/master/src/BlackBoneDrv/PEStructs.h
        # http://static1.1.sqspcdn.com/static/f/336849/25005618/1402230025800/ep12-FullDump.txt?token=13GN1EahQqnHjM%2Ft3hnDCfQ03iU%3D
        # http://www.virtualbox.org/svn/vbox/trunk/src/VBox/Runtime/include/internal/ldrPE.h
    def isCFGEnabled(self):
        """
        Determines if the current L{PE} instance has CFG (Control Flow Guard) flag enabled.
        @see: U{http://blogs.msdn.com/b/vcblog/archive/2014/12/08/visual-studio-2015-preview-work-in-progress-security-feature.aspx}
        @see: U{https://msdn.microsoft.com/en-us/library/dn919635%%28v=vs.140%%29.aspx}

        @rtype: bool
        @return: Returns C{True} if the current L{PE} instance has the CFG flag enabled. Otherwise, return C{False}.
        """
        return self.ntHeaders.optionalHeader.dllCharacteristics.value & consts.IMAGE_DLL_CHARACTERISTICS_GUARD_CF == consts.IMAGE_DLL_CHARACTERISTICS_GUARD_CF

    def isASLREnabled(self):
        """
        Determines if the current L{PE} instance has the DYNAMICBASE (Use address space layout randomization) flag enabled.
        @see: U{http://msdn.microsoft.com/en-us/library/bb384887.aspx}

        @rtype: bool
        @return: Returns C{True} if the current L{PE} instance has the DYNAMICBASE flag enabled. Otherwise, returns C{False}.
        """
        return self.ntHeaders.optionalHeader.dllCharacteristics.value & consts.IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE == consts.IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE

    def isSAFESEHEnabled(self):
        """
        Determines if the current L{PE} instance has the SAFESEH (Image has Safe Exception Handlers) flag enabled.
        @see: U{http://msdn.microsoft.com/en-us/library/9a89h429.aspx}

        @rtype: bool
        @return: Returns C{True} if the current L{PE} instance has the SAFESEH flag enabled. Returns C{False} if SAFESEH is off or -1 if SAFESEH is set to NO.
        """
        NOSEH = -1
        SAFESEH_OFF = 0
        SAFESEH_ON = 1

        if self.ntHeaders.optionalHeader.dllCharacteristics.value & consts.IMAGE_DLL_CHARACTERISTICS_NO_SEH:
            return NOSEH

        loadConfigDir = self.ntHeaders.optionalHeader.dataDirectory[consts.CONFIGURATION_DIRECTORY]
        if loadConfigDir.info:
            if loadConfigDir.info.SEHandlerTable.value:
                return SAFESEH_ON
        return SAFESEH_OFF

    def _parseDirectories(self, dataDirectoryInstance, magic = consts.PE32):
        """
        Parses all the directories in the L{PE} instance.
        
        @type dataDirectoryInstance: L{DataDirectory}
        @param dataDirectoryInstance: A L{DataDirectory} object with the directories data.
        
        @type magic: int
        @param magic: (Optional) The type of PE. This value could be L{consts.PE32} or L{consts.PE64}.
        """
        directories = [(consts.EXPORT_DIRECTORY, self._parseExportDirectory),\
                         (consts.IMPORT_DIRECTORY, self._parseImportDirectory),\
                         (consts.RESOURCE_DIRECTORY, self._parseResourceDirectory),\
                         (consts.EXCEPTION_DIRECTORY, self._parseExceptionDirectory),\
                         (consts.RELOCATION_DIRECTORY, self._parseRelocsDirectory),\
                         (consts.TLS_DIRECTORY, self._parseTlsDirectory),\
                         (consts.DEBUG_DIRECTORY, self._parseDebugDirectory),\
                         (consts.BOUND_IMPORT_DIRECTORY, self._parseBoundImportDirectory),\
                         (consts.DELAY_IMPORT_DIRECTORY, self._parseDelayImportDirectory),\
                         (consts.CONFIGURATION_DIRECTORY, self._parseLoadConfigDirectory),\
                         (consts.NET_METADATA_DIRECTORY, self._parseNetDirectory)]
        
        for directory in directories:
            dir = dataDirectoryInstance[directory[0]]
            if dir.rva.value and dir.size.value:
                try:
                    dataDirectoryInstance[directory[0]].info = directory[1](dir.rva.value, dir.size.value, magic)
                except Exception as e:
                    print excep.PEWarning("Error parsing PE directory: %s." % directory[1].__name__.replace("_parse", ""))

    def _parseResourceDirectory(self, rva, size, magic = consts.PE32):
        """
        Parses the C{IMAGE_RESOURCE_DIRECTORY} directory.
        
        @type rva: int 
        @param rva: The RVA where the C{IMAGE_RESOURCE_DIRECTORY} starts.
        
        @type size: int
        @param size: The size of the C{IMAGE_RESOURCE_DIRECTORY} directory.
        
        @type magic: int
        @param magic: (Optional) The type of PE. This value could be L{consts.PE32} or L{consts.PE64}.
        
        @rtype: str
        @return: The C{IMAGE_RESOURCE_DIRECTORY} data.
        """
        return self.getDataAtRva(rva, size)
    
    def _parseExceptionDirectory(self, rva, size, magic = consts.PE32):
        """
        Parses the C{IMAGE_EXCEPTION_DIRECTORY} directory.
        
        @type rva: int 
        @param rva: The RVA where the C{IMAGE_EXCEPTION_DIRECTORY} starts.
        
        @type size: int
        @param size: The size of the C{IMAGE_EXCEPTION_DIRECTORY} directory.
        
        @type magic: int
        @param magic: (Optional) The type of PE. This value could be L{consts.PE32} or L{consts.PE64}.
        
        @rtype: str
        @return: The C{IMAGE_EXCEPTION_DIRECTORY} data.
        """
        return self.getDataAtRva(rva, size)
        
    def _parseDelayImportDirectory(self, rva, size, magic = consts.PE32):
        """
        Parses the delay imports directory.
        
        @type rva: int 
        @param rva: The RVA where the delay imports directory starts.
        
        @type size: int
        @param size: The size of the delay imports directory.
        
        @type magic: int
        @param magic: (Optional) The type of PE. This value could be L{consts.PE32} or L{consts.PE64}.
        
        @rtype: str
        @return: The delay imports directory data.
        """
        return self.getDataAtRva(rva, size)
        
    def _parseBoundImportDirectory(self, rva, size, magic = consts.PE32):
        """
        Parses the bound import directory.
        
        @type rva: int 
        @param rva: The RVA where the bound import directory starts.
        
        @type size: int
        @param size: The size of the bound import directory.
        
        @type magic: int
        @param magic: (Optional) The type of PE. This value could be L{consts.PE32} or L{consts.PE64}.
        
        @rtype: L{ImageBoundImportDescriptor}
        @return: A new L{ImageBoundImportDescriptor} object.
        """
        data = self.getDataAtRva(rva, size)
        rd = utils.ReadData(data)
        boundImportDirectory = directories.ImageBoundImportDescriptor.parse(rd)
        
        # parse the name of every bounded import.
        for i in range(len(boundImportDirectory) - 1):
            if hasattr(boundImportDirectory[i],  "forwarderRefsList"):
                if boundImportDirectory[i].forwarderRefsList:
                    for forwarderRefEntry in boundImportDirectory[i].forwarderRefsList:
                        offset = forwarderRefEntry.offsetModuleName.value
                        forwarderRefEntry.moduleName = self.readStringAtRva(offset + rva)
                        
            offset = boundImportDirectory[i].offsetModuleName.value
            boundImportDirectory[i].moduleName = self.readStringAtRva(offset + rva)
        return boundImportDirectory

    def _parseLoadConfigDirectory(self, rva, size, magic = consts.PE32):
        """
        Parses IMAGE_LOAD_CONFIG_DIRECTORY.
        
        @type rva: int 
        @param rva: The RVA where the IMAGE_LOAD_CONFIG_DIRECTORY starts.
        
        @type size: int
        @param size: The size of the IMAGE_LOAD_CONFIG_DIRECTORY.
        
        @type magic: int
        @param magic: (Optional) The type of PE. This value could be L{consts.PE32} or L{consts.PE64}.
        
        @rtype: L{ImageLoadConfigDirectory}
        @return: A new L{ImageLoadConfigDirectory}. 
        @note: if the L{PE} instance is a PE64 file then a new L{ImageLoadConfigDirectory64} is returned.
        """
        # print "RVA: %x - SIZE: %x" % (rva, size)

        # I've found some issues when parsing the IMAGE_LOAD_CONFIG_DIRECTORY in some DLLs. 
        # There is an inconsistency with the size of the struct between MSDN docs and VS.
        # sizeof(IMAGE_LOAD_CONFIG_DIRECTORY) should be 0x40, in fact, that's the size Visual Studio put
        # in the directory table, even if the DLL was compiled with SAFESEH:ON. But If that is the case, the sizeof the
        # struct should be 0x48.
        # more information here: http://www.accuvant.com/blog/old-meets-new-microsoft-windows-safeseh-incompatibility
        data = self.getDataAtRva(rva, directories.ImageLoadConfigDirectory().sizeof())
        rd = utils.ReadData(data)

        if magic == consts.PE32:
            return directories.ImageLoadConfigDirectory.parse(rd)
        elif magic == consts.PE64:
            return directories.ImageLoadConfigDirectory64.parse(rd)
        else:
            raise excep.InvalidParameterException("Wrong magic")

    def _parseTlsDirectory(self, rva, size, magic = consts.PE32):
        """
        Parses the TLS directory.
        
        @type rva: int 
        @param rva: The RVA where the TLS directory starts.
        
        @type size: int
        @param size: The size of the TLS directory.
        
        @type magic: int
        @param magic: (Optional) The type of PE. This value could be L{consts.PE32} or L{consts.PE64}.
        
        @rtype: L{TLSDirectory}
        @return: A new L{TLSDirectory}. 
        @note: if the L{PE} instance is a PE64 file then a new L{TLSDirectory64} is returned.
        """
        data = self.getDataAtRva(rva, size)
        rd = utils.ReadData(data)
        
        if magic == consts.PE32:
            return directories.TLSDirectory.parse(rd)
        elif magic == consts.PE64:
            return directories.TLSDirectory64.parse(rd)
        else:
            raise excep.InvalidParameterException("Wrong magic")
        
    def _parseRelocsDirectory(self, rva, size, magic = consts.PE32):
        """
        Parses the relocation directory.
        
        @type rva: int 
        @param rva: The RVA where the relocation directory starts.
        
        @type size: int
        @param size: The size of the relocation directory.
        
        @type magic: int
        @param magic: (Optional) The type of PE. This value could be L{consts.PE32} or L{consts.PE64}.
        
        @rtype: L{ImageBaseRelocation}
        @return: A new L{ImageBaseRelocation} object.
        """
        data = self.getDataAtRva(rva,  size)
        #print "Length Relocation data: %x" % len(data)
        rd = utils.ReadData(data)
        
        relocsArray = directories.ImageBaseRelocation()
        while rd.offset < size:
            relocEntry = directories.ImageBaseRelocationEntry.parse(rd)
            relocsArray.append(relocEntry)
        return relocsArray
        
    def _parseExportDirectory(self, rva, size, magic = consts.PE32):
        """
        Parses the C{IMAGE_EXPORT_DIRECTORY} directory.
        
        @type rva: int 
        @param rva: The RVA where the C{IMAGE_EXPORT_DIRECTORY} directory starts.
        
        @type size: int
        @param size: The size of the C{IMAGE_EXPORT_DIRECTORY} directory.
        
        @type magic: int
        @param magic: (Optional) The type of PE. This value could be L{consts.PE32} or L{consts.PE64}.
        
        @rtype: L{ImageExportTable}
        @return: A new L{ImageExportTable} object.
        """
        data = self.getDataAtRva(rva,  size)
        rd = utils.ReadData(data)
        
        iet = directories.ImageExportTable.parse(rd)
        
        auxFunctionRvaArray = list()
        
        numberOfNames = iet.numberOfNames.value
        addressOfNames = iet.addressOfNames.value
        addressOfNameOrdinals = iet.addressOfNameOrdinals.value
        addressOfFunctions = iet.addressOfFunctions.value
        
        # populate the auxFunctionRvaArray
        for i in xrange(iet.numberOfFunctions.value):
            auxFunctionRvaArray.append(self.getDwordAtRva(addressOfFunctions).value)
            addressOfFunctions += datatypes.DWORD().sizeof()
            
        for i in xrange(numberOfNames):
            
            nameRva = self.getDwordAtRva(addressOfNames).value
            nameOrdinal = self.getWordAtRva(addressOfNameOrdinals).value
            exportName = self.readStringAtRva(nameRva).value
            
            entry = directories.ExportTableEntry()
            
            ordinal = nameOrdinal + iet.base.value
            #print "Ordinal value: %d" % ordinal
            entry.ordinal.value = ordinal
            
            entry.nameOrdinal.vaue = nameOrdinal
            entry.nameRva.value = nameRva
            entry.name.value = exportName
            entry.functionRva.value = auxFunctionRvaArray[nameOrdinal]
            
            iet.exportTable.append(entry)
            
            addressOfNames += datatypes.DWORD().sizeof()
            addressOfNameOrdinals += datatypes.WORD().sizeof()
        
        #print "export table length: %d" % len(iet.exportTable)
        
        #print "auxFunctionRvaArray: %r" % auxFunctionRvaArray
        for i in xrange(iet.numberOfFunctions.value):
            #print "auxFunctionRvaArray[%d]: %x" % (i,  auxFunctionRvaArray[i])
            if auxFunctionRvaArray[i] != iet.exportTable[i].functionRva.value:
                entry = directories.ExportTableEntry()
                
                entry.functionRva.value = auxFunctionRvaArray[i]
                entry.ordinal.value = iet.base.value + i
                
                iet.exportTable.append(entry)
        
        #print "export table length: %d" % len(iet.exportTable)
        sorted(iet.exportTable, key=lambda entry:entry.ordinal)
        return iet
        
    def _parseDebugDirectory(self, rva, size, magic = consts.PE32):
        """
        Parses the C{IMAGE_DEBUG_DIRECTORY} directory.
        @see: U{http://msdn.microsoft.com/es-es/library/windows/desktop/ms680307(v=vs.85).aspx}
        
        @type rva: int 
        @param rva: The RVA where the C{IMAGE_DEBUG_DIRECTORY} directory starts.
        
        @type size: int
        @param size: The size of the C{IMAGE_DEBUG_DIRECTORY} directory.
        
        @type magic: int
        @param magic: (Optional) The type of PE. This value could be L{consts.PE32} or L{consts.PE64}.
        
        @rtype: L{ImageDebugDirectory}
        @return: A new L{ImageDebugDirectory} object.
        """        
        debugDirData = self.getDataAtRva(rva, size)
        numberOfEntries = size / consts.SIZEOF_IMAGE_DEBUG_ENTRY32
        rd = utils.ReadData(debugDirData)
        return directories.ImageDebugDirectories.parse(rd,  numberOfEntries)
        
    def _parseImportDirectory(self, rva, size, magic = consts.PE32):
        """
        Parses the C{IMAGE_IMPORT_DIRECTORY} directory.
        
        @type rva: int 
        @param rva: The RVA where the C{IMAGE_IMPORT_DIRECTORY} directory starts.
        
        @type size: int
        @param size: The size of the C{IMAGE_IMPORT_DIRECTORY} directory.
        
        @type magic: int
        @param magic: (Optional) The type of PE. This value could be L{consts.PE32} or L{consts.PE64}.
        
        @rtype: L{ImageImportDescriptor}
        @return: A new L{ImageImportDescriptor} object.
        
        @raise InvalidParameterException: If wrong magic was specified.
        """
        #print "RVA: %x - Size: %x" % (rva, size)        
        importsDirData = self.getDataAtRva(rva,  size)
        #print "Length importsDirData: %d" % len(importsDirData)
        numberOfEntries = size / consts.SIZEOF_IMAGE_IMPORT_ENTRY32
        rd = utils.ReadData(importsDirData)
        
        # In .NET binaries, the size of the data directory corresponding to the import table
        # is greater than the number of bytes in the file. Thats why we check for the last group of 5 null bytes
        # that indicates the end of the IMAGE_IMPORT_DESCRIPTOR array.
        rdAux = utils.ReadData(importsDirData)
        count = 0
        entry = rdAux.read(consts.SIZEOF_IMAGE_IMPORT_ENTRY32)
        while rdAux.offset < len(rdAux.data) and not utils.allZero(entry):
            try:
                entry = rdAux.read(consts.SIZEOF_IMAGE_IMPORT_ENTRY32)
                count += 1
            except excep.DataLengthException:
                if self._verbose:
                    print "[!] Warning: DataLengthException detected!."
                
        if numberOfEntries - 1 > count:
            numberOfEntries = count + 1

        iid = directories.ImageImportDescriptor.parse(rd, numberOfEntries)
        iidLength = len(iid)
        
        peIsBounded = self.isPeBounded()
        
        if magic == consts.PE64:
            ORDINAL_FLAG = consts.IMAGE_ORDINAL_FLAG64
            ADDRESS_MASK = consts.ADDRESS_MASK64
        elif magic == consts.PE32:
            ORDINAL_FLAG = consts.IMAGE_ORDINAL_FLAG
            ADDRESS_MASK = consts.ADDRESS_MASK32
        else:
            raise InvalidParameterException("magic value %d is not PE64 nor PE32." % magic)
        
        for i in range(iidLength -1):
            if iid[i].originalFirstThunk.value != 0:
                iltRva = iid[i].originalFirstThunk.value
                iatRva = iid[i].firstThunk.value
                
                if magic == consts.PE64:
                    entry = self.getQwordAtRva(iltRva).value
                elif magic == consts.PE32:
                    entry = self.getDwordAtRva(iltRva).value

                while entry != 0:
                    
                    if magic == consts.PE64:
                        iatEntry = directories.ImportAddressTableEntry64()
                    elif magic == consts.PE32:
                        iatEntry = directories.ImportAddressTableEntry()
                        
                    iatEntry.originalFirstThunk.value = entry
                    
                    if iatEntry.originalFirstThunk.value & ORDINAL_FLAG:
                        iatEntry.hint.value = None
                        iatEntry.name.value = iatEntry.originalFirstThunk.value & ADDRESS_MASK
                    else: 
                        iatEntry.hint.value = self.getWordAtRva(iatEntry.originalFirstThunk.value).value
                        iatEntry.name.value = self.readStringAtRva(iatEntry.originalFirstThunk.value + 2).value
                    
                    if magic == consts.PE64:
                        iatEntry.firstThunk.value = self.getQwordAtRva(iatRva).value
                        iltRva += 8
                        iatRva += 8
                        entry = self.getQwordAtRva(iltRva).value
                    elif magic == consts.PE32:
                        iatEntry.firstThunk.value = self.getDwordAtRva(iatRva).value                        
                        iltRva += 4
                        iatRva += 4
                        entry = self.getDwordAtRva(iltRva).value                        
                    
                    iid[i].iat.append(iatEntry)
                    
            else:
                iatRva = iid[i].firstThunk.value
                
                if magic == consts.PE64:
                    entry = self.getQwordAtRva(iatRva).value
                elif magic == consts.PE32:
                    entry = self.getDwordAtRva(iatRva).value
                    
                while entry != 0:

                    if magic == consts.PE64:
                        iatEntry = directories.ImportAddressTableEntry64()
                    elif magic == consts.PE32:
                        iatEntry = directories.ImportAddressTableEntry()
                    
                    iatEntry.firstThunk.value = entry
                    iatEntry.originalFirstThunk.value = 0
                    
                    if not peIsBounded:
                        ft = iatEntry.firstThunk.value

                        if ft & ORDINAL_FLAG:
                            iatEntry.hint.value = None
                            iatEntry.name.value = ft & ADDRESS_MASK
                        else:
                            iatEntry.hint.value = self.getWordAtRva(ft).value
                            iatEntry.name.value = self.readStringAtRva(ft + 2).value                            
                    else:
                        iatEntry.hint.value = None
                        iatEntry.name.value = None
                
                    if magic == consts.PE64:
                        iatRva += 8
                        entry = self.getQwordAtRva(iatRva).value
                    elif magic == consts.PE32:
                        iatRva += 4
                        entry = self.getDwordAtRva(iatRva).value

                    iid[i].iat.append(iatEntry)
             
            iid[i].metaData.moduleName.value = self.readStringAtRva(iid[i].name.value).value
            iid[i].metaData.numberOfImports.value = len(iid[i].iat)
        return iid
        
    def _parseNetDirectory(self, rva, size, magic = consts.PE32):
        """
        Parses the NET directory.
        @see: U{http://www.ntcore.com/files/dotnetformat.htm}
        
        @type rva: int 
        @param rva: The RVA where the NET directory starts.
        
        @type size: int
        @param size: The size of the NET directory.
        
        @type magic: int
        @param magic: (Optional) The type of PE. This value could be L{consts.PE32} or L{consts.PE64}.
        
        @rtype: L{NETDirectory}
        @return: A new L{NETDirectory} object.
        """        
        if not rva or not size:
            return None

        # create a NETDirectory class to hold the data
        netDirectoryClass = directories.NETDirectory()

        # parse the .NET Directory
        netDir = directories.NetDirectory.parse(utils.ReadData(self.getDataAtRva(rva,  size)))

        netDirectoryClass.directory = netDir

        # get the MetaData RVA and Size
        mdhRva = netDir.metaData.rva.value
        mdhSize = netDir.metaData.size.value

        # read all the MetaData
        rd = utils.ReadData(self.getDataAtRva(mdhRva, mdhSize))

        # parse the MetaData headers
        netDirectoryClass.netMetaDataHeader = directories.NetMetaDataHeader.parse(rd)

        # parse the NET metadata streams
        numberOfStreams = netDirectoryClass.netMetaDataHeader.numberOfStreams.value
        netDirectoryClass.netMetaDataStreams = directories.NetMetaDataStreams.parse(rd, numberOfStreams)

        for i in range(numberOfStreams):
            stream = netDirectoryClass.netMetaDataStreams[i]
            name = stream.name.value
            rd.setOffset(stream.offset.value)
            rd2 = utils.ReadData(rd.read(stream.size.value))
            stream.info = []
            if name == "#~":
                stream.info = rd2
            elif name == "#Strings":
                while len(rd2) > 0:
                    offset = rd2.tell()
                    stream.info.append({ offset: rd2.readDotNetString() })
            elif name == "#US":
                while len(rd2) > 0:
                    offset = rd2.tell()
                    stream.info.append({ offset: rd2.readDotNetUnicodeString() })
            elif name == "#GUID":
                while len(rd2) > 0:
                    offset = rd2.tell()
                    stream.info.append({ offset: rd2.readDotNetGuid() })
            elif name == "#Blob":
                while len(rd2) > 0:
                    offset = rd2.tell()
                    stream.info.append({ offset: rd2.readDotNetBlob() })

        for i in range(numberOfStreams):
            stream = netDirectoryClass.netMetaDataStreams[i]
            name = stream.name.value
            if name == "#~":
                stream.info = directories.NetMetaDataTables.parse(stream.info, netDirectoryClass.netMetaDataStreams)

        # parse .NET resources
        # get the Resources RVA and Size
        resRva = netDir.resources.rva.value
        resSize = netDir.resources.size.value

        # read all the MetaData
        rd = utils.ReadData(self.getDataAtRva(resRva, resSize))

        resources = []

        for i in netDirectoryClass.netMetaDataStreams[0].info.tables["ManifestResource"]:
            offset = i["offset"]
            rd.setOffset(offset)
            size = rd.readDword()
            data = rd.read(size)
            if data[:4] == "\xce\xca\xef\xbe":
                data = directories.NetResources.parse(utils.ReadData(data))
            resources.append({ "name": i["name"], "offset": offset + 4, "size": size, "data": data })

        netDirectoryClass.directory.resources.info = resources

        return netDirectoryClass
    
    def getMd5(self):
        """
        Get MD5 hash from PE file.

        @rtype: str
        @return: The MD5 hash from the L{PE} instance.
        """
        return hashlib.md5(str(self)).hexdigest()

    def getSha1(self):
        """
        Get SHA1 hash from PE file.

        @rtype: str
        @return: The SHA1 hash from the L{PE} instance.
        """
        return hashlib.sha1(str(self)).hexdigest()

    def getSha256(self):
        """
        Get SHA256 hash from PE file.

        @rtype: str
        @return: The SHA256 hash from the L{PE} instance.
        """
        return hashlib.sha256(str(self)).hexdigest()

    def getSha512(self):
        """
        Get SHA512 hash from PE file.

        @rtype: str
        @return: The SHA512 hash from the L{PE} instance.
        """
        return hashlib.sha512(str(self)).hexdigest()

    def getCRC32(self):
        """
        Get CRC32 checksum from PE file.

        @rtype: int
        @return: The CRD32 checksum from the L{PE} instance.
        """
        return binascii.crc32(str(self)) & 0xffffffff

    def hasImportedFunction(self, funcName):
        retval = False
        if not self._fastLoad:
            import_directory = self.ntHeaders.optionalHeader.dataDirectory[consts.IMPORT_DIRECTORY]
            if import_directory:
                for iid_entry in import_directory.info:
                    for entry in iid_entry.iat:
                        if entry.name.value == funcName:
                            retval = True
                            break
            else:
                print "WARNING: IMPORT_DIRECTORY not found on PE!"
        else:
            print "WARNING: fastLoad parameter was used to load the PE. Data directories are not parsed when using this options. Please, use fastLoad = False."
        return retval

    def getNetMetadataToken(self, token):
        dnh = self.ntHeaders.optionalHeader.dataDirectory[14].info
        if not dnh: return None
        tables = dnh.netMetaDataStreams[0].info.tables

        tblid = token >> 24 & 0xff
        table = tables.get(tblid)
        if not table:
            return None

        rowid = (token & 0xffffff) - 1
        if rowid < 0 or rowid >= len(table):
            return None

        return table[rowid]

    def getNetEntryPointOffset(self):
        dnh = self.ntHeaders.optionalHeader.dataDirectory[14].info
        if not dnh: return None
        dnh = dnh.directory

        token = self.getNetMetadataToken(dnh.entryPointToken.value)

        if dnh.flags.value & consts.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT:
            # print("Native entry point.")
            offset = self.getOffsetFromRva(token)
        else:
            # print("Managed entry point.")
            offset = self.getOffsetFromRva(token["rva"])
            rd = utils.ReadData(self.getDataAtOffset(offset, 12))
            flags = rd.readByte()
            if flags & 0x3 == consts.CORILMETHOD_TINYFORMAT:
                # print("Tiny header.")
                codeSize = flags >> 2 & 0x3f
                flags = flags & 0x3
                headerSize = 1
                maxStack = 8
                localVarSigTok = 0
            elif flags & 0x3 == consts.CORILMETHOD_FATFORMAT:
                # print("Fat header.")
                flags |= rd.readByte() << 8
                headerSize = 4 * (flags >> 12 & 0xf)
                flags = flags & 0xfff
                maxStack = rd.readWord()
                codeSize = rd.readDword()
                localVarSigTok = rd.readDword()
            else:
                raise Exception("Unknown CLR method header.")
            offset += headerSize

        return offset

class DosHeader(baseclasses.BaseStructClass):
    """DosHeader object."""
    def __init__(self,  shouldPack = True):
         """
         Class representation of the C{IMAGE_DOS_HEADER} structure. 
         @see: U{http://msdn.microsoft.com/en-us/magazine/cc301805.aspx}
         
         @type shouldPack: bool
         @param shouldPack: (Optional) If set to C{True}, the object will be packed. If set to C{False}, the object won't be packed.
         """
         baseclasses.BaseStructClass.__init__(self,  shouldPack)
        
         self.e_magic = datatypes.WORD(consts.MZ_SIGNATURE) #: L{WORD} e_magic.
         self.e_cblp = datatypes.WORD(0) #: L{WORD} e_cblp.
         self.e_cp = datatypes.WORD(0) #: L{WORD} e_cp.
         self.e_crlc = datatypes.WORD(0) #: L{WORD} e_crlc.
         self.e_cparhdr = datatypes.WORD(0) #: L{WORD} e_cparhdr.
         self.e_minalloc = datatypes.WORD(0) #: L{WORD} e_minalloc.
         self.e_maxalloc = datatypes.WORD(0) #: L{WORD} e_maxalloc.
         self.e_ss = datatypes.WORD(0) #: L{WORD} e_ss.
         self.e_sp = datatypes.WORD(0) #: L{WORD} e_sp.
         self.e_csum = datatypes.WORD(0) #: L{WORD} e_csum.
         self.e_ip = datatypes.WORD(0) #: L{WORD} e_ip.
         self.e_cs = datatypes.WORD(0) #: L{WORD} e_cs.
         self.e_lfarlc = datatypes.WORD(0) #: L{WORD} e_lfarlc.
         self.e_ovno = datatypes.WORD(0) #: L{WORD} e_ovno.
         
         self.e_res = datatypes.Array(datatypes.TYPE_WORD) #: L{Array} of type L{WORD} e_res.
         self.e_res.extend([datatypes.WORD(0), datatypes.WORD(0),  datatypes.WORD(0),  datatypes.WORD(0)])
         
         self.e_oemid = datatypes.WORD(0) #: L{WORD} e_oemid.
         self.e_oeminfo = datatypes.WORD(0) #: L{WORD} e_oeminfo.
         
         self.e_res2 = datatypes.Array(datatypes.TYPE_WORD) #: L{Array} of type L{WORD} e_res2.
         self.e_res2.extend([datatypes.WORD(0), datatypes.WORD(0),  datatypes.WORD(0),  datatypes.WORD(0),\
                             datatypes.WORD(0), datatypes.WORD(0),  datatypes.WORD(0),  datatypes.WORD(0),\
                             datatypes.WORD(0), datatypes.WORD(0)])
        
         self.e_lfanew = datatypes.DWORD(0xf0) #: L{DWORD} e_lfanew.
         
         self._attrsList = ["e_magic","e_cblp","e_cp","e_crlc","e_cparhdr","e_minalloc","e_maxalloc","e_ss","e_sp","e_csum",\
         "e_ip","e_cs","e_lfarlc","e_ovno","e_res","e_oemid","e_oeminfo","e_res2","e_lfanew"]
         
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{DosHeader} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{DosHeader} object.
        
        @rtype: L{DosHeader}
        @return: A new L{DosHeader} object.
        """
        dosHdr = DosHeader()

        dosHdr.e_magic.value  = readDataInstance.readWord()
        dosHdr.e_cblp.value  = readDataInstance.readWord()
        dosHdr.e_cp.value  = readDataInstance.readWord()
        dosHdr.e_crlc.value  = readDataInstance.readWord()
        dosHdr.e_cparhdr.value  = readDataInstance.readWord()
        dosHdr.e_minalloc.value  = readDataInstance.readWord()
        dosHdr.e_maxalloc.value  = readDataInstance.readWord()
        dosHdr.e_ss.value  = readDataInstance.readWord()
        dosHdr.e_sp.value  = readDataInstance.readWord()
        dosHdr.e_csum.value  = readDataInstance.readWord()
        dosHdr.e_ip.value  = readDataInstance.readWord()
        dosHdr.e_cs.value  = readDataInstance.readWord()
        dosHdr.e_lfarlc.value  = readDataInstance.readWord()
        dosHdr.e_ovno.value  = readDataInstance.readWord()
        
        dosHdr.e_res = datatypes.Array(datatypes.TYPE_WORD)
        for i in range(4):
            dosHdr.e_res.append(datatypes.WORD(readDataInstance.readWord()))
            
        dosHdr.e_oemid.value  = readDataInstance.readWord()
        dosHdr.e_oeminfo.value  = readDataInstance.readWord()

        dosHdr.e_res2 = datatypes.Array(datatypes.TYPE_WORD)
        for i in range (10):
            dosHdr.e_res2.append(datatypes.WORD(readDataInstance.readWord()))
        
        dosHdr.e_lfanew.value = readDataInstance.readDword()
        return dosHdr
        
    def getType(self):
        """Returns L{consts.IMAGE_DOS_HEADER}."""
        return consts.IMAGE_DOS_HEADER
        
class NtHeaders(baseclasses.BaseStructClass):
    """NtHeaders object."""
    def __init__(self, shouldPack = True):
        """
        Class representation of the C{IMAGE_NT_HEADERS} structure.
        @see: U{http://msdn.microsoft.com/es-es/library/windows/desktop/ms680336%28v=vs.85%29.aspx}

        @type shouldPack: bool
        @param shouldPack: (Optional) If set to C{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self, shouldPack)
        
        self.signature = datatypes.DWORD(consts.PE_SIGNATURE) #: L{DWORD} signature.
        self.fileHeader = FileHeader() #: L{FileHeader} fileHeader.
        self.optionalHeader = OptionalHeader() #: L{OptionalHeader} optionalHeader.
        
    def __str__(self):
        return str(self.signature) + str(self.fileHeader) + str(self.optionalHeader)

    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{NtHeaders} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{NtHeaders} object.
        
        @rtype: L{NtHeaders}
        @return: A new L{NtHeaders} object.
        """
        nt = NtHeaders()
        nt.signature.value = readDataInstance.readDword()
        nt.fileHeader = FileHeader.parse(readDataInstance)
        nt.optionalHeader = OptionalHeader.parse(readDataInstance)
        return nt
    
    def getType(self):
        """Returns L{consts.IMAGE_NT_HEADERS}."""
        return consts.IMAGE_NT_HEADERS
        
class FileHeader(baseclasses.BaseStructClass):
    """FileHeader object."""
    def __init__(self,  shouldPack = True):
        """
        Class representation of the C{IMAGE_FILE_HEADER} structure. 
        @see: U{http://msdn.microsoft.com/es-es/library/windows/desktop/ms680313%28v=vs.85%29.aspx}

        @type shouldPack: bool
        @param shouldPack: (Optional) If set to C{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self,  shouldPack = True)
        
        self.machine = datatypes.WORD(consts.INTEL386) #: L{WORD} machine.
        self.numberOfSections = datatypes.WORD(1) #: L{WORD} numberOfSections.
        self.timeDateStamp = datatypes.DWORD(0) #: L{DWORD} timeDataStamp.
        self.pointerToSymbolTable = datatypes.DWORD(0) #: L{DWORD} pointerToSymbolTable.
        self.numberOfSymbols = datatypes.DWORD(0) #: L{DWORD} numberOfSymbols.
        self.sizeOfOptionalHeader = datatypes.WORD(0xe0) #: L{WORD} sizeOfOptionalHeader.
        self.characteristics = datatypes.WORD(consts.COMMON_CHARACTERISTICS) #: L{WORD} characteristics.
    
        self._attrsList = ["machine","numberOfSections","timeDateStamp","pointerToSymbolTable","numberOfSymbols",\
        "sizeOfOptionalHeader","characteristics"]
    
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{FileHeader} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{FileHeader} object.
        
        @rtype: L{FileHeader}
        @return: A new L{ReadData} object.
        """
        fh = FileHeader()
        fh.machine.value  = readDataInstance.readWord()
        fh.numberOfSections.value  = readDataInstance.readWord()
        fh.timeDateStamp.value  = readDataInstance.readDword()
        fh.pointerToSymbolTable.value  = readDataInstance.readDword()
        fh.numberOfSymbols.value  = readDataInstance.readDword()
        fh.sizeOfOptionalHeader.value  = readDataInstance.readWord()
        fh.characteristics.value = readDataInstance.readWord()
        return fh
        
    def getType(self):
        """Returns L{consts.IMAGE_FILE_HEADER}."""
        return consts.IMAGE_FILE_HEADER
        
class OptionalHeader(baseclasses.BaseStructClass):
    """OptionalHeader object."""
    def __init__(self,  shouldPack = True):
        """
        Class representation of the C{IMAGE_OPTIONAL_HEADER} structure.
        @see: U{http://msdn.microsoft.com/es-es/library/windows/desktop/ms680339%28v=vs.85%29.aspx}
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to C{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self, shouldPack)
        
        self.magic = datatypes.WORD(consts.PE32) #: L{WORD} magic.
        self.majorLinkerVersion = datatypes.BYTE(2) #: L{BYTE} majorLinkerVersion.
        self.minorLinkerVersion = datatypes.BYTE(0x19) #: L{BYTE} minorLinkerVersion.
        self.sizeOfCode = datatypes.DWORD(0x1000) #: L{DWORD} sizeOfCode.
        self.sizeOfInitializedData = datatypes.DWORD(0) #: L{DWORD} sizeOfInitializedData.
        self.sizeOfUninitializedData = datatypes.DWORD(0) #: L{DWORD} sizeOfUninitializedData.
        self.addressOfEntryPoint = datatypes.DWORD(0x1000) #: L{DWORD} addressOfEntryPoint.
        self.baseOfCode = datatypes.DWORD(0x1000) #: L{DWORD} baseOfCode.
        self.baseOfData = datatypes.DWORD(0x1000) #: L{DWORD} baseOfData.
        self.imageBase = datatypes.DWORD(0x400000) #: L{DWORD} imageBase.
        self.sectionAlignment = datatypes.DWORD(0x1000) #: L{DWORD} sectionAlignment.
        self.fileAlignment = datatypes.DWORD(0x200) #: L{DWORD} fileAligment.
        self.majorOperatingSystemVersion = datatypes.WORD(5) #: L{WORD} majorOperatingSystemVersion.
        self.minorOperatingSystemVersion = datatypes.WORD(0) #: L{WORD} minorOperatingSystemVersion.
        self.majorImageVersion = datatypes.WORD(6) #: L{WORD} majorImageVersion.
        self.minorImageVersion = datatypes.WORD(0) #: L{WORD} minorImageVersion.
        self.majorSubsystemVersion = datatypes.WORD(5) #: L{WORD} majorSubsystemVersion.
        self.minorSubsystemVersion = datatypes.WORD(0) #: L{WORD} minorSubsystemVersion.
        self.win32VersionValue = datatypes.DWORD(0) #: L{DWORD} win32VersionValue.
        self.sizeOfImage = datatypes.DWORD(0x2000) #: L{DWORD} sizeOfImage.
        self.sizeOfHeaders = datatypes.DWORD(0x400) #: L{DWORD} sizeOfHeaders.
        self.checksum = datatypes.DWORD(0) #: L{DWORD} checksum.
        self.subsystem = datatypes.WORD(consts.WINDOWSGUI) #: L{WORD} subsystem.
        self.dllCharacteristics = datatypes.WORD(consts.TERMINAL_SERVER_AWARE) #: L{WORD} dllCharacteristics.
        self.sizeOfStackReserve = datatypes.DWORD(0x00100000) #: L{DWORD} sizeOfStackReserve.
        self.sizeOfStackCommit = datatypes.DWORD(0x00004000) #: L{DWORD} sizeOfStackCommit.
        self.sizeOfHeapReserve = datatypes.DWORD(00100000) #: L{DWORD} sizeOfHeapReserve.
        self.sizeOfHeapCommit = datatypes.DWORD(0x1000) #: L{DWORD} sizeOfHeapCommit.
        self.loaderFlags = datatypes.DWORD(0) #: L{DWORD} loaderFlags.
        self.numberOfRvaAndSizes = datatypes.DWORD(0x10) #: L{DWORD} numberOfRvaAndSizes.
        self.dataDirectory = datadirs.DataDirectory() #: L{DataDirectory} dataDirectory.
        
        self._attrsList = ["magic","majorLinkerVersion","minorLinkerVersion","sizeOfCode","sizeOfInitializedData",\
        "sizeOfUninitializedData","addressOfEntryPoint","baseOfCode","baseOfData","imageBase","sectionAlignment",\
        "fileAlignment","majorOperatingSystemVersion","minorOperatingSystemVersion","majorImageVersion",\
        "minorImageVersion","majorSubsystemVersion","minorSubsystemVersion","win32VersionValue","sizeOfImage",\
        "sizeOfHeaders","checksum","subsystem","dllCharacteristics","sizeOfStackReserve","sizeOfStackCommit",\
        "sizeOfHeapReserve","sizeOfHeapCommit","loaderFlags","numberOfRvaAndSizes","dataDirectory"]
        
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{OptionalHeader} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{OptionalHeader} object.
        
        @rtype: L{OptionalHeader}
        @return: A new L{OptionalHeader} object.
        """
        oh = OptionalHeader()

        oh.magic.value  = readDataInstance.readWord()
        oh.majorLinkerVersion.value  = readDataInstance.readByte()
        oh.minorLinkerVersion.value  = readDataInstance.readByte()
        oh.sizeOfCode.value  = readDataInstance.readDword()
        oh.sizeOfInitializedData.value  = readDataInstance.readDword()
        oh.sizeOfUninitializedData.value  = readDataInstance.readDword()
        oh.addressOfEntryPoint.value  = readDataInstance.readDword()
        oh.baseOfCode.value  = readDataInstance.readDword()
        oh.baseOfData.value  = readDataInstance.readDword()
        oh.imageBase.value  = readDataInstance.readDword()
        oh.sectionAlignment.value  = readDataInstance.readDword()
        oh.fileAlignment.value  = readDataInstance.readDword()
        oh.majorOperatingSystemVersion.value  = readDataInstance.readWord()
        oh.minorOperatingSystemVersion.value  = readDataInstance.readWord()
        oh.majorImageVersion.value  = readDataInstance.readWord()
        oh.minorImageVersion.value  = readDataInstance.readWord()
        oh.majorSubsystemVersion.value  = readDataInstance.readWord()
        oh.minorSubsystemVersion.value  = readDataInstance.readWord()
        oh.win32VersionValue.value  = readDataInstance.readDword()
        oh.sizeOfImage.value  = readDataInstance.readDword()
        oh.sizeOfHeaders.value  = readDataInstance.readDword()
        oh.checksum.value  = readDataInstance.readDword()
        oh.subsystem.value  = readDataInstance.readWord()
        oh.dllCharacteristics.value  = readDataInstance.readWord()
        oh.sizeOfStackReserve.value  = readDataInstance.readDword()
        oh.sizeOfStackCommit.value  = readDataInstance.readDword()
        oh.sizeOfHeapReserve.value  = readDataInstance.readDword()
        oh.sizeOfHeapCommit.value  = readDataInstance.readDword()
        oh.loaderFlags.value  = readDataInstance.readDword()
        oh.numberOfRvaAndSizes.value  = readDataInstance.readDword()
        
        dirs = readDataInstance.read(consts.IMAGE_NUMBEROF_DIRECTORY_ENTRIES * 8)

        oh.dataDirectory = datadirs.DataDirectory.parse(utils.ReadData(dirs))

        return oh
    
    def getType(self):
        """Returns L{consts.IMAGE_OPTIONAL_HEADER}."""
        return consts.IMAGE_OPTIONAL_HEADER

# typedef struct _IMAGE_OPTIONAL_HEADER64 {
# WORD        Magic;
# BYTE        MajorLinkerVersion;
# BYTE        MinorLinkerVersion;
# DWORD       SizeOfCode;
# DWORD       SizeOfInitializedData;
# DWORD       SizeOfUninitializedData;
# DWORD       AddressOfEntryPoint;
# DWORD       BaseOfCode;
# ULONGLONG   ImageBase;
# DWORD       SectionAlignment;
# DWORD       FileAlignment;
# WORD        MajorOperatingSystemVersion;
# WORD        MinorOperatingSystemVersion;
# WORD        MajorImageVersion;
# WORD        MinorImageVersion;
# WORD        MajorSubsystemVersion;
# WORD        MinorSubsystemVersion;
# DWORD       Win32VersionValue;
# DWORD       SizeOfImage;
# DWORD       SizeOfHeaders;
# DWORD       CheckSum;
# WORD        Subsystem;
# WORD        DllCharacteristics;
# ULONGLONG   SizeOfStackReserve;
# ULONGLONG   SizeOfStackCommit;
# ULONGLONG   SizeOfHeapReserve;
# ULONGLONG   SizeOfHeapCommit;
# DWORD       LoaderFlags;
# DWORD       NumberOfRvaAndSizes;
# IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
# } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
class OptionalHeader64(baseclasses.BaseStructClass):
    """OptionalHeader64 object."""
    def __init__(self,  shouldPack = True):
        """
        Class representation of the C{IMAGE_OPTIONAL_HEADER64} structure. 
        @see: Remarks in U{http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339%28v=vs.85%29.aspx}

        @type shouldPack: bool
        @param shouldPack: (Optional) If set to C{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self, shouldPack)
        
        self.magic = datatypes.WORD(consts.PE32) #: L{WORD} magic.
        self.majorLinkerVersion = datatypes.BYTE(2) #: L{BYTE} majorLinkerVersion.
        self.minorLinkerVersion = datatypes.BYTE(0x19) #: L{BYTE} minorLinkerVersion.
        self.sizeOfCode = datatypes.DWORD(0x1000) #: L{DWORD} sizeOfCode.
        self.sizeOfInitializedData = datatypes.DWORD(0) #: L{DWORD} sizeOfInitializedData.
        self.sizeOfUninitializedData = datatypes.DWORD(0) #: L{DWORD} sizeOfUninitializedData.
        self.addressOfEntryPoint = datatypes.DWORD(0x1000) #: L{DWORD} addressOfEntryPoint.
        self.baseOfCode = datatypes.DWORD(0x1000) #: L{DWORD} baseOfCode.
        self.imageBase = datatypes.QWORD(0x400000) #: L{QWORD} imageBase.
        self.sectionAlignment = datatypes.DWORD(0x1000) #: L{DWORD} sectionAlignment.
        self.fileAlignment = datatypes.DWORD(0x200) #: L{DWORD} fileAligment.
        self.majorOperatingSystemVersion = datatypes.WORD(5) #: L{WORD} majorOperatingSystemVersion.
        self.minorOperatingSystemVersion = datatypes.WORD(0) #: L{WORD} minorOperatingSystemVersion.
        self.majorImageVersion = datatypes.WORD(6) #: L{WORD} majorImageVersion.
        self.minorImageVersion = datatypes.WORD(0) #: L{WORD} minorImageVersion.
        self.majorSubsystemVersion = datatypes.WORD(5) #: L{WORD} majorSubsystemVersion.
        self.minorSubsystemVersion = datatypes.WORD(0) #: L{WORD} minorSubsystemVersion.
        self.win32VersionValue = datatypes.DWORD(0) #: L{DWORD} win32VersionValue.
        self.sizeOfImage = datatypes.DWORD(0x2000) #: L{DWORD} sizeOfImage.
        self.sizeOfHeaders = datatypes.DWORD(0x400) #: L{DWORD} sizeOfHeaders.
        self.checksum = datatypes.DWORD(0) #: L{DWORD} checksum.
        self.subsystem = datatypes.WORD(consts.WINDOWSGUI) #: L{WORD} subsystem.
        self.dllCharacteristics = datatypes.WORD(consts.TERMINAL_SERVER_AWARE) #: L{WORD} dllCharacteristics.
        self.sizeOfStackReserve = datatypes.QWORD(0x00100000) #: L{QWORD} sizeOfStackReserve.
        self.sizeOfStackCommit = datatypes.QWORD(0x00004000) #: L{QWORD} sizeOfStackCommit.
        self.sizeOfHeapReserve = datatypes.QWORD(00100000) #: L{QWORD} sizeOfHeapReserve.
        self.sizeOfHeapCommit = datatypes.QWORD(0x1000) #: L{QWORD} sizeOfHeapCommit.
        self.loaderFlags = datatypes.DWORD(0) #: L{DWORD}  loaderFlags.
        self.numberOfRvaAndSizes = datatypes.DWORD(0x10) #: L{DWORD} numberOfRvaAndSizes.
        self.dataDirectory = datadirs.DataDirectory() #: L{DataDirectory} dataDirectory.
        
        self._attrsList = ["magic","majorLinkerVersion","minorLinkerVersion","sizeOfCode","sizeOfInitializedData",\
        "sizeOfUninitializedData","addressOfEntryPoint","baseOfCode", "imageBase","sectionAlignment",\
        "fileAlignment","majorOperatingSystemVersion","minorOperatingSystemVersion","majorImageVersion",\
        "minorImageVersion","majorSubsystemVersion","minorSubsystemVersion","win32VersionValue","sizeOfImage",\
        "sizeOfHeaders","checksum","subsystem","dllCharacteristics","sizeOfStackReserve","sizeOfStackCommit",\
        "sizeOfHeapReserve","sizeOfHeapCommit","loaderFlags","numberOfRvaAndSizes","dataDirectory"]
        
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{OptionalHeader64} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{OptionalHeader64} object.
        
        @rtype: L{OptionalHeader64}
        @return: A new L{OptionalHeader64} object.
        """
        oh = OptionalHeader64()

        oh.magic.value  = readDataInstance.readWord()
        oh.majorLinkerVersion.value  = readDataInstance.readByte()
        oh.minorLinkerVersion.value  = readDataInstance.readByte()
        oh.sizeOfCode.value  = readDataInstance.readDword()
        oh.sizeOfInitializedData.value  = readDataInstance.readDword()
        oh.sizeOfUninitializedData.value  = readDataInstance.readDword()
        oh.addressOfEntryPoint.value  = readDataInstance.readDword()
        oh.baseOfCode.value  = readDataInstance.readDword()
        oh.imageBase.value  = readDataInstance.readQword()
        oh.sectionAlignment.value  = readDataInstance.readDword()
        oh.fileAlignment.value  = readDataInstance.readDword()
        oh.majorOperatingSystemVersion.value  = readDataInstance.readWord()
        oh.minorOperatingSystemVersion.value  = readDataInstance.readWord()
        oh.majorImageVersion.value  = readDataInstance.readWord()
        oh.minorImageVersion.value  = readDataInstance.readWord()
        oh.majorSubsystemVersion.value  = readDataInstance.readWord()
        oh.minorSubsystemVersion.value  = readDataInstance.readWord()
        oh.win32VersionValue.value  = readDataInstance.readDword()
        oh.sizeOfImage.value  = readDataInstance.readDword()
        oh.sizeOfHeaders.value  = readDataInstance.readDword()
        oh.checksum.value  = readDataInstance.readDword()
        oh.subsystem.value  = readDataInstance.readWord()
        oh.dllCharacteristics.value  = readDataInstance.readWord()
        oh.sizeOfStackReserve.value  = readDataInstance.readQword()
        oh.sizeOfStackCommit.value  = readDataInstance.readQword()
        oh.sizeOfHeapReserve.value  = readDataInstance.readQword()
        oh.sizeOfHeapCommit.value  = readDataInstance.readQword()
        oh.loaderFlags.value  = readDataInstance.readDword()
        oh.numberOfRvaAndSizes.value  = readDataInstance.readDword()
        
        dirs = readDataInstance.read(consts.IMAGE_NUMBEROF_DIRECTORY_ENTRIES * 8)

        oh.dataDirectory = datadirs.DataDirectory.parse(utils.ReadData(dirs))

        return oh
    
    def getType(self):
        """Returns L{consts.IMAGE_OPTIONAL_HEADER64}."""
        return consts.IMAGE_OPTIONAL_HEADER64

class SectionHeader(baseclasses.BaseStructClass):
    """SectionHeader object."""
    def __init__(self,  shouldPack = True):
        """
        Class representation of the C{IMAGE_SECTION_HEADER} structure.
        @see: U{http://msdn.microsoft.com/en-us/library/windows/desktop/ms680341%28v=vs.85%29.aspx}

        @type shouldPack: bool
        @param shouldPack: (Optional) If set to C{True}, the object will be packed. If set to C{False}, the object won't be packed.
        """
        baseclasses.BaseStructClass.__init__(self,  shouldPack)
        
        self.name = datatypes.String('.travest') #: L{String} name.
        self.misc = datatypes.DWORD(0x1000) #: L{DWORD} misc. 
        self.virtualAddress = datatypes.DWORD(0x1000) #: L{DWORD} virtualAddress.
        self.sizeOfRawData = datatypes.DWORD(0x200) #: L{DWORD} sizeOfRawData.
        self.pointerToRawData = datatypes.DWORD(0x400) #: L{DWORD} pointerToRawData.
        self.pointerToRelocations = datatypes.DWORD(0) #: L{DWORD} pointerToRelocations.
        self.pointerToLineNumbers = datatypes.DWORD(0) #: L{DWORD} pointerToLineNumbers.
        self.numberOfRelocations = datatypes.WORD(0) #: L{WORD} numberOfRelocations.
        self.numberOfLinesNumbers = datatypes.WORD(0) #: L{WORD} numberOfLinesNumbers.
        self.characteristics = datatypes.DWORD(0x60000000) #: L{DWORD} characteristics.
        
        self._attrsList = ["name","misc","virtualAddress","sizeOfRawData","pointerToRawData","pointerToRelocations",\
        "pointerToLineNumbers","numberOfRelocations","numberOfLinesNumbers","characteristics"]
     
    @staticmethod
    def parse(readDataInstance):
        """
        Returns a new L{SectionHeader} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{SectionHeader} object.
        
        @rtype: L{SectionHeader}
        @return: A new L{SectionHeader} object.
        """
        sh = SectionHeader()
        sh.name.value = readDataInstance.read(8)
        sh.misc.value  = readDataInstance.readDword()
        sh.virtualAddress.value  = readDataInstance.readDword()
        sh.sizeOfRawData.value  = readDataInstance.readDword()
        sh.pointerToRawData.value  = readDataInstance.readDword()
        sh.pointerToRelocations.value  = readDataInstance.readDword()
        sh.pointerToLineNumbers.value  = readDataInstance.readDword()
        sh.numberOfRelocations.value  = readDataInstance.readWord()
        sh.numberOfLinesNumbers.value  = readDataInstance.readWord()
        sh.characteristics.value  = readDataInstance.readDword()
        return sh
        
    def getType(self):
        """Returns L{consts.IMAGE_SECTION_HEADER}."""
        return consts.IMAGE_SECTION_HEADER
        
class SectionHeaders(list):
    """SectionHeaders object."""
    def __init__(self, numberOfSectionHeaders = 1,  shouldPack = True):
        """
        Array of L{SectionHeader} objects.
        
        @type shouldPack: bool
        @param shouldPack: (Optional) If set to C{True}, the object will be packed. If set to C{False}, the object won't be packed.
        
        @type numberOfSectionHeaders: int
        @param numberOfSectionHeaders: (Optional) The number of desired section headers. By default, this parameter is set to 1.
        """
        list.__init__(self)
        
        self.shouldPack = shouldPack
        
        if numberOfSectionHeaders:
            for i in range(numberOfSectionHeaders):
                sh = SectionHeader()
                self.append(sh)
                
    def __str__(self):
        return "".join([str(x) for x in self if x.shouldPack])
        
    @staticmethod
    def parse(readDataInstance,  numberOfSectionHeaders):
        """
        Returns a new L{SectionHeaders} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{SectionHeaders} object.
        
        @type numberOfSectionHeaders: int
        @param numberOfSectionHeaders: The number of L{SectionHeader} objects in the L{SectionHeaders} instance.
        """
        sHdrs = SectionHeaders(numberOfSectionHeaders = 0)
        
        for i in range(numberOfSectionHeaders):
            sh = SectionHeader()
            
            sh.name.value = readDataInstance.read(8)
            sh.misc.value = readDataInstance.readDword()
            sh.virtualAddress.value = readDataInstance.readDword()
            sh.sizeOfRawData.value = readDataInstance.readDword()
            sh.pointerToRawData.value = readDataInstance.readDword()
            sh.pointerToRelocations.value = readDataInstance.readDword()
            sh.pointerToLineNumbers.value = readDataInstance.readDword()
            sh.numberOfRelocations.value = readDataInstance.readWord()
            sh.numberOfLinesNumbers.value = readDataInstance.readWord()
            sh.characteristics.value = readDataInstance.readDword()
        
            sHdrs.append(sh)
        
        return sHdrs
        
class Sections(list):
    """Sections object."""
    def __init__(self,  sectionHeadersInstance = None):
        """
        Array with the data of each section present in the file.
        
        @type sectionHeadersInstance: instance
        @param sectionHeadersInstance: (Optional) A L{SectionHeaders} instance to be parsed. 
        """
        list.__init__(self)
        
        if sectionHeadersInstance:
            for sh in sectionHeadersInstance:
                self.append("\xcc" * sh.sizeOfRawData.value)
                
    def __str__(self):          
        return "".join([str(data) for data in self])
        
    @staticmethod
    def parse(readDataInstance,  sectionHeadersInstance):
        """
        Returns a new L{Sections} object.
        
        @type readDataInstance: L{ReadData}
        @param readDataInstance: A L{ReadData} object with data to be parsed as a L{Sections} object.
        
        @type sectionHeadersInstance: instance
        @param sectionHeadersInstance: The L{SectionHeaders} instance with the necessary to parse every section data.
        
        @rtype: L{Sections}
        @return: A new L{Sections} object.
        """
        sData = Sections()
        
        for sectionHdr in sectionHeadersInstance:
            
            if sectionHdr.sizeOfRawData.value > len(readDataInstance.data):
                print "Warning: SizeOfRawData is larger than file."
            
            if sectionHdr.pointerToRawData.value > len(readDataInstance.data):
                print "Warning: PointerToRawData points beyond the end of the file."
            
            if sectionHdr.misc.value > 0x10000000:
                print "Warning: VirtualSize is extremely large > 256MiB."
            
            if sectionHdr.virtualAddress.value > 0x10000000:
                print "Warning: VirtualAddress is beyond 0x10000000"
            
            # skip sections with pointerToRawData == 0. According to PECOFF, it contains uninitialized data
            if sectionHdr.pointerToRawData.value:
                sData.append(readDataInstance.read(sectionHdr.sizeOfRawData.value))
        
        return sData
