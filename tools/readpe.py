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

__revision__ = "$Id$"
__author__ = "Nahuel Riva"
__contact__ = "crackinglandia@gmail.com"
__license__ = "BSD 3-Clause"

import sys
import pype32

from pype32 import utils, datatypes, consts, datadirs

from optparse import OptionParser,  OptionGroup

def showDosHeaderData(peInstance):
    """ Prints IMAGE_DOS_HEADER fields. """
    
    dosFields = peInstance.dosHeader.getFields()
    print "[+] IMAGE_DOS_HEADER values:\n"
    for field in dosFields:
        if isinstance(dosFields[field],  datatypes.Array):
            print "--> %s - Array of length %d" % (field,  len(dosFields[field]))
            counter = 0
            for element in dosFields[field]:
                print "[%d] 0x%08x" % (counter,  element.value)
                counter += 1
        else:
            print "--> %s = 0x%08x" % (field,  dosFields[field].value)

def showNtHeadersData(peInstance):
    """ Prints IMAGE_NT_HEADERS signature. """
    
    print "[+] IMAGE_NT_HEADERS signature:\n"
    print "--> NT_HEADERS signature: 0x%08x" % peInstance.ntHeaders.signature.value
    
def showFileHeaderData(peInstance):
    """ Prints IMAGE_FILE_HEADER fields. """
    
    fileHeaderFields = peInstance.ntHeaders.fileHeader.getFields()    
    print "[+] IMAGE_FILE_HEADER values:\n"
    for field in fileHeaderFields:
        print "--> %s = 0x%08x" % (field,  fileHeaderFields[field].value)

def showOptionalHeaderData(peInstance):
    """ Prints IMAGE_OPTIONAL_HEADER fields. """
    
    print "[+] IMAGE_OPTIONAL_HEADER:\n"
    ohFields = peInstance.ntHeaders.optionalHeader.getFields()
    for field in ohFields:
        if not isinstance(ohFields[field],  datadirs.DataDirectory):
            print "--> %s = 0x%08x" % (field,  ohFields[field].value)

def showDataDirectoriesData(peInstance):
    """ Prints the DATA_DIRECTORY fields. """
    
    print "[+] Data directories:\n"
    dirs = peInstance.ntHeaders.optionalHeader.dataDirectory
    counter = 1
    for dir in dirs:
        print "[%d] --> Name: %s -- RVA: 0x%08x -- SIZE: 0x%08x" % (counter,  dir.name.value,  dir.rva.value,  dir.size.value)
        counter += 1

def showSectionsHeaders(peInstance):
    """ Prints IMAGE_SECTION_HEADER for every section present in the file. """
    
    print "[+] Sections information:\n"
    print "--> NumberOfSections: %d\n" % peInstance.ntHeaders.fileHeader.numberOfSections.value
    for section in peInstance.sectionHeaders:
        fields = section.getFields()
        for field in fields:
            if isinstance(fields[field],  datatypes.String):
                fmt = "%s = %s"
            else:
                fmt = "%s = 0x%08x"
            print fmt % (field,  fields[field].value)
        print "\n"

def showImports(peInstance):
    """ Shows imports information. """
    
    iidEntries = peInstance.ntHeaders.optionalHeader.dataDirectory[consts.IMPORT_DIRECTORY].info
    if iidEntries:
        for iidEntry in iidEntries:
            fields = iidEntry.getFields()
            print "module: %s" % iidEntry.metaData.moduleName.value
            for field in fields:
                print "%s -> %x" % (field,  fields[field].value)
            
            for iatEntry in iidEntry.iat:
                fields = iatEntry.getFields()
                for field in fields:
                    print "%s - %r" % (field,  fields[field].value)
                    
            print "\n"
    else:
        print "The file does not have imported functions."

def showExports(peInstance):
    """ Show exports information """
    exports = peInstance.ntHeaders.optionalHeader.dataDirectory[consts.EXPORT_DIRECTORY].info
    if exports:
        exp_fields = exports.getFields()

        for field in exp_fields:
            print "%s -> %x" % (field,  exp_fields[field].value)
        
        for entry in exports.exportTable:
            entry_fields = entry.getFields()
            for field in entry_fields:
                print "%s -> %r" % (field,  entry_fields[field].value)    
    else:
        print "The file does not have exported functions."

def prepareOptions(parser):
    HeadersGroup = OptionGroup(parser,  "Options for PE Headers")
    DirectoriesGroup = OptionGroup(parser,  "Options for Directories")
    SectionsGroup = OptionGroup(parser,  "Options for Sections")
    AdditionalInformationGroup = OptionGroup(parser,  "Additional Options")
        
    HeadersGroup.add_option("-a",  "--headers",  dest="show_headers",  action="store_true",  default=False,  help="print all headers")
    HeadersGroup.add_option("--section-headers",  dest="show_section_headers",  action="store_true",  default=False,  help="print all section headers")
    
    DirectoriesGroup.add_option("-d",  "--directories",  dest="show_directories",  action="store_true",  default=False,  help="print data directories")
    DirectoriesGroup.add_option("-i",  "--imports",  dest="show_imports",  action="store_true",  default=False,  help="print imported functions information")
    DirectoriesGroup.add_option("-e",  "--exports",  dest="show_exports",  action="store_true",  default=False,  help="print exported functions information")

    SectionsGroup.add_option("--add-section",  dest="section_data",  help="add a section to a file. i.e. -f PE-file --add-section section-data")
    SectionsGroup.add_option("-E",  "--extend-section",  dest="multi",  action="store",  nargs=2,  help="extends a section. i.e. -E section-index section-data")

    AdditionalInformationGroup.add_option("-s",  "--signature",  dest="show_signature",  action="store_true",  default=False,  help="print digital signature (if any)")
    AdditionalInformationGroup.add_option("-o",  "--overlay",  dest="show_overlay",  action="store_true",  default=False,  help="print file overlay (if any)")
    AdditionalInformationGroup.add_option("--fast-load",  dest="fast_load",  action="store_true",  default=False,  help="loads only PE-headers when parsing file")
    
    parser.add_option_group(HeadersGroup)
    parser.add_option_group(DirectoriesGroup)
    parser.add_option_group(SectionsGroup)
    parser.add_option_group(AdditionalInformationGroup)
    
    return parser
    
def main():
    usage = "usage %prog <option> PE-file"
    
    parserInst = OptionParser(usage=usage,  version="%prog 1.0")
    
    parser = prepareOptions(parserInst)
    
    (options,  args) = parser.parse_args()
    
    if len(args) != 1:
        parser.error("incorrect number of arguments: no PE file was specified.")

    if options.fast_load:
        pe = pype32.PE(args[0],  fastLoad=True)
    else:
        pe = pype32.PE(args[0])

    if options.show_headers:
        showDosHeaderData(pe)
        print "\n"
        showNtHeadersData(pe)
        print "\n"
        showFileHeaderData(pe)
        print "\n"
        showOptionalHeaderData(pe)
        print "\n"
    elif options.show_directories:
        showDataDirectoriesData(pe)
    elif options.show_section_headers:
        showSectionsHeaders(pe)
    elif options.show_signature:
        if len(pe.signature):
            print "--> Digital signature detected. Length: %x" % len(pe.signature)
            print "--> Signature (first 0x10 bytes): %r" % pe.signature[:0x10]
    elif options.show_overlay:
        if len(pe.overlay):
            print "--> Overlay detected. Length: %x" % len(pe.overlay)
    elif options.show_imports:
        showImports(pe)
    elif options.show_exports:
        showExports(pe)
    elif options.section_data:
        pe.addSection(section_data)
    elif options.multi:
        if len(pe.sections):
            
            try:
                index = int(options.multi[0])
            except ValueError:
                raise "First parameter must be an integer!."
            
            pe.extendSection(options.multi[0],  options.multi[1])
        else:
            print "PE has no section to extend!."
    else:
        parser.print_help()
        
    
if __name__ == "__main__":
    main()
