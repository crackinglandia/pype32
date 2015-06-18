#!/usr/bin/env python
# -*- coding: utf-8 -*- 

# Copyright (c) 2015, Sandor Nemes
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

import sys

import datatypes
import caching

class StringHeapIndex(object):

    def __init__(self, dt, streams):
        self.dt = dt
        self.streams = streams
        self.offset = 0
        self.value = None

    def getString(self, offset):
        funcname = sys._getframe().f_code.co_name
        cache = caching.getCache(funcname)
        result = cache.get(offset)
        if result is not None: return result

        for i in self.streams["#Strings"].info:
            cache.put(*i.iteritems().next())

        return cache.get(offset)

    def parse(self, readDataInstance):
        if self.dt.netMetaDataTableHeader.heapOffsetSizes.value & 0x1:
            self.offset = datatypes.DWORD(readDataInstance.readDword()).value
        else:
            self.offset = datatypes.WORD(readDataInstance.readWord()).value
        self.value = self.getString(self.offset)
        return self

class GuidHeapIndex(object):

    def __init__(self, dt, streams):
        self.dt = dt
        self.streams = streams
        self.offset = 0
        self.value = None

    def getGuid(self, offset):
        funcname = sys._getframe().f_code.co_name
        cache = caching.getCache(funcname)
        result = cache.get(offset)
        if result is not None: return result

        for i in self.streams["#GUID"].info:
            cache.put(*i.iteritems().next())

        return cache.get(offset)

    def parse(self, readDataInstance):
        if self.dt.netMetaDataTableHeader.heapOffsetSizes.value & 0x2:
            self.offset = datatypes.DWORD(readDataInstance.readDword()).value
        else:
            self.offset = datatypes.WORD(readDataInstance.readWord()).value
        self.value = self.getGuid(16*(self.offset-1))
        return self

class BlobHeapIndex(object):

    def __init__(self, dt, streams):
        self.dt = dt
        self.streams = streams
        self.offset = 0
        self.value = None

    def getBlob(self, offset):
        funcname = sys._getframe().f_code.co_name
        cache = caching.getCache(funcname)
        result = cache.get(offset)
        if result is not None: return result

        for i in self.streams["#Blob"].info:
            cache.put(*i.iteritems().next())

        return cache.get(offset)

    def parse(self, readDataInstance):
        if self.dt.netMetaDataTableHeader.heapOffsetSizes.value & 0x4:
            self.offset = datatypes.DWORD(readDataInstance.readDword()).value
        else:
            self.offset = datatypes.WORD(readDataInstance.readWord()).value
        self.value = self.getBlob(self.offset)
        return self


class MultiTableIndex(object):

    refs = None

    def __init__(self, dt=None, streams=None):
        if not self.refs: raise NotImplementedError
        self.dt = dt
        self.streams = streams
        self.value = None
        self.hash = "{0:x}".format(hash(self.refs))

    @staticmethod
    def getBits(value):
        funcname = sys._getframe().f_code.co_name
        cache = caching.getCache(funcname)
        bits = cache.get(value)
        if bits is not None: return bits

        bits = 0
        tmp = value - 1
        while tmp > 0:
            bits += 1
            tmp >>= 1

        cache.put(value, bits)
        return bits

    def dwordIndex(self):
        funcname = sys._getframe().f_code.co_name
        cache = caching.getCache(funcname)
        result = cache.get(self.hash)
        if result is not None: return result

        largestTable = max(self.dt.tables[_]["rows"] for _ in self.refs if _ != "Not used")
        result = self.getBits(largestTable) > 16 - self.getBits(len(self.refs))

        cache.put(self.hash, result)
        return result

    def decodeValue(self, value):
        funcname = sys._getframe().f_code.co_name
        cache = caching.getCache(funcname + "#" + self.hash)
        result = cache.get(value)
        if result is not None: return result

        bits = self.getBits(len(self.refs))
        result = (self.refs[value & (1 << bits)-1], value >> bits)

        cache.put(value, result)
        return result

    def parse(self, readDataInstance):
        if self.dwordIndex():
            self.value = self.decodeValue(datatypes.DWORD(readDataInstance.readDword()).value)
        else:
            self.value = self.decodeValue(datatypes.WORD(readDataInstance.readWord()).value)
        return self


class TypeDefOrRefIndex(MultiTableIndex):
    refs = (
        "TypeDef",
        "TypeRef",
        "TypeSpec"
    )

class HasConstantIndex(MultiTableIndex):
    refs = (
        "Field",
        "Param",
        "Property"
    )

class HasCustomAttributeIndex(MultiTableIndex):
    refs = (
        "MethodDef",
        "Field",
        "TypeRef",
        "TypeDef",
        "Param",
        "InterfaceImpl",
        "MemberRef",
        "Module",
        "Permission",
        "Property",
        "Event",
        "StandAloneSig",
        "ModuleRef",
        "TypeSpec",
        "Assembly",
        "AssemblyRef",
        "File",
        "ExportedType",
        "ManifestResource",
    )


class HasFieldMarshallIndex(MultiTableIndex):
    refs = (
        "Field",
        "Param",
    )


class HasDeclSecurityIndex(MultiTableIndex):
    refs = (
        "TypeDef",
        "MethodDef",
        "Assembly",
    )


class MemberRefParentIndex(MultiTableIndex):
    refs = (
        "TypeDef",
        "TypeRef",
        "ModuleRef",
        "MethodDef",
        "TypeSpec",
    )


class HasSemanticsIndex(MultiTableIndex):
    refs = (
        "Event",
        "Property",
    )


class MethodDefOrRefIndex(MultiTableIndex):
    refs = (
        "MethodDef",
        "MemberRef",
    )


class MemberForwardedIndex(MultiTableIndex):
    refs = (
        "Field",
        "MethodDef",
    )


class ImplementationIndex(MultiTableIndex):
    refs = (
        "File",
        "AssemblyRef",
        "ExportedType",
    )


class CustomAttributeTypeIndex(MultiTableIndex):
    refs = (
        "Not used",
        "Not used",
        "MethodDef",
        "MemberRef",
        "Not used"
    )


class ResolutionScopeIndex(MultiTableIndex):
    refs = (
        "Module",
        "ModuleRef",
        "AssemblyRef",
        "TypeRef"
    )


class TypeOrMethodDefIndex(MultiTableIndex):
    refs = (
        "TypeDef",
        "MethodDef",
    )


class FieldIndex(MultiTableIndex):
    refs = (
        "Field",
    )


class MethodDefIndex(MultiTableIndex):
    refs = (
        "MethodDef",
    )


class ParamIndex(MultiTableIndex):
    refs = (
        "Param",
    )


class TypeDefIndex(MultiTableIndex):
    refs = (
        "TypeDef",
    )


class EventIndex(MultiTableIndex):
    refs = (
        "Event",
    )


class PropertyIndex(MultiTableIndex):
    refs = (
        "Property",
    )


class ModuleRefIndex(MultiTableIndex):
    refs = (
        "ModuleRef",
    )


class AssemblyRefIndex(MultiTableIndex):
    refs = (
        "AssemblyRef",
    )


class GenericParamIndex(MultiTableIndex):
    refs = (
        "GenericParam",
    )


MetadataTableNames = {
    0x00: "Module",
    0x01: "TypeRef",
    0x02: "TypeDef",
    0x03: "FieldPtr",
    0x04: "Field",
    0x05: "MethodPtr",
    0x06: "MethodDef",
    0x07: "ParamPtr",
    0x08: "Param",
    0x09: "InterfaceImpl",
    0x0a: "MemberRef",
    0x0b: "Constant",
    0x0c: "CustomAttribute",
    0x0d: "FieldMarshal",
    0x0e: "Permission", # DeclSecurity
    0x0f: "ClassLayout",
    0x10: "FieldLayout",
    0x11: "StandAloneSig",
    0x12: "EventMap",
    0x13: "EventPtr",
    0x14: "Event",
    0x15: "PropertyMap",
    0x16: "PropertyPtr",
    0x17: "Property",
    0x18: "MethodSemantics",
    0x19: "MethodImpl",
    0x1a: "ModuleRef",
    0x1b: "TypeSpec",
    0x1c: "ImplMap",
    0x1d: "FieldRVA",
    0x1e: None,
    0x1f: None,
    0x20: "Assembly",
    0x21: "AssemblyProcessor",
    0x22: "AssemblyOS",
    0x23: "AssemblyRef",
    0x24: "AssemblyRefProcessor",
    0x25: "AssemblyRefOS",
    0x26: "File",
    0x27: "ExportedType",
    0x28: "ManifestResource",
    0x29: "NestedClass",
    0x2a: "GenericParam",
    0x2b: "MethodSpec",
    0x2c: "GenericParamConstraint",
    0x2d: None,
    0x2e: None,
    0x2f: None,
    0x30: None,
    0x31: None,
    0x32: None,
    0x33: None,
    0x34: None,
    0x35: None,
    0x36: None,
    0x37: None,
    0x38: None,
    0x39: None,
    0x3a: None,
    0x3b: None,
    0x3c: None,
    0x3d: None,
    0x3e: None,
    0x3f: None,
}


def MetadataTableDefinitions(dt, netMetaDataStreams):
    return {
        0x00: [
            { "generation": datatypes.WORD() },
            { "name": StringHeapIndex(dt, netMetaDataStreams) },
            { "mvId": GuidHeapIndex(dt, netMetaDataStreams) },
            { "encId": GuidHeapIndex(dt, netMetaDataStreams) },
            { "encBaseId": GuidHeapIndex(dt, netMetaDataStreams) },
        ],
        0x01: [
            { "resolutionScope": ResolutionScopeIndex(dt, netMetaDataStreams) },
            { "typeName": StringHeapIndex(dt, netMetaDataStreams) },
            { "typeNamespace": StringHeapIndex(dt, netMetaDataStreams) },
        ],
        0x02: [
            { "flags": datatypes.DWORD() },
            { "typeName": StringHeapIndex(dt, netMetaDataStreams) },
            { "typeNamespace": StringHeapIndex(dt, netMetaDataStreams) },
            { "extends": TypeDefOrRefIndex(dt, netMetaDataStreams) },
            { "fieldList": FieldIndex(dt, netMetaDataStreams) },
            { "methodList": MethodDefIndex(dt, netMetaDataStreams) },
        ],
        0x03: [
            { "ref": datatypes.WORD() },
        ],
        0x04: [
            { "flags": datatypes.WORD() },
            { "name": StringHeapIndex(dt, netMetaDataStreams) },
            { "signature": BlobHeapIndex(dt, netMetaDataStreams) },
        ],
        0x05: [
            { "ref": datatypes.WORD() },
        ],
        0x06: [
            { "rva": datatypes.DWORD() },
            { "implFlags": datatypes.WORD() },
            { "flags": datatypes.WORD() },
            { "name": StringHeapIndex(dt, netMetaDataStreams) },
            { "signature": BlobHeapIndex(dt, netMetaDataStreams) },
            { "paramList": ParamIndex(dt, netMetaDataStreams) },
        ],
        0x07: [
            { "ref": datatypes.WORD() },
        ],
        0x08: [
            { "flags": datatypes.WORD() },
            { "sequence": datatypes.WORD() },
            { "name": StringHeapIndex(dt, netMetaDataStreams) },
        ],
        0x09: [
            { "class": TypeDefIndex(dt, netMetaDataStreams) },
            { "interface": TypeDefOrRefIndex(dt, netMetaDataStreams) },
        ],
        0x0a: [
            { "class": MemberRefParentIndex(dt, netMetaDataStreams) },
            { "name": StringHeapIndex(dt, netMetaDataStreams) },
            { "signature": BlobHeapIndex(dt, netMetaDataStreams) },
        ],
        0x0b: [
            { "type": datatypes.WORD() },
            { "parent": HasConstantIndex(dt, netMetaDataStreams) },
            { "value": BlobHeapIndex(dt, netMetaDataStreams) },
        ],
        0x0c: [
            { "parent": HasCustomAttributeIndex(dt, netMetaDataStreams) },
            { "type": CustomAttributeTypeIndex(dt, netMetaDataStreams) },
            { "value": BlobHeapIndex(dt, netMetaDataStreams) },
        ],
        0x0d: [
            { "parent": HasFieldMarshallIndex(dt, netMetaDataStreams) },
            { "nativeType": BlobHeapIndex(dt, netMetaDataStreams) },
        ],
        0x0e: [
            { "action": datatypes.WORD() },
            { "parent": HasDeclSecurityIndex(dt, netMetaDataStreams) },
            { "permissionSet": BlobHeapIndex(dt, netMetaDataStreams) },
        ],
        0x0f: [
            { "packingSize": datatypes.WORD() },
            { "classSize": datatypes.DWORD() },
            { "parent": TypeDefIndex(dt, netMetaDataStreams) },
        ],
        0x10: [
            { "offset": datatypes.DWORD() },
            { "field": FieldIndex(dt, netMetaDataStreams) },
        ],
        0x11: [
            { "signature": BlobHeapIndex(dt, netMetaDataStreams) },
        ],
        0x12: [
            { "parent": TypeDefIndex(dt, netMetaDataStreams) },
            { "eventList": EventIndex(dt, netMetaDataStreams) },
        ],
        0x13: [
            { "ref": datatypes.WORD() },
        ],
        0x14: [
            { "eventFlags": datatypes.WORD() },
            { "name": StringHeapIndex(dt, netMetaDataStreams) },
            { "eventType": TypeDefOrRefIndex(dt, netMetaDataStreams) },
        ],
        0x15: [
            { "parent": TypeDefIndex(dt, netMetaDataStreams) },
            { "propertyList": PropertyIndex(dt, netMetaDataStreams) },
        ],
        0x16: [
            { "ref": datatypes.WORD() },
        ],
        0x17: [
            { "flags": datatypes.WORD() },
            { "name": StringHeapIndex(dt, netMetaDataStreams) },
            { "type": BlobHeapIndex(dt, netMetaDataStreams) },
        ],
        0x18: [
            { "semantics": datatypes.WORD() },
            { "method": MethodDefIndex(dt, netMetaDataStreams) },
            { "association": HasSemanticsIndex(dt, netMetaDataStreams) },
        ],
        0x19: [
            { "class": TypeDefIndex(dt, netMetaDataStreams) },
            { "methodBody": MethodDefOrRefIndex(dt, netMetaDataStreams) },
            { "methodDeclaration": MethodDefOrRefIndex(dt, netMetaDataStreams) },
        ],
        0x1a: [
            { "name": StringHeapIndex(dt, netMetaDataStreams) },
        ],
        0x1b: [
            { "signature": BlobHeapIndex(dt, netMetaDataStreams) },
        ],
        0x1c: [
            { "mappingFlags": datatypes.WORD() },
            { "memberForwarded": MemberForwardedIndex(dt, netMetaDataStreams) },
            { "importName": StringHeapIndex(dt, netMetaDataStreams) },
            { "importScope": ModuleRefIndex(dt, netMetaDataStreams) },
        ],
        0x1d: [
            { "rva": datatypes.DWORD() },
            { "field": FieldIndex(dt, netMetaDataStreams) },
        ],
        0x1e: None,
        0x1f: None,
        0x20: [
            { "hashAlgId": datatypes.DWORD() },
            { "majorVersion": datatypes.WORD() },
            { "minorVersion": datatypes.WORD() },
            { "buildNumber": datatypes.WORD() },
            { "revisionNumber": datatypes.WORD() },
            { "flags": datatypes.DWORD() },
            { "publicKey": BlobHeapIndex(dt, netMetaDataStreams) },
            { "name": StringHeapIndex(dt, netMetaDataStreams) },
            { "culture": StringHeapIndex(dt, netMetaDataStreams) },
        ],
        0x21: [
            { "processor": datatypes.DWORD() },
        ],
        0x22: [
            { "osPlatformId": datatypes.DWORD() },
            { "osMajorVersion": datatypes.DWORD() },
            { "osMinorVersion": datatypes.DWORD() },
        ],
        0x23: [
            { "majorVersion": datatypes.WORD() },
            { "minorVersion": datatypes.WORD() },
            { "buildNumber": datatypes.WORD() },
            { "revisionNumber": datatypes.WORD() },
            { "flags": datatypes.DWORD() },
            { "publicKeyOrToken": BlobHeapIndex(dt, netMetaDataStreams) },
            { "name": StringHeapIndex(dt, netMetaDataStreams) },
            { "culture": StringHeapIndex(dt, netMetaDataStreams) },
            { "hashValue": BlobHeapIndex(dt, netMetaDataStreams) },
        ],
        0x24: [
            { "processor": datatypes.DWORD() },
            { "assemblyRef": AssemblyRefIndex(dt, netMetaDataStreams) },
        ],
        0x25: [
            { "osPlatformId": datatypes.DWORD() },
            { "osMajorVersion": datatypes.DWORD() },
            { "osMinorVersion": datatypes.DWORD() },
            { "assemblyRef": AssemblyRefIndex(dt, netMetaDataStreams) },
        ],
        0x26: [
            { "flags": datatypes.DWORD() },
            { "name": StringHeapIndex(dt, netMetaDataStreams) },
            { "hashValue": BlobHeapIndex(dt, netMetaDataStreams) },
        ],
        0x27: [
            { "flags": datatypes.DWORD() },
            { "typeDefId": datatypes.DWORD() },
            { "typeName": StringHeapIndex(dt, netMetaDataStreams) },
            { "typeNamespace": StringHeapIndex(dt, netMetaDataStreams) },
            { "implementation": ImplementationIndex(dt, netMetaDataStreams) },
        ],
        0x28: [
            { "offset": datatypes.DWORD() },
            { "flags": datatypes.DWORD() },
            { "name": StringHeapIndex(dt, netMetaDataStreams) },
            { "implementation": ImplementationIndex(dt, netMetaDataStreams) },
        ],
        0x29: [
            { "nestedClass": TypeDefIndex(dt, netMetaDataStreams) },
            { "enclosingClass": TypeDefIndex(dt, netMetaDataStreams) },
        ],
        0x2a: [
            { "number": datatypes.WORD() },
            { "flags": datatypes.WORD() },
            { "owner": TypeOrMethodDefIndex(dt, netMetaDataStreams) },
            { "name": StringHeapIndex(dt, netMetaDataStreams) },
        ],
        0x2b: [
            { "method": MethodDefOrRefIndex(dt, netMetaDataStreams) },
            { "instantiation": BlobHeapIndex(dt, netMetaDataStreams) },
        ],
        0x2c: [
            { "owner": GenericParamIndex(dt, netMetaDataStreams) },
            { "constraint": TypeDefOrRefIndex(dt, netMetaDataStreams) },
        ],
        0x2d: None,
        0x2e: None,
        0x2f: None,
        0x30: None,
        0x31: None,
        0x32: None,
        0x33: None,
        0x34: None,
        0x35: None,
        0x36: None,
        0x37: None,
        0x38: None,
        0x39: None,
        0x3a: None,
        0x3b: None,
        0x3c: None,
        0x3d: None,
        0x3e: None,
        0x3f: None,
    }
