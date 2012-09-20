# VMware snapshot file parser
# Copyright (C) 2012 Nir Izraeli (nirizr@gmail.com)
#
# DISCLAIMER:
# This script provides the ability to parse and read VMWare's file structure.
# since no documentation is available this script was written using file analysis
# and a lot of guesswork, as reverse engineering is forbidden by VMWare's End User
# Licence Agreement without permission (which i didn't bothered to ask for).
# This obviously increase the chance of mistakes in parsing. please let me know
# if there are any bugs or mismatches with current or future file format versions.
# i'll do my best to fix them.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

"""
@author:       Nir Izraeli
@license:      GNU General Public License 2.0 or later
@contact:      nirizr@gmail.com

This file parses files written in VMWare's VMSN/VMSS file format
originally written for the Volatility framework,
but designed to be used by other products/software as well.
"""

import struct
import os
import sys

# a bit ugly but allows this script to be used outside of Volatility without any changes
try:
    import volatility.debug.debug as debug
except ImportError:
    debug = lambda string: sys.stdout.write(string+"\n")

class ParserException(Exception):
    "ParserException is thrown whenever there is an error with parsing the vmsn file"
    pass

HEADER_SIZE = 12
GROUP_SIZE = 80
GROUP_NAME_SIZE = 64

class Tag():
    def __init__(self, parser, group, name, indices, data_offset, data_size, data_mem_size, compressed):
        self.parser = parser
        self.group = group
        self.name = name
        self.indices = indices
        self.data_offset = data_offset
        self.data_size = data_size
        self.data_mem_size = data_mem_size
        self.compressed = compressed

    # methods used to read the tag
    def read(self, offset = 0, size = -1):
        if size == -1:
            size = self.data_size - offset
        #print("base addr: {0:X}, paddr: {1:X}, size: {2:X}".format(self.data_offset, self.data_offset + offset, size))
        return self.parser.read(self.data_offset + offset, size)
 
    def read_offset(self):
        if self.data_size < self.parser._offset_size:
            raise TypeError("Attempt to read tag at {offset} with size {tag_size} as {read_type} {read_size}".format(offset=self.data_offset, tag_size=self.data_size, read_type="offset", read_size=self.parser._offset_size))
        return self.parser.reada_offset(self.data_offset)
    
    def read_long_long(self):
        if self.data_size < 8:
            raise TypeError("Attempt to read tag at {offset} with size {tag_size} as {read_type} {read_size}".format(offset=self.data_offset, tag_size=self.data_size, read_type="long long", read_size=8))
        return self.parser.reada_long_long(self.data_offset)
        
    def read_long(self):
        if self.data_size < 4:
            raise TypeError("Attempt to read tag at {offset} with size {tag_size} as {read_type} {read_size}".format(offset=self.data_offset, tag_size=self.data_size, read_type="long", read_size=4))
        return self.parser.reada_long(self.data_offset)
        
    def read_byte(self):
        if self.data_size < 1:
            raise TypeError("Attempt to read tag at {offset} with size {tag_size} as {read_type} {read_size}".format(offset=self.data_offset, tag_size=self.data_size, read_type="byte", read_size=1))
        return self.parser.reada_byte(self.data_offset)

    def __str__(self):
        return str(self.parent) + self.name
        
class MetaTag():
    """A metatag is what i use to implement an intermidiate array level.
    for example, when trying to access the parserObj["memory"]["Memory"][0][0] data, the following logic flow will execute:
    a. the "memory" group will be searched by a Parser obejct, and a Group object will be returned.
    b. the Group object will search for the Memory tag, and return a MetaTag object, since it has indices not yet matched.
    c. the MetaTag object will search for a tag name "Memory" with a first level index of 0. since the "Memory" tag has additional index levels another MetaTag object will be returned.
    finally the second MetaTag object will search for the "Memory" tag, with both first and second indices equal to 0. this is the last index level and an actual tag will be returned.
    
    This design was choosen because it is more readable for users of the class, as it provides a more intuitive structure.
    In addition, this structure allows to save each intermidiate point inside the tree for easier access with fewer searches."""
    def __init__(self, parser, group, name, indices):
        self.parser = parser
        self.group = group
        self.name = name
        self.indices = indices
    
    def __getitem__(self, tag_index):
        tag_data = self.group.search_tag(self.name, *(self.indices + (tag_index,)))
        if not tag_data:
            raise KeyError("{0}: tag not found. identifier should be tag data index".format(tag_index))
        
        # if we're dealling with a meta-tag
        if tag_data[0] == "MetaTag":
            return MetaTag(self.parser, self.group, *tag_data[1:])
        # or an actual tag
        if tag_data[0] == "Tag":
            return Tag(self.parser, self.group, *tag_data[1:])

    def __setitem__(self, tag_ident, value):
        raise NotImplementedError("Currently doesn't support write operations", tag_ident, value)

    def __contains__(self, tag_index):
        return not (self.group.search_tag(*(self.indices + (tag_index,))) == None)

    def __str__(self):
        return str(self.parser) + self.name
            
class Group():
    def __init__(self, parser, index, offset, name):
        # fill basic data
        self.parser = parser
        self.index = index
        self.offset = offset
        self.name = name
        
        # read additional data from file
        self.tags_offset = self.parser.reada_long_long(self.offset + GROUP_NAME_SIZE)

    def __getitem__(self, tag_ident, *tag_indices):
        debug("searching Tag: {0}{1}".format(tag_ident, tag_indices))
        tag_data = self.search_tag(tag_ident, *tag_indices)
        if not tag_data:
            raise AttributeError("{0}: tag {1} not found. identifier should be tag name".format(self.name, tag_ident))

        # if we're dealling with a meta-tag
        if tag_data[0] == "MetaTag":
            return MetaTag(self.parser, self, *tag_data[1:])
        # or an actual tag
        if tag_data[0] == "Tag":
            return Tag(self.parser, self, *tag_data[1:])

    def __contains__(self, tag_ident):
        return (self.search_tag(tag_ident) is not None)
    
    def __setitem__(self, tag_ident, value):
        raise NotImplementedError("Currently doesn't support write operations", tag_ident, value)

    ##
    ## actual parsing methods
    ##
    def search_tag(self, tag, *indices):
        # seek to the tag offset within the group structure
        self.parser.seek(self.tags_offset)

        # read first tag info
        flags = self.parser.read_byte()
        name_size = self.parser.read_byte()
        while not (flags == 0 and name_size == 0):
            # using the name size to read the tag's name
            name = self.parser.read(name_size)
            
            tag_indices_depth = (flags>>6)&0x03
            tag_indices = []
            for _ in range(0, tag_indices_depth):
                tag_indices.append(self.parser.read_long())
            
            data_size = flags&0x3f
            # these are special data sizes that signal a longer data stream...
            if data_size == 62 or data_size == 63:
                compressed = (data_size == 63)
                
                ## read real data sizes (memory and on-disk)
                data_size = self.parser.read_offset()
                data_mem_size = self.parser.read_offset()
                
                ## read unknown word. seems to always be 0x0000, perhaps structure padding?
                unkwnown = self.parser.read(2)
            else:
                data_mem_size = data_size
                compressed = False
            
            # get data offset
            data_offset = self.parser.tell()
            
            ## if its not the tag we were looking for skip the data
            self.parser.seek(data_size, os.SEEK_CUR)

            # read data for the next tag
            flags = self.parser.read_byte()
            name_size = self.parser.read_byte()
            
            # check if current tag is suitable by name
            if not name == tag:
                debug("Found Tag: {name}[{indices}] size: {size} mem size: {mem_size} compressed: {compressed}".format(name=name, indices="][".join(map(str, indices)), size=data_size, mem_size=data_mem_size, compressed=compressed))
                continue
                
            # if a complete indices match is found. for more info regarding the "MetaTag" thing, see the MetaTag class description
            #print tuple(tag_indices), indices
            if tuple(tag_indices) == indices:
                debug("Found Tag: {name}[{indices}] size: {size} mem size: {mem_size} compressed: {compressed}".format(name=name, indices="][".join(map(str, indices)), size=data_size, mem_size=data_mem_size, compressed=compressed))
                return ("Tag", name, tag_indices, data_offset, data_size, data_mem_size, compressed)

            # if indices match up to a point, we're deallnig with a meta-tag, so we havn't found an actual tag yet, but we're on our way
            if tuple(tag_indices[0:len(indices)]) == indices:
                debug("Found Meta-Tag: {name}{indices}".format(name=name, indices=tag_indices))
                return ("MetaTag", name, indices)
            else:
                debug("Tag: {name} {indexes} size: {size} mem size: {mem_size} compressed: {compressed}".format(name=name, indexes="".join(indexes), size=data_size, mem_size=data_mem_size, compressed=compressed))

    def __str__(self):
        return self.name
        
class Parser():
    """Parses vmsn/vmss VMWare produced files and provides an easy access interface.
    
    The VMSN strcuture isn't too complicated. it is basically a tree-like representing the virtual machine's properties.
    the structure is constructed from 'Groups' and 'Tags', where a group is the top level in the tree hierarchy, and represents a logical seperation
    of data. for example, one group is the "CPU" group (containing all CPU registers, state and properties) and another is the "memory" group (containing memory regions and raw memory data)
    each group has a variable number of tags. each tag is a property of the group (for example, the CR registers is a tag in the CPU group, and the RegionsCount is a property in the memory group).
    A tag can either directly contain data or have internal levels of indices, in a wat that resembles arrays. tags that has additional levels of indices, and don't contain data, are called 'MetaTags'.
    
    the vmsn file strucure begins with a simple header that contains a magic and the number of groups in file.
    """
    
    _header_size = 12
    _group_size = 80
    _group_name_size = 64
    
    def __init__(self, fh):
        if not "b" in fh.mode.lower():
            raise ValueError("Invalid file handler: file must be opened in binary mode (and not {0})".format(fh.mode))
        
        self.fh = fh
        
        ## Must start with one of the magic values
        magic = self.reada_long(0)
        debug("{0:x}".format(magic))
        
        ## Resolve version and magic
        if magic == 0xbed2bed0:
            self.version = 0
        elif magic == 0xbad1bad1:
            self.version = 1
        elif magic == 0xbed2bed2:
            self.version = 2
        elif magic == 0xbed3bed3:
            self.version = 3
        else:
            raise ParserException("Header signature invalid", magic)

        ## determine offset sizes.
        # this is used whenever the vmsn specifications use 4\8 byte ints dependant of version, so "offset" is a bit misleading.
        self.offset_size = 4 if self.version == 0 else 8
            
        ## Read group count
        self.group_count = self.reada_long(8)
        
    def __getitem__(self, group_ident):
        group_data = self.search_group(group_ident)
        if not group_data:
            raise KeyError("{0}: group not found. identifier could be either group index or name".format(group_ident))
            
        return Group(self, *group_data)

    def __contains__(self, group_ident):
        return (self.search_group(group_ident) == None)
    
    def __setitem__(self, group_ident):
        raise NotImplementedError("Currently doesn't support write operations,1")

    ##
    ## actual parsing methods
    ##
    def search_group(self, group):
        for group_index in xrange(0, self.group_count):
            ## seek to begining of the group
            self.seek(HEADER_SIZE + group_index * GROUP_SIZE)
        
            group_name = ""
            while True:
                ch = self.read(1)
                if ch == '\x00':
                    break
                    
                group_name += ch
            
            # support getting the group by both index and name
            if group_name == group or group_index == group:
                debug("found group {i}: {name}".format(name=group_name, i=group_index))
                return group_index, (HEADER_SIZE + group_index * GROUP_SIZE), group_name
    
    ##
    ## These are utilities to ease the access for the lower level file
    ## read predefined sizes in predefined formats without duplicating code..
    ## its still a bit ugly but i couldn't think of a simple yet better way to implement this
    ##
    def seek(self, addr, curr = os.SEEK_SET):
        return self.fh.seek(addr, curr)
    
    def tell(self):
        return self.fh.tell()

    def read(self, size):
        return self.fh.read(size)
        
    def reada(self, addr, size):
        """Reads from a specific address without changing the current file position
        Note: actually does change the current file position but restores it after reading. should use cation since not atomic"""
        curr = self.tell()
        
        self.seek(addr)
        data = self.read(size)
        
        self.seek(curr)
        return data
    
    def read_offset(self):
        "a few offsets` sizes are dependant of version, so this abstraction helps us read the right amount"
        string = self.read(self.offset_size)
        if self.offset_size == 4:
            (longval,) = struct.unpack('=I', string)
        elif self.offset_size == 8:
            (longval,) = struct.unpack('=Q', string)
        return longval
    
    def read_long_long(self):
        "this is used to read qword ints invariant of version"
        string = self.read(8)
        (longval,) = struct.unpack('=Q', string)
        return longval
        
    def read_long(self):
        "this is used to read qword ints invariant of version"
        string = self.read(4)
        (longval,) = struct.unpack('=I', string)
        return longval
    
    def read_byte(self):
        "this is used to read qword ints invariant of version"
        string = self.read(1)
        (val,) = struct.unpack('=B', string)
        return val

    # reada functions - read data in a specific address
    def reada_offset(self, addr):
        "a few offsets` sizes are dependant of version, so this abstraction helps us read the right amount"
        string = self.reada(addr, self.offset_size)
        if self.offset_size == 4:
            (longval,) = struct.unpack('=I', string)
        elif self.offset_size == 8:
            (longval,) = struct.unpack('=Q', string)
        return longval

    def reada_long_long(self, addr):
        "this is used to read qword ints invariant of version"
        string = self.reada(addr, 8)
        (longval,) = struct.unpack('=Q', string)
        return longval

    def reada_long(self, addr):
        "this is used to read dword ints invariant of version"
        string = self.reada(addr, 4)
        (val,) = struct.unpack('=I', string)
        return val
    
    def reada_byte(self, addr):
        "this is used to read qword ints invariant of version"
        string = self.reada(addr, 1)
        (val,) = struct.unpack('=B', string)
        return val

    def close(self):
        "just in case i'd need to close something"
        self.fh.close()
