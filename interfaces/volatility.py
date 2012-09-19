# VMware snapshot file parser
# Copyright (C) 2012 Nir Izraeli (nirizr at gmail dot com)
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

This file provides support for vmware's VMSS/VMSN file format
the VMSNParser class is used to parse the file format
while this class is used as an interface for the Volatility framework,
simple wrapping the VMSN Parser class
"""

import struct
import volatility.addrspace as addrspace
import volatility.debug as debug
import os

# the vmsn/vmss parser
import vmsn

PAGE_SIZE = 4096

class VMWareSnapshotFile(addrspace.RunBasedAddressSpace):
    """ This AS supports VMware snapshot files (*.VMSN;*.VMSS).
    It uses the vmsn Parser class for vmsn/vmss file parsing,
    and provides the read interface used by the Volatility framework"""
    order = 30
    name = "VMware Snapshot File"
    
    def __init__(self, base, config, **kwargs):
        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")

        # init base address space
        self.base = base

        # start parsing the underlying AS, hopefully it has a VMSN data structure
        try:
            self.parser = vmsn.Parser(self.base.fhandle)
        except vmsn.ParserException as e:
            # if its not a vmsn file, just fail an assert to inform this is the wrong address space
            self.as_assert(False, e)
        
        # make sure memory is embedded within the vmss/vmsn file
        #  It might also be an unsuported version,
        #  in that case please consult authors at top of file.
        self.as_assert("Memory" in self.parser["memory"],
           "Couldn't find actual memory in file. Older vmware versions saved memory in *.vmem files.")

        self.read_regions()

    def read_regions(self):
        memory = self.parser["memory"]

        # find the "regionsCount" tag, if it exists
        #  read regions one by one and create runs for them
        if "regionsCount" in memory and memory["regionsCount"].read_long() > 0:
            region_count = memory["regionsCount"].read_long()
            debug.debug("Read region count from file: " + str(region_count))

            for region_i in range(0, region_count):
                # create a new run, according to Previous Page Number, Page Number and Size
                self.assert_as(region_i in memory["regionPPN"]
                                 and region_i in memory["regionPageNum"]
                                 and region_i in memory["regionSize"],
			       "File is currept. Internal data memory region #{0} is missing.".format(region_i))

                memory_offset = memory["regionPPN"][region_i].read_long() * PAGE_SIZE
                file_offset = memory["regionPageNum"][region_i].read_long() * PAGE_SIZE
                              + memory["Memory"][0][0].data_offset
                length = memory["regionSize"][region_i].read_long()*PAGE_SIZE

                # add a new run for the current vmss region
                self.runs.append((memory_offset, file_offset, length))
        # if "regionsCount" tag is missing
        #  assume there's only one memory region, and that is contains all available memory space
        #  seen this in with several vmss files
        else:
            # create a single region according to the entire memory space.
            # the memory space begins at virtual address zero,
            # and has a size equal to the memory region's
            memory_offset = 0
            file_offset = 0 + memory["Memory"][0][0].data_offset
            length = memory["Memory"][0][0].data_size

            # add a new run for the current vmss region
            self.runs.append((memory_offset, file_offset, length))

        # print debug data regarding the regions found
        debug.debug("RegionCount: {0}".format(len(self.runs)))
        debug.debug("\n".join(map(str, self.runs)))
        
        # get the first CPU core's CR3 (CR=Control Register)
        # CR3 is used to support virtual memory and paging by the CPU.
        # there may be more than one core, but the CR3 should be equal for all cores...
        self.dtb = self.parser["cpu"]["CR"][0][3].read_long()
        debug.debug("dtb: {0:x}".format(self.dtb))

    def close(self):
        self.parser.close()
        self.base.close()
