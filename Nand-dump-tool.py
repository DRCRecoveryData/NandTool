#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#############################################################################
##                                                                         ##
## This file is proposed as is                                             ##
##                                                                         ##
##  Author: Jean-Michel Picod                                              ##
##                                                                         ##
## This program is distributed under GPLv3 licence                         ##
##                                                                         ##
#############################################################################

import sys
import os
import argparse


class NandId(object):
    _manuf = {
        0x01: "AMD / Spansion",
        0x04: "Fujitsu",
        0x07: "Renesas",
        0x20: "ST Micro / Numonyx",
        0x2c: "Micron",
        0x8f: "National Semiconductors",
        0x98: "Toshiba",
        0xad: "Hynix",
        0xc2: "Macronix",
        0xec: "Samsung",
    }

    _devid = {
        0x6e: "NAND 1MiB 5V 8-bit",
        0x64: "NAND 2MiB 5V 8-bit",
        0x6b: "NAND 4MiB 5V 8-bit",
        0xe8: "NAND 1MiB 3,3V 8-bit",
        0xec: "NAND 1MiB 3,3V 8-bit",
        0xea: "NAND 2MiB 3,3V 8-bit",
        0xd5: "NAND 4MiB 3,3V 8-bit",
        0xe3: "NAND 4MiB 3,3V 8-bit",
        0xe5: "NAND 4MiB 3,3V 8-bit",
        0xd6: "NAND 8MiB 3,3V 8-bit",
        0x39: "NAND 8MiB 1,8V 8-bit",
        0xe6: "NAND 8MiB 3,3V 8-bit",
        0x33: "NAND 16MiB 1,8V 8-bit",
        0x73: "NAND 16MiB 3,3V 8-bit",
        0x35: "NAND 32MiB 1,8V 8-bit",
        0x75: "NAND 32MiB 3,3V 8-bit",
        0x36: "NAND 64MiB 1,8V 8-bit",
        0x76: "NAND 64MiB 3,3V 8-bit",
        0x78: "NAND 128MiB 1,8V 8-bit",
        0x39: "NAND 128MiB 1,8V 8-bit",
        0x79: "NAND 128MiB 3,3V 8-bit",
        0x71: "NAND 256MiB 3,3V 8-bit",
        0xa2: "NAND 64MiB 1,8V 8-bit",
        0xa0: "NAND 64MiB 1,8V 8-bit",
        0xf2: "NAND 64MiB 3,3V 8-bit",
        0xd0: "NAND 64MiB 3,3V 8-bit",
        0xf0: "NAND 64MiB 3,3V 8-bit",
        0xa1: "NAND 128MiB 1,8V 8-bit",
        0xf1: "NAND 128MiB 3,3V 8-bit",
        0xd1: "NAND 128MiB 3,3V 8-bit",
        0xaa: "NAND 256MiB 1,8V 8-bit",
        0xda: "NAND 256MiB 3,3V 8-bit",
        0xac: "NAND 512MiB 1,8V 8-bit",
        0xdc: "NAND 512MiB 3,3V 8-bit",
        0xa3: "NAND 1GiB 1,8V 8-bit",
        0xd3: "NAND 1GiB 3,3V 8-bit",
        0xa5: "NAND 2GiB 1,8V 8-bit",
        0xd5: "NAND 2GiB 3,3V 8-bit",
        0xa7: "NAND 4GiB 1,8V 8-bit",
        0xd7: "NAND 4GiB 3,3V 8-bit",
        0xae: "NAND 8GiB 1,8V 8-bit",
        0xde: "NAND 8GiB 3,3V 8-bit",
        0x1a: "NAND 16GiB 1,8V 8-bit",
        0x3a: "NAND 16GiB 3,3V 8-bit",
        0x1c: "NAND 32GiB 1,8V 8-bit",
        0x3c: "NAND 32GiB 3,3V 8-bit",
        0x1e: "NAND 64GiB 1,8V 8-bit",
        0x3e: "NAND 64GiB 3,3V 8-bit",
    }

    _serial_access_time = {
        0: 50e-9,
        1: 30e-9,
        2: 25e-9,
        3: None,
    }

    def __init__(self, idcode):
        if isinstance(idcode, str) or isinstance(idcode, unicode):
            idcode = int(idcode, 16)
        self.idcode = idcode
        self.manufId = 0xff & (idcode >> 24)
        self.deviceId = 0xff & (idcode >> 16)
        third = 0xff & (idcode >> 8)
        self.die = 2 ** (third & 0x3)
        self.cell = 2 ** (1 + ((third >> 2) & 0x3))
        self.prog_pages = 2 ** ((third >> 4) & 0x3)
        self.interleave = bool((third >> 6) & 1)
        self.write_cache = bool((third >> 7) & 1)
        fourth = 0xff & idcode
        self.page_size = 2 ** (10 + (fourth & 0x3))
        self.spare_size = 2 ** (fourth & 0x4)
        self._sat = ((fourth >> 6)  & 2) + ((fourth >> 3) & 1)
        self.block_size = 2 ** (16 + ((fourth >> 4) & 3))
        self.organization = 2 ** (4 + (1 & (fourth >> 6)))

    @property
    def manufStr(self):
        return self._manuf[self.manufId] if self.manufId in self._manuf else "Unknown (%02x)" % self.manufId

    @property
    def serial_access_time(self):
        return ("%d ns" % (1e9 * self._serial_access_time[self._sat])) or "Reserved"

    @property
    def oob_size(self):
        return self.spare_size * self.page_size / 512

    @property
    def deviceStr(self):
        return self._devid[self.deviceId] if self.deviceId in self._devid else "Unknown (0x%02x)" % self.deviceId

    def __repr__(self):
        rv = []
        rv.append("ID code                          : %08x" % self.idcode)
        rv.append("Manufacturer                     : %s" % self.manufStr)
        rv.append("Device                           : %s" % self.deviceStr)
        rv.append("Die/Package                      : %d" % self.die)
        rv.append("Cell type                        : %d Level Cell" % self.cell)
        rv.append("Simultaneously programmed paged  : %d" % self.prog_pages)
        rv.append("Interleave between multiple chips: %s" % self.interleave)
        rv.append("Write cache                      : %s" % self.write_cache)
        rv.append("Page size                        : %d bytes (%d K)" % (self.page_size, self.page_size / 1024))
        rv.append("Spare area size                  : %d bytes / 512 byte" % self.spare_size)
        rv.append("Block size                       : %d bytes (%d K)" % (self.block_size, self.block_size / 1024))
        rv.append("Organization                     : X%d" % self.organization)
        rv.append("Serial access time               : %s" % self.serial_access_time)
        rv.append("OOB size                         : %d bytes" % self.oob_size)
        return os.linesep.join(rv)


def prettify(val):
    _suffix = [ 'B', 'KB', 'MB', 'GB', 'TB' ]
    suffix = 0
    small = val
    while small > 1024:
        small /= 1024.0
        suffix += 1
    return (val, round(small, 2), _suffix[suffix])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(sys.argv[0])
    parser.add_argument("-i", "--input", metavar="FILE", type=argparse.FileType('rb'), required=True, dest="finput")
    parser.add_argument("-o", "--output", metavar="FILE", type=argparse.FileType('wb'), required=True, dest="foutput")
    parser.add_argument("-I", "--idcode", metavar="ID", default=None, dest="idcode", type=NandId)
    parser.add_argument("--page-size", type=int, default=None, dest="page")
    parser.add_argument("--oob-size", type=int, default=None, dest="oob")
    parser.add_argument("--extract-oob", metavar="FILE", type=argparse.FileType('wb'), default=None, dest="oobfile")

    args = parser.parse_args(sys.argv[1:])
    if args.idcode is not None and (args.page is not None or args.oob is not None):
        print >> sys.stderr, "You cannot specify an idcode and page/oob size at the same time"
        sys.exit(1)

    if args.idcode is None and (args.page is None or args.oob is None):
        print >> sys.stderr, "You must specify either idcode or both page and oob sizes"
        sys.exit(2)

    if args.idcode is not None:
        print ""
        print "Using given ID code"
        print repr(args.idcode)
        args.page = args.idcode.page_size
        args.oob = args.idcode.oob_size
    else:
        print "Using given parameters: page of %d bytes separated by %d bytes OOB data" % (args.page, args.oob)

    cnt = { 'data': 0, 'oob': 0 }
    while True:
        data = args.finput.read(args.page)
        cnt['data'] += len(data)
        args.foutput.write(data)
        oob = args.finput.read(args.oob)
        cnt['oob'] += len(oob)
        if oob == "":
            break
        if args.oobfile is not None:
            args.oobfile.write(oob)
    args.finput.close()
    args.foutput.close()
    if args.oobfile is not None:
        args.oobfile.close()
    print ""
    print "Status:"
    print "\tTotal: %d bytes (%.02f %s)" % prettify(cnt['data'] + cnt['oob'])
    print "\tData : %d bytes (%.02f %s)" % prettify(cnt['data'])
    print "\tOOB  : %d bytes (%.02f %s)" % prettify(cnt['oob'])
    sys.exit(0)

# vim:ts=4:expandtab:sw=4

