#!/usr/bin/env python3
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

from scapy.all import *


class MifareSerial(Packet):
    fields_desc = [
        ByteEnumField("manufacturer", 4, {0x04: "NXP"}),
        ShortField("serial1", 0),
        ByteField("check0", 0),
        IntField("serial2", 0),
        ByteField("check1", 0)
    ]

    def i2repr(self, pkt):
        return pkt.manufacturer + pkt.serial1 + pkt.serial2
        

class MifareUltralight(Packet):
    fields_desc = [
        PacketField("mifare_serial", None, MifareSerial),
        ByteField("internal", 0),
        ShortField("lockbytes", 0),
        IntField("otp_bytes", 0)
    ]


class VingcardProtected(Packet):
    fields_desc = [
        ByteField("xor_key", 0),
        ByteField("magic", 0x90),
        ThreeBytesField("hotel_id", 0),
        ByteField("key_type", 0x82),
        IntField("key_id", 0),
        IntField("duration", 0),
        ThreeBytesField("room_id", 0),
        ByteField("unk1", 0),
        ShortField("const1", 0xFF00),
        IntField("unk2", 0)
    ]

    def pre_dissect(self, s):
        k = s[0]
        return bytes([k]) + bytes([k ^ x for x in s[1:]])

    def post_build(self, p, pay):
        k = p[0]
        return bytes([k]) + bytes([k ^ x for x in p[1:]]) + bytes([k ^ x for x in pay])


class Vingcard(Packet):
    fields_desc = [
        PacketField("mifare_ultralight", None, MifareUltralight),
        ByteField("magic", 6),
        FieldLenField("header_length", None, length_of="unknown", fmt="B"),
        FieldLenField("payload_length", None, length_of="protected_data", fmt="H"),
        StrLenField("unknown", "", length_from=lambda pkt: pkt.header_length - 4),
        PacketLenField("protected_data", None, VingcardProtected, length_from=lambda pkt: pkt.payload_length),
        ByteField("unk", 0),
        IntField("checksum", None)
    ]


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument('dump', metavar="FILE", nargs=1, type=argparse.FileType('rb'))
    args = parser.parse_args()
    try:
        pkt = Ether(args.dump[0].read())
        pkt.show2()
    except:
        print("Input file does not seem to be a valid Vingcard dump", file=sys.stderr)
    finally:
        args.dump[0].close()
    sys.exit(0)

# vim:ts=4:expandtab:sw=4
