'''
Beta Device Scanner
Give an range of IP addresses, read_holding_registers
 - device type
 - version number
 - build date
 - gateway,
 - subnet mask
 - MAC

 --update 192.168.1.253 --ip 192.168.1.252 --gw 192.168.1.1 --sn 255.255.255.0 --mac DE:AD:BE:0E:94:B6

History
2018Apr15 - created (pjc)

'''
import os
import subprocess
import argparse
from time import sleep
import re
import binascii
import itertools
import ipaddress

from pymodbus3.client.sync import ModbusTcpClient
from pymodbus3.exceptions import ConnectionException

MAX_1WIRE = 7  # maximum 1-wire temperature sensors
HR_KI_003 = 66  # device type and version info TT.MM.NN.PP
HR_KI_004 = 234  # build date in Unix EPOCH
HR_CI_006_CV = 196  # current IP address 32 bit decimal format
HR_CI_007_CV = 198  # current  gateway
HR_CI_008_CV = 200  # current subnet
HR_CI_009_CV = 202  # define current MAC

HW_CI_006_PV = 90  # pending IP decimal format
HW_CI_007_PV = 92  # pending gateway
HW_CI_008_PV = 94  # pending subnet
HW_CI_009_PV = 96  # pending MAC

HW_CY_004 = 46  # reboot device
HW_CY_006 = 59  # Update IP using bending value

HR_TI_001 = 40  # 1-wire temperatures
HR_TI_002 = 41
HR_TI_003 = 42
HR_TI_004 = 43
HR_TI_005 = 44
HR_TI_006 = 45
HR_TI_007 = 46

HR_TI_001_ID_H = 206  # 1-wire UUIDs
HR_TI_001_ID_L = 208
HR_TI_002_ID_H = 210
HR_TI_002_ID_L = 212
HR_TI_003_ID_H = 214
HR_TI_003_ID_L = 216
HR_TI_004_ID_H = 218
HR_TI_004_ID_L = 220
HR_TI_005_ID_H = 222
HR_TI_005_ID_L = 224
HR_TI_006_ID_H = 226
HR_TI_006_ID_L = 228
HR_TI_007_ID_H = 230
HR_TI_007_ID_L = 232


parser = argparse.ArgumentParser(description="Beta Remote I/O Manager")
#parser.add_argument("--scan", help="IP address or name")
parser.add_argument(
    "--scan", help="range of remote I/O IP addresses. e.g. 192.168.1.20-25")
parser.add_argument("--modbus", help="read modbus address")
parser.add_argument("--update", action="store",
                    help="--change remote I/O network settings e.g currentIP --ip newIP --gw new gateway --sn new subnet --mac new mac")

parser.add_argument("--ip", action="store",
                    help="new IP")
parser.add_argument("--gw", action="store",
                    help="new gateway")
parser.add_argument("--sn", action="store",
                    help="new subnet")
parser.add_argument("--mac", action="store",
                    help="new mac")
parser.add_argument("--wire", action="store",
                    help="1 wire config IP")

parser.add_argument("--map", action="store",
                    help="1 wire config maps")

args = parser.parse_args()


def ip_range(anIPRange):
    '''
    return an iterator that list a range of IP adddress
    from web
    '''
    octets = anIPRange.split('.')
    chunks = [list(map(int, octet.split('-'))) for octet in octets]

    ranges = [range(c[0], c[1] + 1) if len(c) == 2 else c for c in chunks]
    for address in itertools.product(*ranges):
        yield '.'.join(map(str, address))

    # print(anIPRange)
    # print(octets)
    # print(chunks)
    #print( *parsed_ranges, sep='\n')


def ping_remote(anIPAddres):
    proc = subprocess.Popen(
        ['ping', '-c', '1', anIPAddres], stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if proc.returncode == 0:
        pingStatus = 1
    else:
        pingStatus = 0
    return pingStatus


def format_modbus_ip_address(modbus_high_word, modbus_low_word):
    return(ipaddress.ip_address((modbus_high_word << 16) + modbus_low_word))


def check_ping(anIPAddress):

    response = os.system("ping -c 1 " + anIPAddress)
    if response == 0:
        pingStatus = "alive"
    else:
        pingStatus = "no response"

    return pingStatus


def format_version(aversion):
    return [aversion >> 12 & 0xf, aversion >> 8 & 0xf, aversion >> 4 & 0xf, aversion & 0xf]


def format_mac(modbus_regs):
    byte_mac = []
    res = ""
    for i in modbus_regs[1:]:
        byte_mac.append(i.to_bytes(2, byteorder='big'))
    for i in byte_mac:
        res += f"{i[0]:#0{4}x}" + " " + f"{i[1]:#0{4}x}" + " "
    return res


def device_type_name(device_type):
    if device_type == 0:
        return "GC"
    elif device_type == 1:
        return "NC"
    else:
        return "BC"


def display_remote_io(ip_address):
    '''
    display remote I/O information at the given IP address
    '''
    try:
        client = ModbusTcpClient(ip_address)
        client.write_coil(HW_CY_006, False)

        ip_holding_regs = client.read_holding_registers(HR_CI_006_CV, 6)

        client.write_registers(HW_CI_006_PV, ip_holding_regs.registers)
        cur_ip = format_modbus_ip_address(
            ip_holding_regs.registers[0], ip_holding_regs.registers[1])
        cur_gateway = format_modbus_ip_address(
            ip_holding_regs.registers[2], ip_holding_regs.registers[3])
        cur_subnet = format_modbus_ip_address(
            ip_holding_regs.registers[4], ip_holding_regs.registers[5])

        ip_holding_regs = client.read_holding_registers(HR_CI_009_CV, 4)
        cur_mac = format_mac(ip_holding_regs.registers)
        ip_holding_regs = client.read_holding_registers(HR_KI_003, 1)
        cur_version = format_version(ip_holding_regs.registers[0])

        print("{0} - {1}, version:{2}.{3}.{4} ".format(
            ip_address, device_type_name(cur_version[0]), cur_version[1], cur_version[2], cur_version[3]), end='')
        print("gateway:{0}, subnet:{1} mac:{2}".format(
            cur_gateway, cur_subnet, cur_mac))
        client.close()
    except ConnectionException:
        print("{0} - unavailable".format(ip_address))


def write_network_config(cuip, aip, agw, asn, amac):
    try:
        client = ModbusTcpClient(cuip)
        client.write_register(HW_CI_006_PV, aip >> 16)
        client.write_register(HW_CI_006_PV + 1, aip & 0xffff)
        client.write_register(HW_CI_007_PV, agw >> 16)
        client.write_register(HW_CI_007_PV + 1, agw & 0xffff)
        client.write_register(HW_CI_008_PV, asn >> 16)
        client.write_register(HW_CI_008_PV + 1, asn & 0xffff)

        client.write_register(HW_CI_009_PV, 0)
        client.write_register(HW_CI_009_PV + 1, amac >> 32)

        client.write_register(HW_CI_009_PV + 2, (amac & 0xFFFFFFFF) >> 16)
        client.write_register(HW_CI_009_PV + 3, (amac & 0xFFFFFFFF) & 0xffff)
        client.write_coil(HW_CY_006, True)
        client.close()
    except ConnectionException:
        print("{0} - unavailable".format(cuip))


if args.update:
    if args.ip and args.gw and args.sn and args.mac:
        pIP = ipaddress.ip_address(args.ip)
        pgw = ipaddress.ip_address(args.gw)
        psn = ipaddress.ip_address(args.sn)
        macbytes = binascii.unhexlify(args.mac.replace(":", ""))
        # for i in macbytes:
        #    print(hex(i))
        #print(int.from_bytes(macbytes, byteorder='big', signed=False))
        # print(int(pIP))
        #print( hex(macbytes[1]) )
        print("updating network settings at {0}...".format(args.update))
        write_network_config(args.update, int(pIP), int(pgw), int(
            psn), int.from_bytes(macbytes, byteorder='big', signed=False))
        print("waiting for reboot...")
        sleep(5)
        print("Fetching remote I/O revised network settings...")
        display_remote_io(args.ip)
    else:
        print("one of more network parameters missing")


def format_uuid(modbus_regs):
    byte_uuid = []
    res = ""
    for i in modbus_regs:
        byte_uuid.append(i.to_bytes(2, byteorder='big'))
    for i in byte_uuid:
        res += f"{i[0]:#0{4}x}" + " " + f"{i[1]:#0{4}x}" + " "
        #res += hex(i[0]) + " " + hex(i[1]) + " "
    return res

def to_signed( aunsinged):
    '''
    convert an unsigned 16bit modbus integer to a signed integer
    '''
    if aunsinged > 32677:
        return aunsinged - 65536
    else:
        return aunsinged

def get_1wire_config(ip_address):
    try:
        client = ModbusTcpClient(ip_address)

        wire_config = []
        for i in range(MAX_1WIRE):
            holding_regs = client.read_holding_registers(
                HR_TI_001_ID_H + i * 4, 4)
            cur_uuid = format_uuid(holding_regs.registers)
            holding_regs = client.read_holding_registers(HR_TI_001 + i, 1)
            wire_config.append([i,cur_uuid, i, to_signed(holding_regs.registers[0])/10.0])

        client.close()
        return wire_config
    except ConnectionException:
        print("{0} - unavailable".format(cuip))


def display_1wire_config(awire_config):
    for (idx, uuid, entry, temperature) in awire_config:
        print("idx:{0}->{1} ({2})->UUID:{3}temperature:{4}".format(
            idx, entry, idx, uuid, temperature))

if args.scan:
    print("Scanning...")
    for address in ip_range(args.scan):
        display_remote_io(address)

if args.wire:
    wire_config = get_1wire_config(args.wire)
    if args.map:
        maps = args.map.split(":")
        #print(wire_config[int(maps[0])][2])
        wire_config[int(maps[0])][2]=int(maps[1])
        wire_config[int(maps[1])][2]=int(maps[0])        
        #wire_config[maps[0][2]=maps[1]]
        display_1wire_config(wire_config)
    else:
        print("Current 1-Wire config at {0}".format(args.wire))
        display_1wire_config(wire_config)
