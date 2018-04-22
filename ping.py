'''
Beta Device Scanner
Give an range of IP addresses, read_holding_registers
 - device type
 - version number
 - build date
 - gateway,
 - subnet mask
 - MAC


History
2018Apr15 - created (pjc)

'''
import os
import subprocess
import argparse
import re
import binascii
import itertools
import ipaddress

from pymodbus3.client.sync import ModbusTcpClient
from pymodbus3.exceptions import ConnectionException

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


parser = argparse.ArgumentParser(description="Beta Remote I/O Manager")
#parser.add_argument("--scan", help="IP address or name")
parser.add_argument("--scan", help="range of addresses. e.g. 192.168.1.20-25")
parser.add_argument("--modbus", help="read modbus address")
parser.add_argument("--update", action="store",
                    help="change network parameters")

parser.add_argument("--ip", action="store",
                    help="new IP")
parser.add_argument("--gw", action="store",
                    help="new gateway")
parser.add_argument("--sn", action="store",
                    help="new subnet")
parser.add_argument("--mac", action="store",
                    help="new mac")





def ip_range(anIPRange):
    '''
    return an iterator that list a range of IP adddress
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


#print( check_ping("192.168.1.253"))
args = parser.parse_args()
print(args)
#print( check_ping(args.scan))
if args.scan:
    print(ping_remote(args.scan))
#print( check_ping(args.scan))

# if args.scan:
#    for address in ip_range(args.range):
#        print("Beta Device @ {0} status: {status}".format(
#            address, status="active" if ping_remote(address) == 1 else "unavailable"))

# ip_range("192.168.1.1-20")


def format_version(aversion):
    return [aversion >> 12 & 0xf, aversion >> 8 & 0xf, aversion >> 4 & 0xf, aversion & 0xf]


def format_mac(modbus_regs):
    byte_mac = []
    res = ""
    for i in modbus_regs[1:]:
        byte_mac.append(i.to_bytes(2, byteorder='big'))
    for i in byte_mac:
        res += hex(i[0]) + " " + hex(i[1]) + " "
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
#client.write_registers(HW_CI_009_PV, ip_holding_regs.registers)


#client = ModbusTcpClient('192.168.1.253')
#client.write_coil(11, True)
#result = client.read_coils(11,1)
#print( result.bits)
# client.close()

if args.update:
    if args.ip and args.gw and args.sn and args.mac:
        pIP = ipaddress.ip_address( args.ip)
        pgw = ipaddress.ip_address( args.gw)
        psn = ipaddress.ip_address( args.sn)
        macbytes = binascii.unhexlify(args.mac.replace(":",""))
        for i in macbytes:
            print(hex(i))
        print( int.from_bytes( macbytes, byteorder = 'big',signed=False))
        #print( hex(macbytes[1]) )
        display_remote_io( args.update)
        print("ready to update")
    else:
        print("need IP")



if args.scan:
    for address in ip_range(args.scan):
        display_remote_io(address)
    # if args.write:
    #    print("writing IP")
    #    pending_ip = 3232236028
    #    client.write_register(HW_CI_006_PV, pending_ip >> 16)
    #    client.write_register(HW_CI_006_PV + 1, pending_ip & 0xffff)
    #    ip_holding_regs = client.read_holding_registers(HW_CI_009_PV, 4)
    #    cur_mac = format_mac(ip_holding_regs.registers)
    ##    print( "MAC written:{0}".format(cur_mac))
    #client.write_coil(HW_CY_006, False )
