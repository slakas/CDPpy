# Script listens to CDP packages on the selected interface
# and looking for information eg. VLAN ID, switch port number, VoiceVlan ID, platform informaion
# Get information about patch panel port number
# and save it to a csv file
# Useful for network engineers or service technicians
# author: Slawomir Kaszlikowski

import os
import re
import datetime
import sys
import socket
import fcntl
import struct
import array
import time

#Get user name
user = os.getlogin()
# Check root permitions
euid = os.geteuid()
if euid != 0:
    print "Enter sudo password: "
    args = ['sudo', sys.executable] + sys.argv + [os.environ]
    # the next line replaces the currently-running process with the sudo
    os.execlpe('sudo', *args)

#Get interfaces list
#This function found on https://gist.github.com/pklaus/289646
def all_interfaces():
    max_possible = 128  # arbitrary. raise if needed.
    bytes = max_possible * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', '\0' * bytes)
    outbytes = struct.unpack('iL', fcntl.ioctl(
        s.fileno(),
        0x8912,  # SIOCGIFCONF
        struct.pack('iL', bytes, names.buffer_info()[0])
    ))[0]
    namestr = names.tostring()
    lst = []
    for i in range(0, outbytes, 40):
        name = namestr[i:i+16].split('\0', 1)[0]
        ip   = namestr[i+20:i+24]
        lst.append((name, ip))
    return lst

def format_ip(addr):
    return str(ord(addr[0])) + '.' + \
           str(ord(addr[1])) + '.' + \
           str(ord(addr[2])) + '.' + \
           str(ord(addr[3]))


# Turn on tcpdump and listen for CDP packages. Break after (default 60 sec) or after receiving the first packet
def GetCDP(interface, time = 60):
    time = str(time)
    cmd = "timeout "+time+" tcpdump -G 5 -nn -v -i " + interface + " -s 1500 -c 1 'ether[20:2] == 0x2000'"
    lines = []
    cdp_data = []
    print('\033[95m')
    p = os.popen(cmd, "r")

    while 1:
        line = p.readline()
        lines.append(line)
        if not line: break

    # If no CDP packet was received break the function and return 0
    if lines[1] == '': return 0

    # Get port name
    line = [s for s in lines if "(0x03)" in s]
    if line:
        port = re.search("'(.*)'", line[0])
        port = port.group(1)
        cdp_data.append(port)
    else: print("Unable to find port name")

    # Get VLAN ID
    line = [s for s in lines if "(0x0a)" in s]
    if line:
        print(line)
        vlan = re.search("bytes:(.*)\n", line[0])
        vlan = "VLAN: "+vlan.group(1)
        print("\n\n \033[93m VLAN ID: \n"+vlan)
        cdp_data.append(vlan)
    else:
        print ("Unable to find vlan ID. Is it L3 port?")

    # Get VoiceVlan ID
    line = [s for s in lines if "(0x0e)" in s]
    if line:
        voiceVlan = re.search("bytes:(.*)\n", line[0])
        voiceVlan = "VOICE: "+voiceVlan.group(1)
        print(voiceVlan)
        cdp_data.append(voiceVlan)
    else:
        print ("Unable to find voice vlan")

    # Get Management IPv4 address
    line = [s for s in lines if "(0x16)" in s]
    if line:
        addIP = re.search("IPv4(.*)\n", line[0])
        addIP = "Mgmt IP: "+addIP.group(1)
        print(addIP+"\n")
        cdp_data.append(addIP)
    else: print ("Unable to find management address")

    # Get platform info
    line = [s for s in lines if "(0x06)" in s]
    if line:
        platform = re.search("'(.*)'", line[0])
        platform = platform.group(1)
        cdp_data.append(platform)
    else: print("Unable to find information about platform")
    return cdp_data


#=====================Main program=====================
#
#Clear screen
os.system('cls' if os.name == 'nt' else 'clear')
#Hello banner
print("\n")
print("=============================================================================")
print("=                                                                           =")
print("=                             CDP Sniffer                                   =")
print("=                                v 1.0                                      =")
print("=                                                                           =")
print("=              ***Simple tool for network engineers***                      =")
print("=               ******** Slawomir Kaszlikowski ******                       =")
print("=                                                                           =")
print("=============================================================================")
time.sleep(3)
os.system('cls' if os.name == 'nt' else 'clear')
print("\n")
print("#        Script listens to CDP packages on the selected interface")
print("#        and looking for information eg. VLAN ID, switch port number, VoiceVlan ID, platform informaion")
print("#        Get information about patch panel port number and save it to a csv file")
print("#        The script will aborted after 60 sec if no CDP packet was received")
print("\n")
#Get list of interfaces
ifs = all_interfaces()
j = 1

print("\nnr     name    address")
for i in ifs:
    print(str(j)+"%12s   %s" % (i[0], format_ip(i[1])))
    j = j+1

print("\n\nSelect interface number: ")
inf = raw_input()
inf = int(inf)
inf = ifs[inf-1]
inf = str(inf[0])

#Abort program if no CDP packet captured
Data = GetCDP(inf)
if Data==0:
    print("\a\n\n\033[91mNo CDP packet was received! Program aborted")
    exit()


DataOut = []
DataOutPanel = []
date = datetime.datetime.now()

# Create the csv file
thefileName = 'CDP_output_'+date.strftime('%I:%M.%d.%m')+'.csv'
thefile = open(thefileName, 'w')
thefile.write(date.strftime('%m/%d/%Y'))
thefile.close()

trueFalse = 'y'
while trueFalse == 'y':
    DataOut.append(Data)
    print('\033[93mEnter the port number on the patch panel: ')
    PortPanelNr = raw_input()
    if not PortPanelNr:
        break
    DataOutPanel.append(PortPanelNr)
    thefile = open(thefileName, 'a')
    thefile.write('\nPort on the patch panel: ,')
    thefile.write("%s" % PortPanelNr)
    thefile.writelines(", %s" % Data)
    thefile.close()
    print('\033[93mContinue? Yes (y) No (n): ')
    trueFalse = raw_input()
    if (trueFalse == 'y'): Data = GetCDP(inf)


n = len(DataOut)
i = 0
# Print the information
while i <= n - 1:
    print("\n\n\033[92mPanel: " + DataOutPanel[i])
    for CDP in DataOut[i]:
        print('    ' + CDP)

    i = i + 1
# Change the file permissions
cmd = "chmod 777 " + thefileName + "\n chown " + user + " " + thefileName
p = os.popen(cmd, "r")

