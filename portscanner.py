#!usr/bin/python3
from unittest import result
import pyfiglet
import socket
# import threading
# import concurrent.futures
import subprocess
import colorama
import re
from colorama import Fore
from datetime import datetime
import asyncio
import xlsxwriter
import pathlib
import sys

class PortStatus:
    open = "Open"
    closed = "Closed"
class PortScannerResponse:
    def __init__(self, port, status,serviceName):
        self.port = port
        self.status = status
        self.serviceName=serviceName

    def __str__(self):
        if(self.status==PortStatus.open):
            return(Fore.WHITE + format(f"{self.port}/tcp", '25') + Fore.YELLOW +  format("Open", '25')  +  Fore.WHITE + format(f"{self.serviceName}", '25'))
        else:
            return(Fore.WHITE + format(f"{self.port}/tcp", '25') + Fore.GREEN + format("Closed", '25') )
async def scanPort(host,port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # s.settimeout(0.5)
        result = s.connect_ex((host, port))
        serviceName = "unknown";
        try:
            serviceName = socket.getservbyport(port, "tcp");
        except:
            pass
        s.close()
        if result == 0:
            return PortScannerResponse(port=port,status=PortStatus.open,serviceName=serviceName)
        else:
            return PortScannerResponse(port=port,status=PortStatus.closed,serviceName=serviceName)
    except Exception as e:
        print(e)
        return PortScannerResponse(port=port,status=PortStatus.closed)
async def scanLePorts(host,port_min,port_max):
    scanValues = await asyncio.gather(*[scanPort(host=host,port=i) for i in range(port_min, port_max + 1)])
    scanValues.sort(key=lambda x: x.port, reverse=False)
    print("\n" + format("PORT", '25') + format("State", '25') + format("Service", '25') + format("Possible Vulnerability", '25'))
    for val in scanValues:
        print(val)
    return scanValues

async def main():
    colorama.init()
    #clearing the terminal screen
    subprocess.call('cls', shell=True)

    #port scanner banner
    banner = pyfiglet.figlet_format("Port Scanner")
    print("\n" + banner + "\n")

    #checking for valid IP addreses from the user input
    validIP = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    while True:
        print(Fore.GREEN + "Please enter the IP address you want to scan in format: <xxx.xxx.xxx.xxx> (example: 192.168.148.120)" + Fore.WHITE)
        host = input("\nPlease enter the ip address that you want to scan: ")
        if validIP.search(host) and host <= "239.255.255.255":
            print(Fore.YELLOW + "\nTarget host: "+f"{host} \n" + "Host Name: " + socket.getfqdn(host) + "\n")
            break   
        else:
            print(Fore.RED + f"\n{host} is not in the range of valid ip addresses. Please try again\n")


            
        
    #checking for validity of Ports from the user input
    validPort = re.compile("([0-9]+)-([0-9]+)")
    while True:
        print(Fore.GREEN + "Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)" + Fore.WHITE)
        ports = input("\nPlease enter the port(s) that you want to scan: ")
        port_range_valid = validPort.search(ports.replace(" ",""))
        if port_range_valid:
            start_time = datetime.now()
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            if(port_min<0 or port_max>65535):
                print("Invalid Port range")
                return
            print(Fore.YELLOW + "\nTarget port(s): "+f"{ports} \n" + Fore.WHITE)
            print(Fore.BLUE +"\nScanning started at:" + str(start_time) + Fore.WHITE)
            break
    values = await scanLePorts(host=host,port_max=port_max,port_min=port_min)
    req = input("\nDo you want to export the scan to excel? Y/N: ")
    end_time = datetime.now()
    print(Fore.BLUE +"\nScanning Finished in:" ,  end_time - start_time, Fore.WHITE)
    if(req=="Y" or req=="y"):
        outputFileName = 'scan-output for ' + host + ".xlsx"
        workbook = xlsxwriter.Workbook(outputFileName)  
        worksheet = workbook.add_worksheet()
        worksheet.write(0, 0, "Port")
        worksheet.write(0, 1, "Status")
        worksheet.write(0, 2, "Service")
        # Start from the first cell. Rows and columns are zero indexed.
        row = 1
        col = 0
        for val in (values):
            worksheet.write(row, col, f"{val.port}/tcp")
            worksheet.write(row, col + 1, val.status)
            worksheet.write(row, col + 2, val.serviceName)
            row += 1
        workbook.close()
        print(Fore.BLUE + "Output saved to ",pathlib.Path().absolute(),outputFileName + Fore.WHITE)


try:
    asyncio.run(main())

except KeyboardInterrupt:
        print("\n Exiting Program !!!!")
        sys.exit()
except socket.gaierror:
        print("\n Hostname Could Not Be Resolved !!!!")
        sys.exit()
except socket.error:
        print("\ Server not responding !!!!")
        sys.exit()