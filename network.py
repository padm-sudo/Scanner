#Library
from tabnanny import verbose
import psutil
from netaddr import IPNetwork

# Network Interface Info
def networkInterface():
    #
    interfaces = []
    print("="*40, "Network Information", "="*40)
    # get all network interfaces (virtual and physical)
    if_addrs = psutil.net_if_addrs()
    interfacesDict={}
    for interface_name, interface_addresses in if_addrs.items():
        for address in interface_addresses:
            if str(address.family) == 'AddressFamily.AF_INET':  
                interfaces.append(interface_name)          
                interfacesDict[interface_name]=[address.address,address.netmask,address.broadcast]
    
    print("\nNetwork Interfaces:\n")   
    i=1 
    for key in interfacesDict:
        print("(",i,")",key)
        i+=1
    option = input("\nSelect the interface:")
    print(chr(27) + "[2J")
    return option, interfacesDict,interfaces

#List Network Interface info:
def networkInfo():
    option,interfaceDict,interfaces = networkInterface()
    
    for i in range(len(interfaces)):
        if int(option)-1 == i:
            print(interfaces[i],"Selected.\n")
            print("HOST IP: ",interfaceDict[interfaces[i]][0])
            #store IP Address
            ip = interfaceDict[interfaces[i]][0]
            #Convert IP to bites
            ip2bin =  ".".join(map(str,["{0:08b}".format(int(x)) for x in ip.split(".")]))
            print("HOST MASK: ",interfaceDict[interfaces[i]][1])
            #store Network Mask
            mask = interfaceDict[interfaces[i]][1]
            #Convert MASK to bites
            mask2bin =  ".".join(map(str,["{0:08b}".format(int(x)) for x in mask.split(".")]))
            #Network bytes
            mask2bin.count('1')
    networkAddress = str(IPNetwork(ip+'/'+mask).cidr)         
    print ("Network Address: "+networkAddress)     
                 
    scanNetworkEquipment(networkAddress)

def scanNetworkEquipment(networkAddress):
    import ipaddress
    import scapy.all as scapy
   
    IPlist=[]
    
    
    for ip in ipaddress.IPv4Network(networkAddress):
        IPlist.append(ip)
    
    print("First IP:",IPlist.pop(0))
    print("Last IP:",IPlist.pop())
    print("\n")
    
    arp_packet = scapy.ARP(pdst = str(networkAddress))
    broadcast_packet = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet/arp_packet
    answerd_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    client_list = []   
    for element in answerd_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)

    for client in client_list:
        print("Live IP:",client["ip"] + "\t\t" + "MAC:",client["mac"])
    print("\n")
        
def main():
    networkInfo()

# Main Code
if __name__=="__main__":
    main()