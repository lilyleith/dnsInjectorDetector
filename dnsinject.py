import sys
from scapy.all import sniff
from scapy.layers.dns import DNS, DNSQR
import psutil

# helper function to check if the interface name provided by the user is valid
def valid_interface(interface_name):
    # pull the list of network interfaces
    interfaces = psutil.net_if_addrs()

    # if the interface is valid return 1
    if interface_name in interfaces:
        return 1
    # else return 0
    return 0

# helper function to inspect the packet
# this will be called in the sniff command in main
def inspect_packet(packet):
    # filter by DNS packets
    if packet.hasLayer(DNS) and packet.getlayer(DNS).qr == 0:
        dns_query = packet[DNSQR].qname.decode('utf-8')
        print(f"DNS Request for: {dns_query}")


if __name__ == '__main__':

    # number of command line arguments
    num_args = len(sys.argv)
    
    # check that the number of arguments passed does not exceed 5
    # exit if it does
    if num_args > 5:
        print("Invalid number of command line arguments.")
        print("Usage: python3 dnsinject.py")
        print("With optional flags [-i <interface>] and [-h <hostnames]")
        exit(0)
    
    # variables for the hostnames file and the interface name
    hostnames = ""
    interface = "eth0"

    # go through the command line arguments and check their validity
    i = 1
    while i < num_args:
        # if interface flag
        if sys.argv[i] == "-i":
            # if there is no argument after the -i flag then print error message and exit
            if i + 1 == num_args:
                print("No network device interface specified after -i.")
                print("Please specify a network device after -i or remove the -i flag for a default network device.")
                exit(0)
            interface = sys.argv[i + 1]
            # check that following argument is a valid interface, exit if not
            if (valid_interface(interface) != 1):
                print("Invalid network devide interface provided. Please provide a valid interface name.")
                exit(0)
            # if valid, skip to the argument after the interface name
            i += 2
        # if the h flag is present
        elif sys.argv[i] == "-h":
            # if there is no argument after the -h flag, then print error message and exit
            if i + 1 == num_args:
                print("No hostname file specified after -h.")
                print("Please specify a hostname file after -h or remove the -h flag for a default response IP.")
                exit(0)
            hostnames = sys.argv[i + 1]
            # try to open the specified file in read only mode
            # if the file DNE, then except the FileNotFound error and exit the program 
            # with an error message
            # if it opens, skip to the argument after the file name
            try:
                with open(hostnames, 'r') as file:
                    i += 2
            except FileNotFoundError:
                print(f"The file '{hostnames}' does not exist.")
                print("Please provide a valid hostnames file or remove the -h flag for a default response IP.")
                exit(1)
        else:
            print("Invalid construction of command line arguments.")
            print("Usage: python3 dnsinject.py")
            print("With optional flags [-i <interface>] and [-h <hostnames]")
            exit(0)

    # sniff packets on port 53 used for udp dns packets
    # send the packets to inspect_packet function for inspection and filtering
    sniff(filter = "udp port 53", iface = interface, prn = inspect_packet, store = 0)
    exit(0)