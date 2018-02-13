from abc import ABCMeta, abstractmethod

from impacket import ImpactPacket

from ArpInjection.addresses_helper import AddressesHelper


class PacketBuilder(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def get_arp(self, sha, spa, tha, tpa, arp_type):
        raise NotImplementedError("Should Implement get_arp")


class ImpacketPacketBuilder(PacketBuilder):
    def __init__(self, addresses_helper):
        assert isinstance(addresses_helper, AddressesHelper)
        self.addresses_helper = addresses_helper

    def get_arp(self, sha, spa, tha, tpa, arp_type):
        ethernet_layer = ImpactPacket.Ethernet()
        arp_layer = ImpactPacket.ARP()
        ethernet_layer.contains(arp_layer)
        arp_layer.set_ar_hrd(1)  # Hardware type Ethernet
        arp_layer.set_ar_pro(0x800)  # IP
        arp_layer.set_ar_op(arp_type)
        arp_layer.set_ar_hln(6)
        arp_layer.set_ar_pln(4)
        arp_layer.set_ar_sha(self.addresses_helper.get_mac_in_list_format2(sha))
        arp_layer.set_ar_spa(self.addresses_helper.get_ip_in_list_format(spa))
        arp_layer.set_ar_tha(self.addresses_helper.get_mac_in_list_format2(tha))
        arp_layer.set_ar_tpa(self.addresses_helper.get_ip_in_list_format(tpa))
        ethernet_layer.set_ether_shost(arp_layer.get_ar_sha())
        ethernet_layer.set_ether_dhost(arp_layer.get_ar_tha())
        return ethernet_layer
