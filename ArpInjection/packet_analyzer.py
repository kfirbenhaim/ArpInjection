from abc import ABCMeta, abstractproperty, abstractmethod

from impacket import ImpactDecoder
from impacket.ImpactPacket import Ethernet, ARP, IP

from ArpInjection import AddressesHelper


class PacketAnalyzer(object):
    __metaclass__ = ABCMeta

    @abstractproperty
    def dst_mac(self):
        pass

    @abstractproperty
    def src_mac(self):
        pass

    @abstractproperty
    def src_ip(self):
        pass

    @abstractproperty
    def dst_ip(self):
        pass

    @abstractmethod
    def is_arp(self):
        pass

    @abstractproperty
    def packet_bytes(self):
        pass


class PacketAnalyzerFactory():
    __metaclass__ = ABCMeta

    @abstractmethod
    def create(self, packet, use_datalink_layer=None):
        pass




# TODO: Design Liskov principle.
class ImpactPacketRepresentation(object):
    @abstractproperty
    def dst_mac(self):
        pass

    @abstractproperty
    def src_mac(self):
        pass

    @abstractproperty
    def src_ip(self):
        pass

    @abstractproperty
    def dst_ip(self):
        pass


class ImpactEthernet(ImpactPacketRepresentation):
    def __init__(self, packet):
        super(ImpactEthernet, self).__init__()
        assert isinstance(packet, Ethernet)
        self.packet = packet

    @property
    def dst_mac(self):
        return self.packet.get_ether_dhost()

    @dst_mac.setter
    def dst_mac(self, value):
        self.packet.set_ether_dhost(value)

    @property
    def src_mac(self):
        return self.packet.get_ether_shost()


class ImpactIP(ImpactPacketRepresentation):
    def __init__(self, packet):
        super(ImpactIP, self).__init__()
        assert isinstance(packet, IP)
        self.packet = packet

    @property
    def dst_ip(self):
        return self.packet.get_ip_dst()

    @property
    def src_ip(self):
        return self.packet.get_ip_src()


class ImpactArp(ImpactPacketRepresentation):
    def __init__(self, packet):
        super(ImpactArp, self).__init__()
        assert isinstance(packet, ARP)
        self.packet = packet

    @property
    def dst_mac(self):
        return self.packet.get_ar_tha()

    @dst_mac.setter
    def dst_mac(self, value):
        self.packet.set_ar_tha(value)

    @property
    def src_mac(self):
        return self.packet.get_ar_sha()

    @property
    def src_ip(self):
        return self.packet.get_ar_spa()

    @property
    def dst_ip(self):
        return self.packet.get_ar_tpa()




class ImpactPacketAnalyzerFactory(PacketAnalyzerFactory):
    def create(self, packet, use_datalink_layer=None):
        return ImpactPacketAnalyzer(packet, use_datalink_layer)





# TODO: Make all properties return general representation instead of impact representation
# TODO: For example, "10.0.0.2" instead of [10,0,0,1] for abstraction. Use addresses_helper for that.
# TODO: After that move, packet_tranferor doesn't need to know AddressesHelper class.


class ImpactPacketAnalyzer(PacketAnalyzer):
    packet_type_to_handler_class = {Ethernet: ImpactEthernet,
                                    ARP: ImpactArp,
                                    IP: ImpactIP}

    def __init__(self, packet, use_datalink_layer=None):
        # If arp packet arrives, and we are using ARPDecoder, there is a bug in impacket and the packet won't be parsed
        # well, so we'll always parse the packet's child. This solution works for this project beause we always need
        # just the layer above the ethernet layer. If you want to use Ethernet properties, please
        # use_datalink_layer=True
        # TODO: Get parameter that mention the wanted layer number instead of this patch or push bugfix to impacket.
        ethernet_decoder = ImpactDecoder.EthDecoder()
        decoded_packet = ethernet_decoder.decode(packet)
        if not use_datalink_layer:
            self.packet = decoded_packet.child()
        else:
            self.packet = decoded_packet
        if type(self.packet) not in self.packet_type_to_handler_class:
            # TODO: Write to log file.
            pass
        else:
            self.packet_type_handler = self.packet_type_to_handler_class[type(self.packet)](self.packet)
            assert (isinstance(self.packet_type_handler, ImpactPacketRepresentation))

    def is_arp(self):
        if hasattr(self.packet, "ethertype"):
            return self.packet.ethertype == 0x806
        else:
            return False

    @property
    def dst_mac(self):
        return self.packet_type_handler.dst_mac

    @dst_mac.setter
    def dst_mac(self, value):
        self.packet_type_handler.dst_mac = value

    @property
    def src_mac(self):
        return self.packet_type_handler.src_mac

    @property
    def src_ip(self):
        return self.packet_type_handler.src_ip

    @property
    def dst_ip(self):
        return self.packet_type_handler.dst_ip

    @property
    def packet_bytes(self):
        return self.packet.get_packet()

