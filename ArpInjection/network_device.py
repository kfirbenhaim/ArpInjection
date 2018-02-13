from abc import ABCMeta

import pcapy


class NetworkDevice(object):
    __metaclass__ = ABCMeta

    def send_packet(self, packet):
        raise NotImplementedError("Should implement send_packet")

    def receive_packet(self):
        raise NotImplementedError("Should implement receive_packet")


class PcapyNetworkDevice(NetworkDevice):
    def __init__(self, device_name, timeout_for_receive_packet):
        # 65536 is the maximum value for packet length
        self.device = pcapy.open_live(device_name, 65536, 0, timeout_for_receive_packet)

    def receive_packet(self):
        return self.device.next()[1]

    def send_packet(self, packet):
        self.device.sendpacket(packet)
