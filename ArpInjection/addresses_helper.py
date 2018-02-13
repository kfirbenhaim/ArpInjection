#TODO: Abstraction
class AddressesHelper(object):
    BROADCAST = "ff:ff:ff:ff:ff:ff"

    @staticmethod
    def get_mac_in_list_format(mac):
        assert isinstance(mac, basestring)
        return [int(mac[i] + mac[i + 1], 16) for i in range(len(mac)) if i % 2 == 0]

    @staticmethod
    def get_mac_in_list_format2(mac):
        assert isinstance(mac, basestring)
        return [int(i, 16) for i in mac.split(":")]


    @staticmethod
    def get_ip_in_list_format(ip):
        assert isinstance(ip, basestring)
        return [int(i) for i in ip.split(".")]

