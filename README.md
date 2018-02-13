# ArpInjection
This system injects arp replys to both attacked sides, and transfers the data of both sides via attacker's computer. Implements Man In The Middle attack.
Run the system by running the main.py file.
I used impacket for parsing and pcap for communicating with the network interface card, but there is a nice abstraction, 
so you can change the implementation modules via the main.py file.
