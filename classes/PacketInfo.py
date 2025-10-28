from scapy.layers.inet import IP, TCP, UDP
import psutil

flags = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'C': 'CWE',
    'E': 'ECE',
    'N': ''
}

class PacketInfo:
    """
    Collect packet metadata to generate statistical flow features
    """
    def __init__(self):
        """Initialize packet metadata extractor"""
        self.src_ip = ""
        self.dst_ip = ""
        self.src_port = 0
        self.dst_port = 0
        self.protocol = ""
        self.timestamp = 0

        self.pid = None
        self.p_name = ""
        
        self.packet_size = 0
        self.header_size = 0
        self.payload_size = 0
        self.window_size = 0
        
        self.FIN_flag = False
        self.SYN_flag = False
        self.RST_flag = False
        self.PSH_flag = False
        self.ACK_flag = False
        self.URG_flag = False
        self.CWE_flag = False
        self.ECE_flag = False

    def set_source_ip(self, packet):
        """Set source IP address"""
        self.src_ip = packet[IP].src

    def get_source_ip(self) -> str:
        return self.src_ip

    def set_destination_ip(self, packet):
        """Set destination IP address"""
        self.dst_ip = packet[IP].dst
    
    def get_destination_ip(self) -> str:
        return self.dst_ip

    def set_source_port(self, packet):
        """Set source port"""
        if packet.haslayer(TCP):
            self.src_port = packet[TCP].sport
        elif packet.haslayer(UDP):
            self.src_port = packet[UDP].sport

        if self.pid is None and self.p_name == "":
            connections = psutil.net_connections()
            for con in connections:
                if (con.laddr.port - self.src_port == 0.0) or (con.laddr.port - self.dst_port == 0.0):
                    self.pid = con.pid
                    self.p_name = psutil.Process(con.pid).name()

    def get_source_port(self) -> int:
        return self.src_port

    def set_destination_port(self, packet):
        """Set destination port"""
        if packet.haslayer(TCP):
            self.dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            self.dst_port = packet[UDP].dport
        
        if self.pid is None and self.p_name == "":
            connections = psutil.net_connections()
            for con in connections:
                if (con.laddr.port - self.src_port == 0.0) or (con.laddr.port - self.dst_port == 0.0):
                    self.pid = con.pid
                    self.p_name = psutil.Process(con.pid).name()

    def get_destination_port(self) -> int:
        return self.dst_port

    def set_protocol(self, packet):
        """Convert IANA protocol numbers to text"""
        protocol = packet[IP].proto
        if protocol == 1:
            self.protocol = "ICMP"
        elif protocol == 6:
            self.protocol = "TCP"
        elif protocol == 17:
            self.protocol = "UDP"

    def get_protocol(self) -> str:
        return self.protocol

    def set_timestamp(self, packet):
        """Set timestamp when the packet arrives"""
        self.timestamp = packet.time

    def get_timestamp(self) -> float:
        return self.timestamp

    def set_packet_size(self, packet):
        """Find the size of a packet"""
        self.packet_size = len(packet)

    def get_packet_size(self) -> int:
        return self.packet_size

    def set_header_size(self, packet):
        """Calculate header size of a packet"""
        if packet.haslayer(TCP):
            self.header_size = len(packet[TCP]) - len(packet[TCP].payload)
        elif packet.haslayer(UDP):
            self.header_size = len(packet[UDP]) - len(packet[UDP].payload)

    def get_header_size(self) -> int:
        """Get header size"""
        return self.header_size

    def set_payload_size(self, packet):
        """Extract payload size of a packet"""
        if packet.haslayer(TCP):
            self.payload_size = len(packet[TCP].payload)
        elif packet.haslayer(UDP):
            self.payload_size = len(packet[UDP].payload)

    def get_payload_size(self) -> int:
        return self.payload_size

    def set_window_size(self, packet):
        """
        Extract window size from a network packet that is given
        Packet window size - amount of data that a receiver is ready to accept in a TCP connection
        """
        if packet.haslayer(TCP):
            self.window_size = packet[0].window

    def get_window_size(self) -> int:
        return self.window_size
    
    def set_fin_flag(self, packet):
        """Determine if TCP packet has FIN flag"""
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            flag_arr = [flags[x] for x in tcp_flags]
            if 'FIN' in flag_arr:
                self.FIN_flag = True

    def get_fin_flag(self):
        return self.FIN_flag
    
    def set_syn_flag(self, packet):
        """Determine if TCP packet has SYN flag"""
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            flag_arr = [flags[x] for x in tcp_flags]
            if 'SYN' in flag_arr:
                self.SYN_flag = True

    def get_syn_flag(self):
        return self.SYN_flag
    
    def set_rst_flag(self, packet):
        """Determine if TCP packet has RST flag"""
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            flag_arr = [flags[x] for x in tcp_flags]
            if 'RST' in flag_arr:
                self.RST_flag = True

    def get_rst_flag(self):
        return self.RST_flag
    
    def set_psh_flag(self, packet):
        """Determine if TCP packet has PSH flag"""
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            flag_arr = [flags[x] for x in tcp_flags]
            if 'PSH' in flag_arr:
                self.PSH_flag = True

    def get_psh_flag(self):
        return self.PSH_flag
    
    def set_ack_flag(self, packet):
        """Determine if TCP packet has ACK flag"""
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            flag_arr = [flags[x] for x in tcp_flags]
            if 'ACK' in flag_arr:
                self.ACK_flag = True

    def get_ack_flag(self):
        return self.ACK_flag
    
    def set_urg_flag(self, packet):
        """Determine if TCP packet has URG flag"""
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            flag_arr = [flags[x] for x in tcp_flags]
            if 'URG' in flag_arr:
                self.URG_flag = True

    def get_urg_flag(self):
        return self.URG_flag
    
    def set_cwe_flag(self, packet):
        """Determine if TCP packet has CWE flag"""
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            flag_arr = [flags[x] for x in tcp_flags]
            if 'CWE' in flag_arr:
                self.CWE_flag = True

    def get_cwe_flag(self):
        return self.CWE_flag
    
    def set_ece_flag(self, packet):
        """Determine if TCP packet has ECE flag"""
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            flag_arr = [flags[x] for x in tcp_flags]
            if 'ECE' in flag_arr:
                self.ECE_flag = True

    def get_ece_flag(self):
        return self.ECE_flag

    def packet_info(self):
        """Collect packet metadata"""
        found_flags = {
            'FIN': self.get_fin_flag(),
            'SYN': self.get_syn_flag(),
            'RST': self.get_rst_flag(),
            'PSH': self.get_psh_flag(),
            'ACK': self.get_ack_flag(),
            'URG': self.get_urg_flag(),
            'CWE': self.get_cwe_flag(),
            'ECE': self.get_ece_flag(),
        }
        return self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol, self.timestamp, self.pid, self.p_name, self.packet_size, self.header_size, self.payload_size, self.window_size, found_flags

    def get_packet_key(self):
        """Get flow key from a packet"""
        return self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol
