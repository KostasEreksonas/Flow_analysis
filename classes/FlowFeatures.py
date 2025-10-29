from scapy.layers.inet import TCP
import math

class FlowFeatures:
    """Compute statistical flow features from aggregated packet metadata"""
    def __init__(self, flow_key, initial_packet, timestamp):
        """
        Initialize new flow record
        
        Args:
            flow_key - flow key, sorted 5-tuple
            initial_packet - a 5-tuple information of a first packet that initializes the flow. Used to determine flow direction.
            timestamp - flow initialization timestamp
        """
        self.flow_key = flow_key
        self.src_ip = initial_packet[0]
        self.dst_ip = initial_packet[1]
        self.src_port = initial_packet[2]
        self.dst_port = initial_packet[3]
        self.protocol = initial_packet[4]
        self.timestamp_initial = timestamp
        self.timestamp = timestamp
        self.last_seen = timestamp

        self.flow_duration = 0

        self.total_fwd_packets = 0
        self.total_length_fwd_packets = 0
        self.total_length_fwd_packets_squared = 0 # Used to update standard deviation of length with each new packet
        self.fwd_packet_length_max = 0
        self.fwd_packet_length_min = 0
        self.fwd_packet_length_mean = 0.0
        self.fwd_packet_length_std = 0.0

        self.total_bwd_packets = 0
        self.total_length_bwd_packets = 0
        self.total_length_bwd_packets_squared = 0  # Used to update standard deviation of length with each new packet
        self.bwd_packet_length_max = 0
        self.bwd_packet_length_min = 0
        self.bwd_packet_length_mean = 0.0
        self.bwd_packet_length_std = 0.0

        self.flow_bytes_per_sec = 0.0
        self.flow_packets_per_sec = 0.0

        self.flow_IAT_total = 0
        self.flow_IAT_total_squared = 0 # Used to update standard deviation of IAT with each new packet
        self.flow_IAT_mean = 0.0
        self.flow_IAT_std = 0.0
        self.flow_IAT_max = 0
        self.flow_IAT_min = 0

        self.fwd_IAT_total = 0
        self.fwd_IAT_total_squared = 0  # Used to update standard deviation of IAT with each new packet
        self.fwd_IAT_mean = 0.0
        self.fwd_IAT_std = 0.0
        self.fwd_IAT_max = 0
        self.fwd_IAT_min = 0

        self.bwd_IAT_total = 0
        self.bwd_IAT_total_squared = 0  # Used to update standard deviation of IAT with each new packet
        self.bwd_IAT_mean = 0.0
        self.bwd_IAT_std = 0.0
        self.bwd_IAT_max = 0
        self.bwd_IAT_min = 0

        self.fwd_PSH_flags = 0
        self.bwd_PSH_flags = 0

        self.fwd_URG_flags = 0
        self.bwd_URG_flags = 0

        self.fwd_header_length = 0
        self.bwd_header_length = 0

        self.fwd_packets_per_second = 0
        self.bwd_packets_per_second = 0

        self.packet_length_min = 0
        self.packet_length_max = 0
        self.packet_length_mean = 0.0
        self.packet_length_std = 0.0
        self.packet_length_variance = 0.0

        self.flag_count_FIN = 0
        self.flag_count_SYN = 0
        self.flag_count_RST = 0
        self.flag_count_PSH = 0
        self.flag_count_ACK = 0
        self.flag_count_URG = 0
        self.flag_count_CWE = 0
        self.flag_count_ECE = 0

        self.down_up_ratio = 0

        self.average_packet_size = 0.0
        self.average_fwd_segment_size = 0.0
        self.average_bwd_segment_size = 0.0

    def get_original_flow_key(self) -> tuple[str, str, int, int, str]:
        """Reconstruct original (unsorted) flow key"""
        return self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol

    def calculate_packet_statistics(self, packet_key, size) -> None:
        """
        Calculate packet statistics
        """
        if self.src_ip == packet_key[0]: # Forward flow statistics
            # Forward packet count and total length
            self.total_fwd_packets += 1
            self.total_length_fwd_packets += size
            self.total_length_fwd_packets_squared += size ** 2

            # Min/max forward packet length
            if self.fwd_packet_length_max < size: self.fwd_packet_length_max = size
            if self.fwd_packet_length_min == 0 or self.fwd_packet_length_min > size: self.fwd_packet_length_min = size

            # Mean/std of forward packet length
            self.fwd_packet_length_mean = self.total_length_fwd_packets / self.total_fwd_packets
            self.fwd_packet_length_std = math.sqrt((self.total_length_fwd_packets_squared / self.total_fwd_packets) - (
                    self.total_length_fwd_packets / self.total_fwd_packets)**2)

            # Average forward segment size
            self.average_fwd_segment_size = self.total_length_fwd_packets / self.total_fwd_packets
        elif self.dst_ip == packet_key[0]: # Backward flow statistics
            # Backward packet count and total length
            self.total_bwd_packets += 1
            self.total_length_bwd_packets += size
            self.total_length_bwd_packets_squared += size ** 2

            # Min/max of backward packet length
            if self.bwd_packet_length_max < size: self.bwd_packet_length_max = size
            if self.bwd_packet_length_min == 0 or self.bwd_packet_length_min > size: self.bwd_packet_length_min = size

            # Mean/std of backward packet length
            self.bwd_packet_length_mean = self.total_length_bwd_packets / self.total_bwd_packets
            self.bwd_packet_length_std = math.sqrt((self.total_length_bwd_packets_squared / self.total_bwd_packets) - (
                        self.total_length_bwd_packets / self.total_bwd_packets) ** 2)

            # Average backward segment size
            self.average_bwd_segment_size = self.total_length_bwd_packets / self.total_bwd_packets

        # Bidirectional statistics
        total_packets = self.total_fwd_packets + self.total_bwd_packets
        total_length = self.total_length_fwd_packets + self.total_length_bwd_packets
        total_length_squared = self.total_length_fwd_packets_squared + self.total_length_bwd_packets_squared

        # Min/max of bidirectional length
        if self.packet_length_min == 0 or self.packet_length_min > size: self.packet_length_min = size
        if self.packet_length_max < size: self.packet_length_max = size

        # Mean, standard deviation and variance of bidirectional flow
        self.packet_length_mean = total_length / total_packets
        self.packet_length_std = math.sqrt((total_length_squared / total_packets) - (total_length / total_packets) ** 2)
        self.packet_length_variance = self.packet_length_std ** 2

        # Average bidirectional segment size
        self.average_packet_size = total_length / total_packets

        # Down/Up ratio
        self.down_up_ratio = 0 if self.total_fwd_packets == 0 else self.total_bwd_packets / self.total_fwd_packets

    def calculate_per_second_stats(self, timestamp) -> None:
        """Calculate flow statistics per second"""
        seconds = timestamp - self.timestamp_initial
        total_length_of_packets = self.total_length_fwd_packets + self.total_length_bwd_packets
        total_count_of_packets = self.total_fwd_packets + self.total_bwd_packets

        if seconds != 0:
            self.flow_bytes_per_sec = total_length_of_packets / seconds
            self.flow_packets_per_sec = total_count_of_packets / seconds
            self.fwd_packets_per_second = self.total_fwd_packets / seconds
            self.bwd_packets_per_second = self.total_bwd_packets / seconds

    def calculate_header_length(self, packet_key, header) -> None:
        if self.src_ip == packet_key[0]: self.fwd_header_length += header # Forward direction
        elif self.dst_ip == packet_key[0]: self.bwd_header_length += header # Backward direction

    def calculate_iat_statistics(self, packet_key, timestamp) -> None:
        """Calculate inter-arrival time (IAT) statistics for forward and backward flows"""
        iat = timestamp - self.timestamp
        total_packets = self.total_fwd_packets + self.total_bwd_packets
        self.flow_IAT_total += iat
        self.flow_IAT_total_squared += iat ** 2
        if self.flow_IAT_min == 0 or self.flow_IAT_min > timestamp: self.flow_IAT_min = timestamp
        if self.flow_IAT_max < timestamp: self.flow_IAT_max = timestamp
        self.flow_IAT_mean = self.flow_IAT_total / total_packets
        self.flow_IAT_std = math.sqrt((self.flow_IAT_total_squared / total_packets) - (self.flow_IAT_total / total_packets)**2)

        if self.src_ip == packet_key[0]: # Forward direction
            self.fwd_IAT_total += iat
            self.fwd_IAT_total_squared += iat ** 2
            if self.fwd_IAT_min == 0 or self.fwd_IAT_min > timestamp: self.fwd_IAT_min = timestamp
            if self.fwd_IAT_max < timestamp: self.fwd_IAT_max = timestamp
            self.fwd_IAT_mean = self.fwd_IAT_total / self.total_fwd_packets
            self.fwd_IAT_std = math.sqrt(
                (self.fwd_IAT_total_squared / self.total_fwd_packets) - (
                        self.fwd_IAT_total / self.total_fwd_packets) ** 2)
        elif self.dst_ip == packet_key[0]: # Backward direction
            self.bwd_IAT_total += iat
            self.bwd_IAT_total_squared += iat ** 2
            if self.bwd_IAT_min == 0 or self.bwd_IAT_min > timestamp: self.bwd_IAT_min = timestamp
            if self.bwd_IAT_max < timestamp: self.bwd_IAT_max = timestamp
            self.bwd_IAT_mean = self.bwd_IAT_total / self.total_bwd_packets
            self.bwd_IAT_std = math.sqrt(
                (self.bwd_IAT_total_squared / self.total_bwd_packets) - (
                            self.bwd_IAT_total / self.total_bwd_packets) ** 2)

        # Since IAT is measured between subsequent packets, update self timestamp with a timestamp of a current packet
        self.timestamp = timestamp

    def count_flag_statistics(self, network_packet, flags, packet_key) -> None:
        """Count tcp flags"""
        (fin, syn, rst, psh, ack, urg, cwe, ece) = flags
        if network_packet.haslayer(TCP):
            if fin:
                self.flag_count_FIN += 1
            elif syn:
                self.flag_count_SYN += 1
            elif rst:
                self.flag_count_RST += 1
            elif psh:
                self.flag_count_PSH += 1
            elif ack:
                self.flag_count_ACK += 1
            elif urg:
                self.flag_count_URG += 1
            elif cwe:
                self.flag_count_CWE += 1
            elif ece:
                self.flag_count_ECE += 1

        if self.src_ip == packet_key[0]: # Forward flow
            if psh:
                self.fwd_PSH_flags += 1
            elif urg:
                self.fwd_URG_flags += 1
        elif self.dst_ip == packet_key[0]: # Backward flow
            if psh:
                self.bwd_PSH_flags += 1
            elif urg:
                self.bwd_URG_flags += 1

    def get_initial_timestamp(self):
        """Timestamp of flow initialization"""
        return self.timestamp_initial

    def update_last_seen_timestamp(self, timestamp):
        """Update last seen timestamp"""
        self.last_seen = timestamp

    def get_last_seen_timestamp(self):
        """Timestamp when a packet was last seen"""
        return self.last_seen

    def export_flow_statistics(self, timestamp):
        """Calculate flow duration and return a tuple of flow statistics"""
        self.flow_duration = timestamp - self.timestamp_initial
        return self.dst_port, \
            self.flow_duration, \
            self.total_fwd_packets, \
            self.total_bwd_packets, \
            self.total_length_fwd_packets, \
            self.total_length_bwd_packets, \
            self.fwd_packet_length_max, \
            self.fwd_packet_length_min, \
            self.fwd_packet_length_mean, \
            self.fwd_packet_length_std, \
            self.bwd_packet_length_max, \
            self.bwd_packet_length_min, \
            self.bwd_packet_length_mean, \
            self.bwd_packet_length_std, \
            self.flow_bytes_per_sec, \
            self.flow_packets_per_sec, \
            self.flow_IAT_mean, \
            self.flow_IAT_std, \
            self.flow_IAT_max, \
            self.flow_IAT_min, \
            self.fwd_IAT_total, \
            self.fwd_IAT_mean, \
            self.fwd_IAT_std, \
            self.fwd_IAT_max, \
            self.fwd_IAT_min, \
            self.bwd_IAT_total, \
            self.bwd_IAT_mean, \
            self.bwd_IAT_std, \
            self.bwd_IAT_max, \
            self.bwd_IAT_min, \
            self.fwd_PSH_flags, \
            self.bwd_PSH_flags, \
            self.fwd_URG_flags, \
            self.bwd_URG_flags, \
            self.fwd_header_length, \
            self.bwd_header_length, \
            self.fwd_packets_per_second, \
            self.bwd_packets_per_second, \
            self.packet_length_min, \
            self.packet_length_max, \
            self.packet_length_mean, \
            self.packet_length_std, \
            self.packet_length_variance, \
            self.flag_count_FIN, \
            self.flag_count_SYN, \
            self.flag_count_RST, \
            self.flag_count_PSH, \
            self.flag_count_ACK, \
            self.flag_count_URG, \
            self.flag_count_CWE, \
            self.flag_count_ECE, \
            self.down_up_ratio, \
            self.average_packet_size, \
            self.average_fwd_segment_size, \
            self.average_bwd_segment_size
