import pickle
import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler
from scapy.all import *

from classes.PacketInfo import PacketInfo
from classes.FlowFeatures import FlowFeatures

class FlowClassifier:
    """Real-time network flow analyzer"""
    def __init__(self, model_path, socketio, active_timeout=60, inactive_timeout=30, inactivity_check_period=5):
        """
        Initialize flow classifier
        Args:
            model_path: Path to XGBoost classifier
            socketio: Flask-SocketIO instance for emitting events
            active_timeout: Maximum flow duration before export (seconds)
            inactive_timeout: Maximum inactive period before export (seconds)
            inactivity_check_period: How often check for inactive flows (seconds)
        """
        self.flow_cache = {}
        self.active_timeout = active_timeout
        self.inactive_timeout = inactive_timeout
        self.inactivity_check_period = inactivity_check_period
        self.inactivity_check_time = time.time()
        self.socketio = socketio

        # Load classifier
        with open(model_path, 'rb') as file:
            self.model = pickle.load(file)

        self.scaler = StandardScaler()

        self.attacks = [
        'Benign',
        'Bot',
        'DDoS',
        'DoS Goldeneye',
        'DoS Hulk',
        'DoS Slowhttptest',
        'DoS Slowloris',
        'FTP-Patator',
        'Heartbleed',
        'Infiltration',
        'SSH-Patator',
        'Brute Force',
        'SQL Injection',
        'XSS'
        ]

    @staticmethod
    def sort_key(key) -> tuple[str, str, int, int, str]:
        """Normalize 5-tuple by sorting IP addresses and ports"""
        src_ip, dst_ip, src_port, dst_port, protocol = key

        src = (src_ip, src_port)
        dst = (dst_ip, dst_port)

        if src < dst:
            return src[0], dst[0], src[1], dst[1], protocol
        else:
            return dst[0], src[0], dst[1], src[1], protocol

    def classify(self, original_flow_key, stats) -> tuple[str, str, int, int, str, dict]:
        """Classify given flow record"""
        (src_ip, dst_ip, src_port, dst_port, protocol) = original_flow_key

        stats = np.asarray(stats)
        stats = stats.reshape(-1, 1)
        stats = self.scaler.fit_transform(stats).reshape(1, -1)

        predictions = self.model.predict_proba(stats).reshape(-1, 1)
        results = {attack: prob[0] for attack, prob in zip(self.attacks, predictions)}

        return src_ip, src_port, dst_ip, dst_port, protocol, results

    def check_inactive_flows(self, current_timestamp) -> None:
        """Export flows that exceeded inactive timeout"""
        if current_timestamp - self.inactivity_check_time > self.inactivity_check_period:
            for flow_key in list(self.flow_cache.keys()):
                last_seen = self.flow_cache[flow_key].get_last_seen_timestamp()
                if current_timestamp - last_seen > self.inactive_timeout:
                    stats = self.flow_cache[flow_key].export_flow_statistics()
                    original_flow_key = self.flow_cache[flow_key].get_original_flow_key()
                    flow_data = {
                        "results": self.classify(original_flow_key, stats),
                        "reason": "Inactive Timeout"
                    }
                    self.emit_flow_record(flow_data)
                    #print(f"{flow_data["results"]}, Reason: {flow_data["reason"]}")
                    del self.flow_cache[flow_key]

            self.inactivity_check_time = current_timestamp

    def update_flow_stats(self, flow_key, packet_key, packet_size, current_timestamp, header_size, network_packet, flags) -> None:
        """Update flow statistics with new packet metadata"""
        self.flow_cache[flow_key].calculate_packet_statistics(packet_key, packet_size)
        self.flow_cache[flow_key].calculate_per_second_stats(current_timestamp)
        self.flow_cache[flow_key].calculate_header_length(packet_key, header_size)
        self.flow_cache[flow_key].calculate_iat_statistics(packet_key, current_timestamp)
        self.flow_cache[flow_key].count_flag_statistics(network_packet, flags, packet_key)

    def process_existing_flow(self, flow_key, packet_key, packet_size, current_timestamp, header_size, network_packet, flags, rst, fin) -> None:
        """Update existing flow or export if terminated/expired"""
        initial_timestamp = self.flow_cache[flow_key].get_initial_timestamp()

        # Update flow statistics
        self.update_flow_stats(flow_key, packet_key, packet_size, current_timestamp, header_size, network_packet, flags)

        # Check for TCP RST/FIN flags for TCP flow termination
        if rst or fin:
            stats = self.flow_cache[flow_key].export_flow_statistics()
            reason = "RST" if rst else "FIN"
            flow_data = {
                "results": self.classify(packet_key, stats),
                "reason": reason
            }
            self.emit_flow_record(flow_data)
            #print(f"{flow_data["results"]}, Reason: {flow_data["reason"]}")
            del self.flow_cache[flow_key]
        elif current_timestamp - initial_timestamp > self.active_timeout:
            stats = self.flow_cache[flow_key].export_flow_statistics()
            flow_data = {
                "results": self.classify(packet_key, stats),
                "reason": "Active Timeout"
            }
            self.emit_flow_record(flow_data)
            #print(f"{flow_data["results"]}, Reason: {flow_data["reason"]}")
            del self.flow_cache[flow_key]

            # Initialize new flow in place of expired one and update stats based on first packet
            self.initialize_flow(flow_key, packet_key, packet_size, current_timestamp, header_size, network_packet, flags)
        else:
            self.flow_cache[flow_key].update_last_seen_timestamp(current_timestamp)

    def initialize_flow(self, flow_key, packet_key, packet_size, current_timestamp, header_size, network_packet, flags) -> None:
        """Create new flow record and initialize statistics with the metadata of first packet"""
        self.flow_cache[flow_key] = FlowFeatures(flow_key, packet_key, current_timestamp)
        self.update_flow_stats(flow_key, packet_key, packet_size, current_timestamp, header_size, network_packet, flags)

    def process_packet(self, network_packet) -> None:
        """Process individual packet and update network flow statistics"""
        if not network_packet.haslayer(IP):
            return

        # Extract packet info
        p = PacketInfo()
        p.set_source_ip(network_packet)
        p.set_destination_ip(network_packet)
        p.set_source_port(network_packet)
        p.set_destination_port(network_packet)
        p.set_protocol(network_packet)
        p.set_timestamp(network_packet)
        p.set_packet_size(network_packet)
        p.set_header_size(network_packet)
        p.set_payload_size(network_packet)
        p.set_window_size(network_packet)
        p.set_fin_flag(network_packet)
        p.set_syn_flag(network_packet)
        p.set_rst_flag(network_packet)
        p.set_psh_flag(network_packet)
        p.set_ack_flag(network_packet)
        p.set_urg_flag(network_packet)
        p.set_cwe_flag(network_packet)
        p.set_ece_flag(network_packet)

        current_timestamp = p.get_timestamp()

        # Collect flags to count found flags in a flow
        flags = (p.get_fin_flag(),
            p.get_syn_flag(),
            p.get_rst_flag(),
            p.get_psh_flag(),
            p.get_ack_flag(),
            p.get_urg_flag(),
            p.get_cwe_flag(),
            p.get_ece_flag())

        # Get RST and FIN flags for TCP flow termination
        fin = p.get_fin_flag()
        rst = p.get_rst_flag()

        # Current packet data needed to update flow statistics
        packet_size = p.get_packet_size()
        header_size = p.get_header_size()

        # Get flow key
        packet_key = p.get_packet_key()
        flow_key = self.sort_key(packet_key)

        # Periodically check and export inactive flows
        self.check_inactive_flows(current_timestamp)

        if flow_key in self.flow_cache.keys():
            self.process_existing_flow(flow_key, packet_key, packet_size, current_timestamp, header_size, network_packet, flags, rst, fin)
        else:
            # Initialize new flow record (if no flow record with a given key exists) and update statistics based on first packet
            self.initialize_flow(flow_key, packet_key, packet_size, current_timestamp, header_size, network_packet, flags)

    def start_capture(self, interface=None, packet_filter="ip"):
        sniff(iface=interface, filter=packet_filter, prn=self.process_packet, store=False)

    def emit_flow_record(self, flow_data):
        """Emit new flow records for the fronted to capture"""
        self.socketio.emit('flow', flow_data, namespace='/flows')
