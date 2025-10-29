import pickle
import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler
from scapy.all import *
from rich import print

from classes.PacketInfo import PacketInfo
from classes.FlowFeatures import FlowFeatures

class FlowClassifier:
    """Real-time network flow analyzer"""
    def __init__(self, classifier_path, anomaly_detector, active_timeout=60, inactive_timeout=30, inactivity_check_period=5):
        """
        Initialize flow classifier
        Args:
            classifier_path: Path to XGBoost classifier
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

        # Store flow id's
        self.flow_id_cache = {}
        self.exported_flow_count = 0

        # Load classifier
        with open(classifier_path, 'rb') as file:
            self.classifier = pickle.load(file)

        # Load anomaly detection model
        with open(anomaly_detector, 'rb') as file:
            self.detector = pickle.load(file)

        self.scaler = StandardScaler()

        self.feature_columns = [
            'Destination Port',
            'Flow Duration',
            'Total Forward Packets',
            'Total Backward Packets',
            'Total Length of Forward Packets',
            'Total Length of Backward Packets',
            'Forward Packet Length Max',
            'Forward Packet Length Min',
            'Forward Packet Length Mean',
            'Forward Packet Length Standard Deviation',
            'Backward Packet Length Max',
            'Backward Packet Length Min',
            'Backward Packet Length Mean',
            'Backward Packet Length Standard Deviation',
            'Flow Bytes/Second',
            'Flow Packets/Second',
            'Flow IAT Mean',
            'Flow IAT Standard Deviation',
            'Flow IAT Max',
            'Flow IAT Min',
            'Forward IAT Total',
            'Forward IAT Mean',
            'Forward IAT Standard Deviation',
            'Forward IAT Max',
            'Forward IAT Min',
            'Backward IAT Total',
            'Backward IAT Mean',
            'Backward IAT Standard Deviation',
            'Backward IAT Max',
            'Backward IAT Min',
            'Forward PSH Flags',
            'Backward PSH Flags',
            'Forward URG Flags',
            'Backward URG Flags',
            'Forward Header Length',
            'Backward Header Length',
            'Forward Packets/Second',
            'Backward Packets/Second',
            'Packet Length Min',
            'Packet Length Max',
            'Packet Length Mean',
            'Packet Length Standard Deviation',
            'Packet Length Variance',
            'FIN Flag Count',
            'SYN Flag Count',
            'RST Flag Count',
            'PSH Flag Count',
            'ACK Flag Count',
            'URG Flag Count',
            'CWE Flag Count',
            'ECE Flag Count',
            'Down/Up Ratio',
            'Average Packet Size',
            'Average Forward Segment Size',
            'Average Backward Segment Size'
        ]

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

    def prepare_stats(self, stats):
        """Prepare statistical data to feed into ML models"""
        stats = np.asarray(stats)
        stats = stats.reshape(-1, 1)
        stats = self.scaler.fit_transform(stats).reshape(1, -1)
        return stats

    def classify(self, stats) -> dict:
        """Classify given flow record"""
        predictions = self.classifier.predict_proba(stats).reshape(-1, 1)
        results = {attack: prob[0] for attack, prob in zip(self.attacks, predictions)}

        return results

    def detect_anomalies(self, stats) -> str:
        """Use isolation forest for anomaly detection"""
        predictions = self.detector.predict(stats)
        if predictions == 1:
            return "Normal"
        elif predictions == 0:
            return "Anomalous"
        else:
            return "Undefined"

    @staticmethod
    def print_flow_info(flow_data) -> None:
        """Pretty print flow statistics"""
        src_ip, dst_ip, src_port, dst_port, protocol = flow_data["original_flow_key"]
        print(f"[bold magenta]Flow ID:[/bold magenta] [bold yellow]{flow_data['flow_id']}[/bold yellow]")
        print(f"[bold magenta]Flow key:[/bold magenta]")
        print(f"\t[bold magenta]Source IP:[/bold magenta] {src_ip}")
        print(f"\t[bold magenta]Source port:[/bold magenta] [bold yellow]{src_port}[/bold yellow]")
        print(f"\t[bold magenta]Destination IP:[/bold magenta] {dst_ip}")
        print(f"\t[bold magenta]Destination protocol:[/bold magenta] [bold yellow]{dst_port}[/bold yellow]")
        print(f"\t[bold magenta]Protocol:[/bold magenta] [bold yellow]{protocol}[/bold yellow]")
        print(
            f"[bold magenta]Flow (normal or anomalous):[/bold magenta] [bold yellow]{flow_data["anomalies"]}[/bold yellow]")
        print(f"[bold magenta]Flow type probabilities:[/bold magenta]")
        results = flow_data['results']
        for key in results:
            print(
                f"\t[bold magenta]{key}[/bold magenta]: [bold yellow]{results[key] * 100:.5f}%[/bold yellow]")
        print(f"[bold magenta]Reason for termination:[/bold magenta] [bold yellow]{flow_data["reason"]}[/bold yellow]")
        print(f"[bold magenta]Flow statistics:[/bold magenta]")
        stats = flow_data['stats']
        for key in stats:
            print(f"\t[bold magenta]{key}[/bold magenta]: [bold yellow]{stats[key]}[/bold yellow]")

    def check_inactive_flows(self, current_timestamp) -> None:
        """Export flows that exceeded inactive timeout"""
        if current_timestamp - self.inactivity_check_time > self.inactivity_check_period:
            for flow_key in list(self.flow_cache.keys()):
                last_seen = self.flow_cache[flow_key].get_last_seen_timestamp()
                if current_timestamp - last_seen > self.inactive_timeout:
                    # Generate flow ID for the exported flow
                    self.exported_flow_count += 1
                    self.flow_id_cache[flow_key] = self.exported_flow_count

                    # Export flow statistics
                    stats = self.flow_cache[flow_key].export_flow_statistics(last_seen)
                    statistical_feature_dict = dict(zip(self.feature_columns, stats))
                    stats = self.prepare_stats(stats)

                    # Pretty print flow statistics, classification probabilities and anomaly scores
                    flow_data = {
                        "flow_id": self.flow_id_cache[flow_key],
                        "original_flow_key": self.flow_cache[flow_key].get_original_flow_key(),
                        "results": self.classify(stats),
                        "anomalies": self.detect_anomalies(stats),
                        "reason": "Inactive Timeout",
                        "stats": statistical_feature_dict
                    }
                    self.print_flow_info(flow_data)

                    # Delete flow from flow cache
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
            self.exported_flow_count += 1
            self.flow_id_cache[flow_key] = self.exported_flow_count
            stats = self.flow_cache[flow_key].export_flow_statistics(initial_timestamp)
            statistical_feature_dict = dict(zip(self.feature_columns, stats))
            stats = self.prepare_stats(stats)
            reason = "RST" if rst else "FIN"
            flow_data = {
                "flow_id": self.flow_id_cache[flow_key],
                "original_flow_key": self.flow_cache[flow_key].get_original_flow_key(),
                "results": self.classify(stats),
                "anomalies": self.detect_anomalies(stats),
                "reason": reason,
                "stats": statistical_feature_dict
            }
            self.print_flow_info(flow_data)
            del self.flow_cache[flow_key]
        elif current_timestamp - initial_timestamp > self.active_timeout:
            self.exported_flow_count += 1
            self.flow_id_cache[flow_key] = self.exported_flow_count
            stats = self.flow_cache[flow_key].export_flow_statistics(initial_timestamp)
            statistical_feature_dict = dict(zip(self.feature_columns, stats))
            stats = self.prepare_stats(stats)
            flow_data = {
                "flow_id": self.flow_id_cache[flow_key],
                "original_flow_key": self.flow_cache[flow_key].get_original_flow_key(),
                "results": self.classify(stats),
                "anomalies": self.detect_anomalies(stats),
                "reason": "Active Timeout",
                "stats": statistical_feature_dict
            }
            self.print_flow_info(flow_data)
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
