"""Py-NetMon: A Python-based Network Monitoring Tool

Author: Isaiah River
Class: CSI-260-01
Assignment: Final Project
Due Date: April 28th, 2024
Certification of Authenticity:
I certify that this is entirely my own work, except where I have given
fully-documented references to the work of others. I understand the definition
and consequences of plagiarism and acknowledge that the assessor of this
assignment may, for the purpose of assessing this assignment:
- Reproduce this assignment and provide a copy to another member of academic
- staff; and/or Communicate a copy of this assignment to a plagiarism checking
- service (which may then retain a copy of this assignment on its database for
- the purpose of future plagiarism checking)
"""

import os
import json
import threading
import socket
import logging
import csv
from colorama import Fore
from scapy.all import *
from plyer import notification
from scapy.layers.inet import IP, TCP

colorama.init(autoreset=True)


class OutputHandler:
    """
    Base class for output handling.
    """

    def __init__(self, output_format='csv'):
        self.output_format = None
        self.set_output_format(output_format)
        self.output_string = "detected_packets"

    def set_output_format(self, format):
        self.output_format = format

    def get_output_format(self):
        return self.output_format

    def set_output_string(self, output_string):
        self.output_string = output_string

    @staticmethod
    def print_saved_message(output_file):
        print(Fore.GREEN + f"Detected packets saved to {output_file}")


class CSVOutputHandler(OutputHandler):
    """
    Output handler for saving packets to CSV format.
    """

    def save(self, detected_packets):
        output_file = f"{self.output_string}.csv"

        with open(output_file, "w", newline="") as csvfile:
            fieldnames = ["Source", "Destination", "DestinationURL", "Protocol", "PacketType"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            rows = [
                {field: packet[field] for field in fieldnames}
                for packet in detected_packets
            ]

            writer.writerows(rows)

        self.print_saved_message(output_file)


class JSONOutputHandler(OutputHandler):
    """
    Output handler for saving packets to JSON format.
    """

    def save(self, detected_packets):
        output_file = f"{self.output_string}.json"

        with open(output_file, "w") as jsonfile:
            packets_data = [
                {
                    "Source": packet["Source"],
                    "Destination": packet["Destination"],
                    "DestinationURL": packet["DestinationURL"],
                    "Protocol": packet["Protocol"],
                    "PacketType": packet["PacketType"]
                }
                for packet in detected_packets
            ]

            json.dump(packets_data, jsonfile, indent=4)

        self.print_saved_message(output_file)


class PyNetMon:
    """
    A Network Monitoring Tool that detects packets based on specified criteria.
    """

    def __init__(self, output_format='csv'):
        self.filter_criteria = {}
        self.detected_packets = []
        self.scan_stopped = False
        self.output_handler = self._create_output_handler(output_format)

        if not os.path.exists("detected_packets"):
            os.makedirs("detected_packets")

        logging.basicConfig(
            filename='pynetmon_log.txt',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    @staticmethod
    def _create_output_handler(output_format):
        if output_format.lower() == 'csv':
            return CSVOutputHandler()
        elif output_format.lower() == 'json':
            return JSONOutputHandler()
        else:
            raise ValueError("Unsupported output format")

    @property
    def output_format(self):
        return self.output_handler.output_format

    @output_format.setter
    def output_format(self, format):
        self.output_handler = self._create_output_handler(format)

    @output_format.deleter
    def output_format(self):
        del self.output_handler

    def set_filter(self):
        while True:
            print("Select filtering criteria:")
            print("1. Target IP")
            print("2. Target Port")
            print("3. Source IP")
            print("4. Source Port")
            print("5. Protocol")
            print("6. Run Scan")
            print("7. Stop Scan")
            print("8. Exit")

            choice = input("Enter your choice: ")

            if choice == "1":
                self.filter_criteria['target_ip'] = input("Enter target IP address: ")
            elif choice == "2":
                self.filter_criteria['target_port'] = int(input("Enter target port: "))
            elif choice == "3":
                self.filter_criteria['source_ip'] = input("Enter source IP address: ")
            elif choice == "4":
                self.filter_criteria['source_port'] = int(input("Enter source port: "))
            elif choice == "5":
                self.filter_criteria['protocol'] = input(
                    "Enter protocol (e.g., TCP, UDP): "
                ).upper()
            elif choice == "6":
                self.run_scan()
            elif choice == "7":
                self.stop_scan()
            elif choice == "8":
                break
            else:
                print(Fore.RED + "Invalid choice. Please try again.")

    def run_scan(self):
        if not self.filter_criteria:
            print(Fore.YELLOW + "Please select filtering criteria first.")
            return

        print(Fore.YELLOW + "Running network scan...")
        logging.info("Scan started.")
        self.scan_stopped = False

        scan_thread = threading.Thread(target=self.sniff_packets)
        scan_thread.start()

    def sniff_packets(self):
        sniff(prn=self.monitor_packet, stop_filter=self.should_stop_scan)

    def should_stop_scan(self, _):
        return self.scan_stopped

    def stop_scan(self):
        print(Fore.YELLOW + "Stopping scan...")
        logging.info("Scan stopped.")
        self.scan_stopped = True

    def monitor_packet(self, packet):
        if self.scan_stopped:
            return

        matched = True

        for key, value in self.filter_criteria.items():
            if key == 'target_ip' and packet.haslayer(IP):
                if packet[IP].dst != value:
                    matched = False

            elif key == 'target_port' and packet.haslayer(TCP):
                if packet[TCP].dport != value:
                    matched = False

            elif key == 'source_ip' and packet.haslayer(IP):
                if packet[IP].src != value:
                    matched = False

            elif key == 'source_port' and packet.haslayer(TCP):
                if packet[TCP].sport != value:
                    matched = False

            elif key == 'protocol' and packet.haslayer(IP):
                if packet[IP].proto != {'TCP': 6, 'UDP': 17}.get(value.upper(), 0):
                    matched = False
            else:
                matched = False
                break

        if matched:
            destination_url = self.resolve_destination_url(packet[IP].dst)

            self.detected_packets.append({
                "Source": packet[IP].src,
                "Destination": packet[IP].dst,
                "DestinationURL": destination_url,
                "Protocol": packet[IP].proto,
                "PacketType": packet.summary().split()[0]
            })

            logging.warning(f"Traffic match detected: {packet.summary()}")

            self.send_notification(
                "Py-NetMon Alert",
                f"Traffic detected: {self.packet_summary(packet)}"
            )

    def resolve_destination_url(self, ip_address):
        try:
            domain_name = socket.gethostbyaddr(ip_address)[0]
            return domain_name if domain_name != ip_address else self.reverse_dns_lookup(ip_address)
        except socket.herror:
            return ip_address

    @staticmethod
    def reverse_dns_lookup(ip_address):
        try:
            domain_name = socket.gethostbyaddr(ip_address)[0]
            return domain_name
        except socket.herror:
            return ip_address

    @staticmethod
    def packet_summary(packet):
        return (
            f"Source: {packet[IP].src}, Destination: {packet[IP].dst}, "
            f"Protocol: {packet[IP].proto}, Packet Type: {packet.summary().split()[0]}"
        )

    @staticmethod
    def send_notification(title, message):
        notification.notify(
            title=title,
            message=message,
            app_icon=None,
            timeout=10,
        )

    def start(self):
        print(Fore.CYAN + "Starting Py-NetMon...")
        logging.info("Py-NetMon started.")
        self.set_filter()
        self.save_to_output()

    def save_to_output(self):
        self.output_handler.save(self.detected_packets)


def main():
    while True:
        output_format = input(
            Fore.MAGENTA + "Enter output format (csv/json): "
        ).lower()

        if output_format in ['csv', 'json']:
            netmon = PyNetMon(output_format=output_format)
            netmon.start()
            break
        else:
            print(Fore.RED + "Invalid output format. Please enter 'csv' or 'json'.")


if __name__ == "__main__":
    main()
