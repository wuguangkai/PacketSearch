import dpkt
import socket
import hashlib

from scapy.all import *
from scapy.layers import http


class FlowInfo:
    def __init__(self, file_path, pkt_number, four_tuple):
        self.file_path = file_path
        self.pkt_number = pkt_number
        self.four_tuple = four_tuple


class FileCapture:
    def __init__(self, file_path):
        self.file_path = file_path
        self.four_tuple = {}

    def ReadFile(self):
        with open(self.file_path, 'rb') as f:
            # 创建pcap.Reader对象
            pcap_file = dpkt.pcap.Reader(f)
            number = 0
            # 遍历pcap文件的每一个数据包
            for timestamp, buf in pcap_file:
                number += 1
                # 解析以太网帧
                eth = dpkt.ethernet.Ethernet(buf)

                # 判断是否为IP数据包
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data

                    # 判断是否为TCP数据包
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        try:
                            request = dpkt.http.Request(tcp.data)
                        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                            continue
                        # 输出源IP、目的IP、源端口和目的端口
                        print(f"packet number in %s:" % self.file_path, number)
                        print(f"packet timestamp: {timestamp}")
                        print(f"Source IP: {socket.inet_ntoa(ip.src)}")
                        print(f"Destination IP: {socket.inet_ntoa(ip.dst)}")
                        print(f"Source Port: {tcp.sport}")
                        print(f"Destination Port: {tcp.dport}")

    def calcTupleHashVal(self, src_ip, src_port, dst_ip, dst_port):
        hash_val = src_ip
        hash_val = hash_val * 131 + src_port
        hash_val = hash_val * 131 + dst_ip
        hash_val = hash_val * 131 + dst_port
        return hash_val

    def scapyTest(self):
        pkts = rdpcap(self.file_path)
        number = 0
        for pkt in pkts:
            number += 1

            src_ip = 0
            dst_ip = 0
            src_port = 0
            dst_port = 0
            src_ip_str = ""
            dst_ip_str = ""
            if pkt.haslayer('IP'):
                ip_data = pkt['IP']
                src_ip = int.from_bytes(socket.inet_aton(ip_data.src), byteorder='big')
                dst_ip = int.from_bytes(socket.inet_aton(ip_data.dst), byteorder='big')
                src_ip_str = ip_data.src
                dst_ip_str = ip_data.dst
                print(f"packet ip info: {src_ip_str} >> {dst_ip_str}")
                print(f"packet ip int: {src_ip} >> {dst_ip}")

            if pkt.haslayer('TCP'):
                tcp_data = pkt['TCP']
                src_port = tcp_data.sport
                dst_port = tcp_data.dport
                print(f"packet tcp info: {src_port} >> {dst_port}")
            elif pkt.haslayer('UDP'):
                udp_data = pkt['UDP']
                src_port = udp_data.sport
                dst_port = udp_data.dport
                print(f"packet udp info: {src_port} >> {dst_port}")

            tuple_hash_val = self.calcTupleHashVal(src_ip, dst_ip, src_port, dst_port)
            flow_info = FlowInfo(self.file_path, number, {'src_ip': src_ip_str, 'src_port': src_port,
                                                          'dst_ip': dst_ip_str, 'dst_port': dst_port})
            if tuple_hash_val not in self.four_tuple:
                self.four_tuple[tuple_hash_val] = []

            self.four_tuple[tuple_hash_val].append(flow_info)

        for key, value in self.four_tuple.items():
            print(f"flow hash key: {key}")
            for item in value:
                print(f"file path: {item.file_path}, packet number: {item.pkt_number}, four tuple: {item.four_tuple}")
