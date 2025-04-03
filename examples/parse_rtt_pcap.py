from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNSQR, DNSRR, DNS
from statistics import mean, median, stdev
from collections import defaultdict
from resolvectl import query_resolvectl

def is_quic_initial(pkt) -> bool:
    """
    Detect QUIC Initial packets
    First byte of QUIC packet after UDP header should have specific bits set
    """
    if UDP in pkt and pkt[UDP].payload:
        raw_payload = bytes(pkt[UDP].payload)
        if len(raw_payload) > 0:
            first_byte = raw_payload[0]
            # Check if it's a long header (first bit is 1)
            # and type is Initial (bits 4-7 are 0000)
            return (first_byte & 0x80) and ((first_byte & 0x30) == 0x00)
    return False

def is_quic_handshake(pkt) -> bool:
    """
    Detect QUIC Handshake packets
    """
    if UDP in pkt and pkt[UDP].payload:
        raw_payload = bytes(pkt[UDP].payload)
        if len(raw_payload) > 0:
            first_byte = raw_payload[0]
            # Check if it's a long header (first bit is 1)
            # and type is Handshake (bits 4-7 are 0010)
            return (first_byte & 0x80) and ((first_byte & 0x30) == 0x20)
    return False


def analyze_rtt(pcap_file, domain_list: List[str]) -> Dict[str, float]:
    """
    Analyze RTT from pcap file by examining QUIC handshakes and data/ACK pairs
    Returns RTT statistics for both handshakes and data transfers
    """
    # Read pcap file
    packets = rdpcap(pcap_file)

    # Track initial and handshake timestamps for handshake RTT
    handshake_rtts = defaultdict(list)
    initial_times = {}  # (src, dst, sport, dport) -> timestamp

    # # Track data packet and ACK timestamps
    # data_rtts = defaultdict(list)  # (src, dst, sport, dport) -> list of RTTs
    # seq_times = {}  # (src, dst, sport, dport, seq) -> timestamp

    for pkt in packets:

        if IP in pkt and UDP in pkt:
            # Extract key connection details
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            timestamp = float(pkt.time)

            # Only track QUIC traffic (typically UDP 443)
            if dport != 443 and sport != 443 and dport != 4000 and sport != 4000:
                continue

             # Handle QUIC Initial packets
            if is_quic_initial(pkt):
                conn_tuple = (src, dst, sport, dport)
                initial_times[conn_tuple] = timestamp
            
            # Handle QUIC Handshake packets
            elif is_quic_handshake(pkt):
                reverse_tuple = (dst, src, dport, sport)  # Reverse direction
                if reverse_tuple in initial_times:
                    rtt = timestamp - initial_times[reverse_tuple]
                    handshake_rtts[src].append(rtt)
                    del initial_times[reverse_tuple]

            # # Handle data packets and ACKs
            # elif pkt[UDP].payload:
            #     seq = pkt[UDP].seq
            #     seq_times[(src, dst, sport, dport, seq)] = timestamp

            # elif flags & 0x10:  # Pure ACK
            #     ack = pkt[UDP].ack
            #     # Check all possible matching data packets
            #     for key in list(seq_times.keys()):
            #         if (
            #             key[1] == src
            #             and key[0] == dst
            #             and key[3] == sport
            #             and key[2] == dport
            #             and key[4] < ack
            #         ):
            #             rtt = timestamp - seq_times[key]
            #             data_rtts[(key[0], key[1], key[2], key[3])].append(rtt)
            #             del seq_times[key]

    # Calculate statistics
    stats = {}

    domains={}
    domains = query_resolvectl(domain_list) # ip -> [domain]
    # print(domains)
    # print(handshake_rtts)
    for dst, rtt_stats in handshake_rtts.items():
        dlist = domains.get(dst, None)
        if not dlist:
            print(f"domain for {dst} not found")
            domain = dst
        else: 
            domain = dlist[0] # domains returns a list, so we take the first element
        stats[domain] = {
            "count": len(rtt_stats),
            "min": min(rtt_stats) * 1000 if rtt_stats else 0,
            "max": max(rtt_stats) * 1000 if rtt_stats else 0,
            "mean": mean(rtt_stats) * 1000 if rtt_stats else 0,
            "median": median(rtt_stats) * 1000 if rtt_stats else 0,
            "stdev": stdev(rtt_stats) * 1000 if len(rtt_stats) > 1 else 0,
        }
        print("----------------------------------------------------------------------")
        print(domain)
        print(stats[domain])

    # Calculate average data RTT per connection
    # avg_data_rtts = []
    # for rtts in data_rtts.values():
    #     if rtts:
    #         avg_data_rtts.append(mean(rtts))

    # if avg_data_rtts:
    #     stats["data_rtts"] = {
    #         "count": sum(len(rtts) for rtts in data_rtts.values()),
    #         "min": min(avg_data_rtts) * 1000,
    #         "max": max(avg_data_rtts) * 1000,
    #         "mean": mean(avg_data_rtts) * 1000,
    #         "median": median(avg_data_rtts) * 1000,
    #         "stdev": stdev(avg_data_rtts) * 1000 if len(avg_data_rtts) > 1 else 0,
    #     }

    return stats
