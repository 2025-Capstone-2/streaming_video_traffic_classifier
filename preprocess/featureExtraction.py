# Jordan Ebel (modified for Python 3)

import dpkt
import argparse
import ipaddress
import numpy as np


# parse input arguments
def parseArgs():
    parser = argparse.ArgumentParser(description="Parse a PCAP file")
    parser.add_argument("-f", "--file", type=str, help=".pcap file", required=True)
    parser.add_argument("-c", "--count", help="Packet count", required=False)
    parser.add_argument("-w", "--window_size", help="Window size", required=False)
    parser.add_argument(
        "--output", type=str, help="Output feature file", default="featureMatrix.dat"
    )
    parser.add_argument(
        "--category", type=str, help="Output category file", default="category.dat"
    )
    return parser.parse_args()


def cidrToSubnet(cidr):
    return ipaddress.IPv4Network(cidr)


def isYoutubePacket(ip):
    dest_ip_addr = ipaddress.IPv4Address(ip.dst)
    src_ip_addr = ipaddress.IPv4Address(ip.src)

    if (
        dest_ip_addr in cidrToSubnet(str("173.194.0.0/16"))
        or dest_ip_addr in cidrToSubnet(str("74.125.0.0/16"))
        or dest_ip_addr in cidrToSubnet(str("192.178.0.0/16"))
        or dest_ip_addr in cidrToSubnet(str("192.179.0.0/16"))
        or dest_ip_addr in cidrToSubnet(str("172.217.0.0/16"))
        or dest_ip_addr in cidrToSubnet(str("216.58.0.0/16"))
        or src_ip_addr in cidrToSubnet(str("173.194.0.0/16"))
        or src_ip_addr in cidrToSubnet(str("74.125.0.0/16"))
        or src_ip_addr in cidrToSubnet(str("192.178.0.0/16"))
        or src_ip_addr in cidrToSubnet(str("192.179.0.0/16"))
        or src_ip_addr in cidrToSubnet(str("172.217.0.0/16"))
        or src_ip_addr in cidrToSubnet(str("216.58.0.0/16"))
    ):

        if ip.p == 17:
            udp = ip.data
            if udp.dport == 443 or udp.sport == 443:
                return True
        elif ip.p == 6:
            tcp = ip.data
            if tcp.dport == 443 or tcp.sport == 443:
                return True

    return False


def isNetflixPacket(ip):
    dest_ip_addr = ipaddress.IPv4Address(ip.dst)
    src_ip_addr = ipaddress.IPv4Address(ip.src)

    if (
        dest_ip_addr in cidrToSubnet(str("54.192.0.0/16"))
        or dest_ip_addr in cidrToSubnet(str("23.246.0.0/16"))
        or src_ip_addr in cidrToSubnet(str("54.192.0.0/16"))
        or src_ip_addr in cidrToSubnet(str("23.246.0.0/16"))
    ):

        if ip.p == 17:
            udp = ip.data
            if udp.dport == 443 or udp.sport == 443:
                return True
        elif ip.p == 6:
            tcp = ip.data
            if tcp.dport == 443 or tcp.sport == 443:
                return True

    return False


def extractStandardFeatures(packet, timestamp, previous_timestamp):
    eth = dpkt.ethernet.Ethernet(packet)
    ip = eth.data

    # only IP packets are supported
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        return -1

    inter_packet_time = timestamp - previous_timestamp
    packet_size = len(packet)
    ip_len = ip.len
    ip_header_len = ip.hl
    ip_off = ip.off
    ip_protocol = ip.p
    ip_ttl = ip.ttl

    return (
        inter_packet_time,
        packet_size,
        ip_len,
        ip_header_len,
        ip_off,
        ip_protocol,
        ip_ttl,
    )


def extractWindowFeatures(packets):
    previous_arrival_time = 0
    interarrival_times = []
    ip_sizes = []
    ttls = []
    protocols = []

    for pktBuf in packets:
        timestamp = pktBuf[0]
        eth = dpkt.ethernet.Ethernet(pktBuf[1])
        ip = eth.data

        if previous_arrival_time != 0:
            interarrival_times.append(timestamp - previous_arrival_time)
        previous_arrival_time = timestamp

        ip_sizes.append(ip.len)
        ttls.append(ip.ttl)
        protocols.append(ip.p)

    return calcAverages(interarrival_times, ip_sizes, ttls, protocols)


def calcAverages(interarrival_times, ip_sizes, ttls, protocols):
    if len(interarrival_times) > 0:
        mean_interarrival_time = np.mean(interarrival_times)
        var_interarrival_time = np.var(interarrival_times)
    else:
        mean_interarrival_time = 0
        var_interarrival_time = 0

    mean_ip_size = np.mean(ip_sizes)
    var_ip_size = np.var(ip_sizes)
    mean_ttl = np.mean(ttls)
    var_ttl = np.var(ttls)
    mean_protocol = np.mean(protocols)
    var_protocol = np.var(protocols)

    return (
        mean_interarrival_time,
        var_interarrival_time,
        mean_ip_size,
        var_ip_size,
        mean_ttl,
        var_ttl,
        mean_protocol,
        var_protocol,
    )


def main():
    args = parseArgs()

    f = open(args.file, "rb")
    if args.count:
        maxCount = int(args.count)
    else:
        maxCount = -1
    if args.window_size:
        window_size = int(args.window_size)
    else:
        window_size = 3

    count = 0
    previous_timestamp = 0
    target_count = 0
    total_count = 0

    featureFile = open(args.output, "w")
    categoryFile = open(args.category, "w")

    pcap = dpkt.pcap.Reader(f)
    pktList = list(pcap.readpkts())

    for timestamp, buf in pktList:
        total_count += 1

        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data

        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        if count == 0:
            previous_timestamp = timestamp

        result = extractStandardFeatures(buf, timestamp, previous_timestamp)
        if result == -1:
            continue

        (
            inter_packet_time,
            packet_size,
            ip_len,
            ip_header_len,
            ip_off,
            ip_protocol,
            ip_ttl,
        ) = result
        previous_timestamp = timestamp

        skip_count = 0
        window_packets = []
        for x in range(0, window_size):
            index = (total_count - 1) + x + skip_count

            if index >= len(pktList):
                break

            eth = dpkt.ethernet.Ethernet(pktList[index][1])
            while eth.type != dpkt.ethernet.ETH_TYPE_IP:
                skip_count += 1
                index = (total_count - 1) + x + skip_count

                if index >= len(pktList):
                    break

                eth = dpkt.ethernet.Ethernet(pktList[index][1])

            if index < len(pktList):
                window_packets.append(pktList[index])

        (
            mean_ia_time,
            var_ia_time,
            mean_ip,
            var_ip,
            mean_ttl,
            var_ttl,
            mean_p,
            var_p,
        ) = extractWindowFeatures(window_packets)

        category = 0
        if isNetflixPacket(ip) or isYoutubePacket(ip):
            category = 1
            target_count += 1

        featureFile.write(
            "%f %d %d %d %d %d %f %f %f %f %f %f %f %f\n"
            % (
                inter_packet_time,
                packet_size,
                ip_len,
                ip_off,
                ip_protocol,
                ip_ttl,
                mean_ia_time,
                var_ia_time,
                mean_ip,
                var_ip,
                mean_ttl,
                var_ttl,
                mean_p,
                var_p,
            )
        )
        categoryFile.write("%d\n" % category)

        count += 1
        if maxCount != -1 and count >= maxCount:
            break

    print("Target count:", target_count)
    print("IP count:", count)
    print("Total count:", total_count)
    featureFile.close()
    categoryFile.close()


if __name__ == "__main__":
    main()
