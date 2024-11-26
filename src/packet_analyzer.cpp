#include "packet_analyzer.h"
#include <iostream>
#include <netinet/ip.h>     // For IPv4 header
#include <netinet/ip6.h>    // For IPv6 header
#include <netinet/tcp.h>    // For TCP header
#include <netinet/udp.h>    // For UDP header
#include <arpa/inet.h>      // For inet_ntop
#include <cstring>          // For memset

PacketAnalyzer::PacketAnalyzer() {}

PacketAnalyzer::~PacketAnalyzer() {}

void PacketAnalyzer::analyzeAndLog(const uint8_t* packet, size_t length) {
    if (length < 1) {
        log("Packet is too small to analyze.");
        return;
    }

    uint8_t version = (packet[0] >> 4); // Extract IP version
    switch (version) {
        case 4:
            handleIPv4(packet, length);
            break;
        case 6:
            handleIPv6(packet, length);
            break;
        default:
            log("Unknown IP version: " + std::to_string(version));
    }
}

void PacketAnalyzer::handleIPv4(const uint8_t* packet, size_t length) {
    if (length < sizeof(struct iphdr)) {
        log("Incomplete IPv4 packet.");
        return;
    }

    const struct iphdr* ip_header = reinterpret_cast<const struct iphdr*>(packet);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);

    std::string protocol = protocolToString(ip_header->protocol);

    log("IPv4 Packet:");
    log("  Source IP: " + std::string(src_ip));
    log("  Destination IP: " + std::string(dst_ip));
    log("  Protocol: " + protocol);
    log("  Total Length: " + std::to_string(ntohs(ip_header->tot_len)));

    if (ip_header->protocol == IPPROTO_TCP && length >= ip_header->ihl * 4 + sizeof(struct tcphdr)) {
        const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(packet + ip_header->ihl * 4);
        log("  Source Port: " + std::to_string(ntohs(tcp_header->source)));
        log("  Destination Port: " + std::to_string(ntohs(tcp_header->dest)));
    } else if (ip_header->protocol == IPPROTO_UDP && length >= ip_header->ihl * 4 + sizeof(struct udphdr)) {
        const struct udphdr* udp_header = reinterpret_cast<const struct udphdr*>(packet + ip_header->ihl * 4);
        log("  Source Port: " + std::to_string(ntohs(udp_header->source)));
        log("  Destination Port: " + std::to_string(ntohs(udp_header->dest)));
    }
}

void PacketAnalyzer::handleIPv6(const uint8_t* packet, size_t length) {
    if (length < sizeof(struct ip6_hdr)) {
        log("Incomplete IPv6 packet.");
        return;
    }

    const struct ip6_hdr* ip6_header = reinterpret_cast<const struct ip6_hdr*>(packet);

    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN);

    log("IPv6 Packet:");
    log("  Source IP: " + std::string(src_ip));
    log("  Destination IP: " + std::string(dst_ip));
    log("  Next Header (Protocol): " + std::to_string(ip6_header->ip6_nxt));
    log("  Payload Length: " + std::to_string(ntohs(ip6_header->ip6_plen)));
}


std::string PacketAnalyzer::protocolToString(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_IPV6: return "IPv6";
        default: return "Unknown";
    }
}

void PacketAnalyzer::log(const std::string& message) {
    std::cout << message << std::endl;
}
