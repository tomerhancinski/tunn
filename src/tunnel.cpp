#include "tunnel.h"
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdexcept>
#include <linux/if_tun.h>

// Constructor: Initialize with the name of the TUN device
tunnel::tunnel(const std::string& tun_name) {
    // Open the TUN device
    tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd < 0) {
        perror("Opening TUN device");
        throw std::runtime_error("Failed to open TUN device");
    }

    // Setup interface request structure
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  // TUN device, no packet info
    strncpy(ifr.ifr_name, tun_name.c_str(), IFNAMSIZ);

    // Create the TUN interface
    if (ioctl(tun_fd, TUNSETIFF, &ifr) < 0) {
        perror("Creating TUN interface");
        close(tun_fd);
        throw std::runtime_error("Failed to create TUN interface");
    }

    std::cout << "TUN interface " << tun_name << " created successfully.\n";

    // Assign IP Address and Route
    std::string ifconfig_cmd = "ifconfig " + tun_name + " 100.100.100.100 netmask 255.255.255.255 up";
    std::string route_cmd = "route add -net 100.100.100.0/24 dev " + tun_name;

    system(ifconfig_cmd.c_str());
    system(route_cmd.c_str());
}

// Destructor: Clean up resources
tunnel::~tunnel() {
    if (tun_fd > 0) {
        close(tun_fd);
    }
}

// Read a packet from the TUN interface
void tunnel::modifyAndForwardPacket( uint8_t* buffer, size_t length) {
 
  //  std::cout << "[Received Packet] Length: " << length << " bytes\n";

    const struct iphdr* ip_header = reinterpret_cast<const struct iphdr*>(buffer);

    struct in_addr src_ip, dst_ip;
    src_ip.s_addr = ip_header->saddr;
    dst_ip.s_addr = ip_header->daddr;

   // std::cout << "[Encapsulated Packet] Source IP: " << inet_ntoa(src_ip)
   //           << ", Destination IP: " << inet_ntoa(dst_ip) << "\n";

    // Check if the protocol is UDP
    if (ip_header->protocol == IPPROTO_UDP) {
        const uint8_t* udp_packet = buffer + (ip_header->ihl * 4);  // Skip IP header
        const struct udphdr* udp_header = reinterpret_cast<const struct udphdr*>(udp_packet);

        uint16_t src_port = ntohs(udp_header->source);
        uint16_t dst_port = ntohs(udp_header->dest);

      //  std::cout << "[Encapsulated Packet] UDP Source Port: " << src_port
      //            << ", UDP Destination Port: " << dst_port << "\n";

        // Prepare a response message
        const char response[] = "Hello from TUN interface!";
        uint8_t response_packet[4096];
        memset(response_packet, 0, sizeof(response_packet));  // Clear the response packet buffer

        // IP Header Setup for the response
        struct iphdr* response_ip_header = reinterpret_cast<struct iphdr*>(response_packet);
        response_ip_header->ihl = 5;  // IP Header length (5 words = 20 bytes)
        response_ip_header->version = 4;  // IPv4
        response_ip_header->tos = 0;  // Type of service
        response_ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(response));  // Total length
        response_ip_header->id = 0;  // Identification
        response_ip_header->frag_off = 0;  // Fragmentation offset
        response_ip_header->ttl = 64;  // Time-to-live
        response_ip_header->protocol = IPPROTO_UDP;  // Protocol (UDP)
        response_ip_header->check = 0;  // Checksum (0 for now, will be calculated later)
        response_ip_header->saddr = dst_ip.s_addr;  // Swap source and destination IP
        response_ip_header->daddr = src_ip.s_addr;

        // UDP Header Setup for the response
        struct udphdr* response_udp_header = reinterpret_cast<struct udphdr*>(response_packet + sizeof(struct iphdr));
        response_udp_header->source = udp_header->dest;  // Swap the UDP source and destination ports
        response_udp_header->dest = udp_header->source;
        response_udp_header->len = htons(sizeof(struct udphdr) + sizeof(response));  // Length of UDP header + response message
        response_udp_header->check = 0;  // Checksum (0 for now)

        // Copy the response message into the UDP packet
        memcpy(response_packet + sizeof(struct iphdr) + sizeof(struct udphdr), response, sizeof(response));

        // Recalculate the IP checksum
        response_ip_header->check = csum(reinterpret_cast<uint16_t*>(response_packet), sizeof(struct iphdr));

        // Send the response packet
        sendPacket(response_packet, sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(response));
    } else {
      //  std::cout << "[Encapsulated Packet] Protocol: " << static_cast<int>(ip_header->protocol)
      //            << " (Not UDP, no port information available)\n";
    }
}

// Send a packet to the TUN interface
void tunnel::sendPacket(const uint8_t* buffer, size_t length) {
    ssize_t written = write(tun_fd, buffer, length);
    if (written < 0) {
        perror("[Error Sending Packet] Writing to TUN interface failed");
    } else {
        std::cout << "[Sending Packet] Successfully wrote " << written << " bytes to the TUN interface\n";
    }
}

// Read a packet from the TUN interface and store it in the provided buffer
// Returns the number of bytes read (size_t), or -1 if there's an error
ssize_t tunnel::readPacket(uint8_t* buffer, size_t buffer_length) {
    ssize_t length = read(tun_fd, buffer, buffer_length);

    if (length < 0) {
        perror("[Error Reading Packet] Failed to read from TUN interface");
        return -1;  // Indicate failure
    } else {
        std::cout << "[Reading Packet] Successfully read " << length << " bytes from TUN interface\n";
        return length;  // Return the number of bytes read
    }
}

// Simple checksum calculation function for IP header
unsigned short tunnel::csum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    // Add remaining byte if any
    if (len == 1) {
        sum += *((unsigned char*)buf);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);  // Fold 32-bit sum to 16 bits
    sum += (sum >> 16);
    return ~sum;  // One's complement
}

int tunnel::getFD() const {
    return tun_fd;
}