#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include <cstdint>
#include <string>

class PacketAnalyzer {
public:

    // Analyze and log packet details
    void analyzeAndLog(const uint8_t* packet, size_t length);

private:
    // Utility to log an IPv4 packet
    void handleIPv4(const uint8_t* packet, size_t length);

    // Utility to log an IPv6 packet
    void handleIPv6(const uint8_t* packet, size_t length);

    // Convert protocol number to string (e.g., 6 -> TCP)
    std::string protocolToString(uint8_t protocol);

  
};

#endif // PACKET_ANALYZER_H
