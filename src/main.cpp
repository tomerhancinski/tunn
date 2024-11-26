#include <iostream>
#include <vector>
#include "tunnel.h"
#include "packet_analyzer.h"

int main() {
    // Create tunnel object for interacting with the TUN interface
    tunnel tun("tun0");

    // Create packet analyzer object to handle packet parsing and logging
    PacketAnalyzer analyzer;

    // Buffer size for reading packets (based on MTU or other limits)
    const size_t buffer_size = 4096;
    uint8_t buffer[buffer_size];  

    while (true) {
        // Read a packet from the TUN interface
        ssize_t length = tun.readPacket(buffer, buffer_size);

        if (length < 0) {
            std::cerr << "Error reading packet from TUN interface. Exiting..." << std::endl;
            break;  // Exit on error reading packet
        }

        if (length == 0) {
            std::cout << "No packet available to read. Waiting..." << std::endl;
            continue;  // Continue if no packet was received
        }

        // Analyze and log the packet
        analyzer.analyzeAndLog(buffer, length);

        // Modify and forward the packet
        tun.modifyAndForwardPacket(buffer, length);
    }

    return 0;
}
