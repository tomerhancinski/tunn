#include <iostream>
#include <vector>
#include "tunnel.h"
#include "PacketAnalyzer.h"
#include "NcClient.h"
int maintest()
{
     // Create an NcClient instance
    NcClient client("127.0.0.1", 9999);

    // Connect to the server
    if (!client.connectToServer()) {
        return -1;
    }

    // Send a message to the server
    client.sendMessage("Hello, nc server!\n");

    // Receive a message from the server
    std::string response = client.receiveMessage();

    if (!response.empty()) {
        std::cout << "Server response: " << response << "\n";
    }
    return 1;
}

int main() {
    
   // maintest();
    
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
