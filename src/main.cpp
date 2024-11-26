#include "tunnel.h"
#include "packet_analyzer.h"

int main() {
    tunnel tun("tun0");
    PacketAnalyzer analyzer;

    while (true) {
     
    uint8_t buffer[4096];  // buffer for the incoming packet
    ssize_t length = read(tun.getFD(), buffer, sizeof(buffer));

    if (length < 0) {
        perror("Error reading from TUN interface");
        return 0;
    }
        analyzer.analyzeAndLog(buffer, length);

        tun.readPacket(buffer,length);  // Continuously read and process incoming packets
    }

    return 0;
}

