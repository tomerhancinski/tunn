#include "tunnel.h"


int main() {
    tunnel tun("tun0");

    while (true) {
        tun.readPacket();  // Continuously read and process incoming packets
    }

    return 0;
}

