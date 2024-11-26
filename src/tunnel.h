#ifndef TUN_TUNNEL_H
#define TUN_TUNNEL_H

#include <string>
#include <cstdint>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <stdexcept>

class tunnel {
public:
    // Constructor: Initialize with the name of the TUN device
    tunnel(const std::string& tun_name);

    // Destructor: Clean up resources
    ~tunnel();

    // Read a packet from the TUN interface
    void modifyAndForwardPacket(uint8_t* buffer, size_t length);

    // Send a packet to the TUN interface
    void sendPacket(const uint8_t* buffer, size_t length);

    ssize_t readPacket(uint8_t* buffer, size_t buffer_length);

    // Calculate checksum (for IP header)
    unsigned short csum(unsigned short *buf, int len);

    // Get the file descriptor of the TUN interface
    int getFD() const;

private:
    int tun_fd;             // File descriptor for the TUN interface
    struct ifreq ifr;       // Interface request structure for configuration
};

#endif // TUN_INTERFACE_H
