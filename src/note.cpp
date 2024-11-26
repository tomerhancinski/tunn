/*

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/ip_icmp.h>
 #include <unordered_map>
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <unordered_map>
#include <map>



///////////////////////////////////////////////////////////////////////////////
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>   // Include IPv6 header definitions
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>



// Define ports
#define LISTEN_PORT 8888       // Port where incoming packets are destined
#define FORWARD_PORT 9999      // Port where netcat is listening
#define LOCAL_HOST "127.0.0.1" // Loopback address to forward packets to netcat




#define TUN_DEVICE "/dev/net/tun"
#define BUFFER_SIZE 2048
#define NAT_PORT 8888
#define FORWARD_PORT 9999
#define VPN_IP "100.100.100.100"
#define VPN_NET "100.100.100.0/24"




// Define ports
#define LISTEN_PORT 8888
#define FORWARD_PORT 9999
#define LOCAL_HOST "127.0.0.1"




int tun_fd = -1;



int create_tun_interface(char *dev) {
    struct ifreq ifr;
    int tun = open(TUN_DEVICE, O_RDWR);
    if (tun < 0) {
        perror("Opening /dev/net/tun");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN device, no packet info
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if (ioctl(tun, TUNSETIFF, &ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(tun);
        exit(1);
    }

    strcpy(dev, ifr.ifr_name);
    return tun;
}

void set_ip_route() {
    // Assign IP Address to the TUN interface
    system("ifconfig tun0 100.100.100.100 netmask 255.255.255.255 up");

    // Add the route for the network 100.100.100.0/24 via the TUN interface
    system("route add -net 100.100.100.0/24 dev tun0");
}



///////////////////////////////////////////////////////////////////////////////////////////////////////////




// Function to print raw buffer as hex for debugging
void print_raw_buffer(const char *buffer, int len) {
    std::cout << "Raw buffer (hex): ";
    for (int i = 0; i < len; ++i) {
        std::cout << std::hex << (int)(unsigned char)buffer[i] << " ";
    }
    std::cout << std::dec << std::endl;
}

// Function to print IPv4 address (in human-readable format)
std::string ip_to_string(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}

// Function to print IPv6 address
std::string ipv6_to_string(struct in6_addr ip) {
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip, str, INET6_ADDRSTRLEN);
    return std::string(str);
}
static int aaaa=0;
// Function to log the packet details
void log_packet_details(const char *buffer, int len) {

    std::cout << "/////////////////////////////sss/////////////////////////////////"<< std::endl;
    struct iphdr *ip_header = (struct iphdr *)buffer;

    if (ip_header->version == 4) {
        // IPv4 Packet
        std::cout << "IP Version: IPv4" << std::endl;
        std::cout << "Total Packet Length: " << ntohs(ip_header->tot_len) << " bytes" << std::endl;
        std::cout << "Source IP: " << ip_to_string(ip_header->saddr) << std::endl;
        std::cout << "Destination IP: " << ip_to_string(ip_header->daddr) << std::endl;

        // Handle TCP/UDP/ICMP
        switch (ip_header->protocol) {
            case IPPROTO_TCP: {
                struct tcphdr *tcp_header = (struct tcphdr *)(buffer + (ip_header->ihl << 2));
                std::cout << "Protocol: TCP" << std::endl;
                std::cout << "Source Port: " << ntohs(tcp_header->source) << std::endl;
                std::cout << "Destination Port: " << ntohs(tcp_header->dest) << std::endl;
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr *udp_header = (struct udphdr *)(buffer + (ip_header->ihl << 2));
                std::cout << "Protocol: UDP" << std::endl;
                std::cout << "Source Port: " << ntohs(udp_header->source) << std::endl;
                std::cout << "Destination Port: " << ntohs(udp_header->dest) << std::endl;
                aaaa =ntohs(udp_header->source);
                break;
            }
            case IPPROTO_ICMP: {
                std::cout << "Protocol: ICMP" << std::endl;
                break;
            }
            default:
                std::cout << "Protocol: Other" << std::endl;
                break;
        }
    }
    else if (ip_header->version == 6) {
        // IPv6 Packet (handle IPv6 headers)
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)buffer;
        std::cout << "IP Version: IPv6" << std::endl;
        std::cout << "Total Packet Length: " << ntohs(ip6_header->ip6_plen) << " bytes" << std::endl;

        // Log IPv6 Source and Destination Addresses
        std::cout << "Source IP: " << ipv6_to_string(ip6_header->ip6_src) << std::endl;
        std::cout << "Destination IP: " << ipv6_to_string(ip6_header->ip6_dst) << std::endl;

        // Handle TCP/UDP/ICMPv6
        switch (ip6_header->ip6_nxt) {
            case IPPROTO_TCP: {
                struct tcphdr *tcp_header = (struct tcphdr *)(buffer + sizeof(struct ip6_hdr));
                std::cout << "Protocol: TCP" << std::endl;
                std::cout << "Source Port: " << ntohs(tcp_header->source) << std::endl;
                std::cout << "Destination Port: " << ntohs(tcp_header->dest) << std::endl;
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr *udp_header = (struct udphdr *)(buffer + sizeof(struct ip6_hdr));
                std::cout << "Protocol: UDP" << std::endl;
                std::cout << "Source Port: " << ntohs(udp_header->source) << std::endl;
                std::cout << "Destination Port: " << ntohs(udp_header->dest) << std::endl;
                break;
            }
            case IPPROTO_ICMPV6: {
                std::cout << "Protocol: ICMPv6" << std::endl;
                break;
            }
            default:
                std::cout << "Protocol: Other" << std::endl;
                break;
        }
    } else {
        std::cout << "Unknown IP Version: " << ip_header->version << std::endl;
    }
std::cout << "///////////////////////////eeee///////////////////////////////////"<< std::endl;
    // Print raw buffer for debugging
   // print_raw_buffer(buffer, len);
}

//////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////







// Map to store the ephemeral ports for NAT mapping
std::map<uint32_t, uint16_t> nat_map;
uint16_t ephemeral_port = 10000;  // Start from this port for the ephemeral port range



void create_udp_packet(char* buffer, int& packet_len, 
                       const char* tun_src_ip, const char* dst_ip, 
                       uint16_t src_port, uint16_t dst_port, const char* payload);

// Function to perform NAT and forward to netcat
void handle_nat_and_forward(char *buffer, int len, int tun_fd) {
    struct iphdr *ip_header = (struct iphdr *)buffer;

    // If the packet is UDP or TCP with destination port 8888, forward it to netcat
    if (ip_header->protocol == IPPROTO_TCP || ip_header->protocol == IPPROTO_UDP) {
        if (ip_header->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(buffer + (ip_header->ihl << 2));
            if (ntohs(tcp_header->dest) == 8888) {
                std::cout << "Packet with destination port 8888 detected. Performing NAT..." << std::endl;

                std::cout << "---1----" << std::endl;
                // Map the source IP to an ephemeral port
                uint16_t mapped_port = ephemeral_port++;
                nat_map[ip_header->saddr] = mapped_port;

                // Change destination port to 9999 for netcat
                tcp_header->dest = htons(9999);

                // Now send this packet to the netcat listener (nc -l 9999)
                int netcat_fd = socket(AF_INET, SOCK_DGRAM, 0);
                if (netcat_fd < 0) {
                    perror("Error opening socket for netcat forwarding");
                    return;
                }
                      std::cout << "---2----" << std::endl;
                struct sockaddr_in netcat_addr;
                memset(&netcat_addr, 0, sizeof(netcat_addr));
                netcat_addr.sin_family = AF_INET;
                netcat_addr.sin_port = htons(9999);
                netcat_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Assuming netcat is running on localhost

                // Send the modified packet to netcat
                int sent_len = sendto(netcat_fd, buffer, len, 0, (struct sockaddr *)&netcat_addr, sizeof(netcat_addr));
                if (sent_len < 0) {
                    perror("Error sending packet to netcat");
                    close(netcat_fd);
                    return;
                }
                  std::cout << "---3----" << std::endl;
                std::cout << "Packet forwarded to netcat with destination port 9999" << std::endl;

                // Now handle response from netcat and send it back to the original sender
                char response_buffer[2048];
                int response_len = recvfrom(netcat_fd, response_buffer, sizeof(response_buffer), 0, NULL, NULL);
                if (response_len < 0) {
                    perror("Error receiving response from netcat");
                    close(netcat_fd);
                    return;
                }
                  std::cout << "---4----" << std::endl;
                // Send the response back to the original sender
                struct sockaddr_in sender_addr;
                memset(&sender_addr, 0, sizeof(sender_addr));
                sender_addr.sin_family = AF_INET;
                sender_addr.sin_port = htons(ntohs(tcp_header->source));  // Send back to original source port
                sender_addr.sin_addr.s_addr = ip_header->saddr;

                int sent_response_len = sendto(tun_fd, response_buffer, response_len, 0, (struct sockaddr *)&sender_addr, sizeof(sender_addr));
                if (sent_response_len < 0) {
                    perror("Error sending response back to original sender");
                } else {
                    std::cout << "Response sent back to original sender" << std::endl;
                }

                close(netcat_fd);
            }
        } else if (ip_header->protocol == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(buffer + (ip_header->ihl << 2));
            if (ntohs(udp_header->dest) == 8888)
             {
                std::cout << "UDP Packet with destination port 8888 detected. Performing NAT..." << std::endl;


            char *payload = buffer + (ip_header->ihl << 2) + sizeof(struct udphdr);
            int payload_len = len - ((ip_header->ihl << 2) + sizeof(struct udphdr));


            int ppp = aaaa;//ntohs(udp_header->source); 


                std::cout << "---66----" << ppp<<std::endl;
                // Map the source IP to an ephemeral port
                uint16_t mapped_port = ephemeral_port++;
                nat_map[ip_header->saddr] = mapped_port;
                   std::cout << "---6----" << std::endl;
                // Change destination port to 9999 for netcat
                udp_header->dest = htons(9999);

                // Update the UDP checksum (optional for local testing)
                udp_header->check = 0; // Simple checksum bypass

                // Create a socket for forwarding to netcat
                int netcat_fd = socket(AF_INET, SOCK_DGRAM, 0);
                if (netcat_fd < 0) {
                    perror("Error opening socket for netcat forwarding");
                    return;
                }
                   std::cout << "---7----" << std::endl;
                struct sockaddr_in netcat_addr;
                memset(&netcat_addr, 0, sizeof(netcat_addr));
                netcat_addr.sin_family = AF_INET;
                netcat_addr.sin_port = htons(9999);
                netcat_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Assuming netcat is running on localhost
                   std::cout << "---8----" << std::endl;
                // Forward the packet to netcat
               // int sent_len = sendto(netcat_fd, buffer, len, 0, (struct sockaddr *)&netcat_addr, sizeof(netcat_addr));
               
                int sent_len = sendto(netcat_fd, payload, payload_len, 0, (struct sockaddr *)&netcat_addr, sizeof(netcat_addr));
                if (sent_len < 0) {
                    perror("Error sending UDP packet to netcat");
                    close(netcat_fd);
                    return;
                }
                   std::cout << "---9----" << std::endl;
                std::cout << "UDP Packet forwarded to netcat on port 9999" << std::endl;
                
                // Listen for the response from netcat



                  // Source address for receiving data
                struct sockaddr_in src_addr;
                memset(&src_addr, 0, sizeof(src_addr));
                socklen_t src_addr_len = sizeof(src_addr);


                char response_buffer[2048];
                int response_len = recvfrom(netcat_fd, response_buffer, sizeof(response_buffer), 0, 
                            (struct sockaddr*)&src_addr, &src_addr_len);

                      
                      print_raw_buffer(response_buffer, response_len); 


                if (response_len < 0) {
                    perror("Error receiving UDP response from netcat");
                    close(netcat_fd);
                    return;
                }
                   std::cout << "---10----" << std::endl;
                // Modify the response to send it back to the original sender
                udp_header = (struct udphdr *)(response_buffer + (ip_header->ihl << 2));
                udp_header->source = htons(8888); // Restore the original source port
                udp_header->dest = htons(mapped_port); // Restore the original destination port

                struct sockaddr_in sender_addr;
                memset(&sender_addr, 0, sizeof(sender_addr));
                sender_addr.sin_family = AF_INET;
                sender_addr.sin_port = htons(mapped_port);
                sender_addr.sin_addr.s_addr = ip_header->saddr;
                   std::cout << "---11----" << std::endl;
                // Send the response back to the original sender
               
               
              //  int sent_response_len = sendto(tun_fd, response_buffer, response_len, 0, (struct sockaddr *)&sender_addr, sizeof(sender_addr));
             //   if (sent_response_len < 0) {
             //       perror("Error sending UDP response back to original sender");
            //    } else {
            //        std::cout << "UDP Response sent back to original sender" << std::endl;
            //    }
                


///////////////////////////////////////////////////////////////////////

    const char* netcat_response = "Hello from netcat!";
    char buffer[1500]; // Buffer for raw IP packet
    int packet_len = 0;
 std::cout << "---12----" << std::endl;
    // Create an IP+UDP packet
    create_udp_packet(buffer, packet_len, 
                      "100.100.100.1",        // souce interface IP
                      "100.100.100.1", // Destination IP
                      8888,              // Source ephemeral port
                      ppp,              // Destination port
                      netcat_response);
 std::cout << "---13----" << std::endl;
    // Send packet to TUN device
    if (write(tun_fd, buffer, packet_len) < 0) {
        perror("Error writing to TUN interface");
        close(tun_fd);

    }

 std::cout << "---14----" << std::endl;

//////////////////////////////////////////////////////////////////////


//////////////////////////////////

                close(netcat_fd);
            }
        }
    }
}





void create_udp_packet(char* buffer, int& packet_len, 
                       const char* tun_src_ip, const char* dst_ip, 
                       uint16_t src_port, uint16_t dst_port, const char* payload) {
    // Prepare headers
    struct iphdr* ip = (struct iphdr*)buffer;
    struct udphdr* udp = (struct udphdr*)(buffer + sizeof(struct iphdr));

    int payload_len = strlen(payload);

    // Fill UDP header
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(sizeof(struct udphdr) + payload_len);
    udp->check = 0; // Optional checksum (can be left 0 for simplicity)

    // Fill IP header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len);
    ip->id = htons(12345); // Packet ID
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0; // Kernel recalculates this if needed
    ip->saddr = inet_addr(tun_src_ip); // Source IP (TUN interface)
    ip->daddr = inet_addr(dst_ip);     // Destination IP

    // Copy payload
    memcpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), payload, payload_len);

    // Total packet length
    packet_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
}
int write_to_tun(int tun_fd, char* response_buffer, int response_len) {
    // Ensure response_buffer contains a valid IP packet
    int sent_response_len = write(tun_fd, response_buffer, response_len);
    if (sent_response_len < 0) {
        perror("Error writing UDP response to TUN interface");
        return -1;
    }
    std::cout << "UDP Response written to TUN interface, length: " << sent_response_len << std::endl;
    return 0;
}






int main() {
    //client 
    ///////////////////////////////////////////////////////////////////////////////
    char tun_name[IFNAMSIZ] = "tun0";
    tun_fd = create_tun_interface(tun_name);
    std::cout << "Created TUN interface: " << tun_name << std::endl;
  
    // Set IP address and routing for the TUN interface
    set_ip_route();

    ///////////////////////////////////////////////////////////////////////////////

    //server 
    ///////////////////////////////////////////////////////////////////////////////
    char buffer[BUFFER_SIZE];
    while (true) {
        ssize_t nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            perror("Reading from TUN interface");
            close(tun_fd);
            exit(1);
        }
  // Log packet details
        log_packet_details(buffer, nread);

       // Handle NAT and forward to netcat
        handle_nat_and_forward(buffer, nread, tun_fd);

    }

    close(tun_fd);
    return 0;
}


*/