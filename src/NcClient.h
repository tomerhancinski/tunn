#ifndef NCCLIENT_H
#define NCCLIENT_H

#include <string>

class NcClient {
public:
    // Constructor and Destructor
    NcClient(const std::string& serverIP, int serverPort);
    ~NcClient();

    // Methods
    bool connectToServer();                  // Connect to the server
    bool sendMessage(const std::string& message); // Send a message to the server
    std::string receiveMessage();           // Receive a message from the server

private:
    std::string serverIP;                   // Server IP address
    int serverPort;                         // Server port
    int sock;                               // Socket descriptor
    static const int BUFFER_SIZE = 1024;

    // Helper methods
    void cleanup();                         // Cleanup resources
};

#endif // NCCLIENT_H
