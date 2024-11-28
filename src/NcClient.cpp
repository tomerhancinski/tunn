
#include "NcClient.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

// Constructor
NcClient::NcClient(const std::string& serverIP, int serverPort)
    : serverIP(serverIP), serverPort(serverPort), sock(-1) {}

// Destructor
NcClient::~NcClient() {
    cleanup();
}

// Cleanup method to close the socket
void NcClient::cleanup() {
    if (sock != -1) {
        close(sock);
        sock = -1;
    }
}

// Connect to the server
bool NcClient::connectToServer() {
    sockaddr_in serverAddr{};

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation failed.\n";
        return false;
    }

    // Setup server address
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);

    if (inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr) <= 0) {
        std::cerr << "Invalid server address.\n";
        cleanup();
        return false;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Connection failed.\n";
        cleanup();
        return false;
    }

    std::cout << "Connected to the server at " << serverIP << ":" << serverPort << "\n";
    return true;
}

// Send a message to the server
bool NcClient::sendMessage(const std::string& message) {
    if (send(sock, message.c_str(), message.size(), 0) < 0) {
        std::cerr << "Failed to send message.\n";
        return false;
    }
    std::cout << "Message sent: " << message << "\n";
    return true;
}

// Receive a message from the server
std::string NcClient::receiveMessage() {
    char buffer[BUFFER_SIZE];
    int bytesReceived = recv(sock, buffer, BUFFER_SIZE - 1, 0);

    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0'; // Null-terminate the received message
        std::cout << "Message received: " << buffer << "\n";
        return std::string(buffer);
    }

    std::cerr << "Failed to receive message or connection closed.\n";
    return "";
}
