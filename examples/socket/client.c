// client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    char message[BUFFER_SIZE];
    
    // 1. Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // 2. Configure server address
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    // Convert IPv4 address from text to binary
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("invalid address");
        exit(EXIT_FAILURE);
    }
    
    // 3. Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connection failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Connected to server. Type messages (Ctrl+D to exit):\n");
    
    // 4. Send and receive messages
    while (1) {
        printf("> ");
        
        // Read input from stdin
        if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
            break;  // Ctrl+D
        }
        
        // Remove trailing newline for empty message check
        message[strcspn(message, "\n")] = '\0';
        
        // Send message
        send(sock, message, strlen(message), 0);
        
        // Receive response
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_read = read(sock, buffer, BUFFER_SIZE);
        
        if (bytes_read <= 0) {
            printf("Server disconnected\n");
            break;
        }
        
        printf("Server: %s\n", buffer);
    }
    
    // 5. Close socket
    close(sock);
    
    return 0;
}