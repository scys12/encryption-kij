#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#define PORT 8080
#define HOST "127.0.0.1"
#define SIZE 1024

void send_file(char *filename, int sockfd) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
    {
        perror("Error in reading file");
        exit(EXIT_FAILURE);
    }
    
    int n;
    char data[SIZE] = {0};

    while (fgets(data, SIZE, fp) != NULL)
    {
        if (send(sockfd, data, sizeof(data), 0) == -1)
        {
            perror("Error sending file");
            exit(EXIT_FAILURE);
        }
        bzero(data, SIZE);
    }
    
}

int main() {
    char *message = "Hello from client";
    int sock = 0, valread;
    struct sockaddr_in serv_address;
    char buffer[SIZE] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    serv_address.sin_family = AF_INET;
    serv_address.sin_port = htons(PORT);

    if (inet_pton(AF_INET, HOST, &serv_address.sin_addr) <= 0)
    {
        perror("Invalid Address");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&serv_address, sizeof(serv_address)) < 0)
    {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    send(sock, message, strlen(message), 0);
    printf("Hello message\n");
    valread = read(sock, buffer, SIZE);
    printf("%s\n", buffer);

    send_file("test.txt", sock);
    printf("File data send successfully\n");
    close(sock);
    
    return EXIT_SUCCESS;
}