/* Client for 5.2 */
#include <math.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define USERNAME "USERNAME"
#define SERVER_PORT 7800

#define MAX_MSG_SIZE 1024

//#define DEBUG


/* Create and return a socket bound to the given port and server */
int setup_client_socket(const int port, const char* server_name,
        struct sockaddr_in* serv_addr) {
    int sockfd;
    struct hostent* server;

    server = gethostbyname(server_name);
    if (!server) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(EXIT_FAILURE);
    }
    bzero((char*)serv_addr, sizeof(serv_addr));
    serv_addr->sin_family = AF_INET;
    bcopy(server->h_addr_list[0], (char*)&serv_addr->sin_addr.s_addr,
            server->h_length);
    serv_addr->sin_port = htons(port);

    /* Create socket */
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}


int main(int argc, char *argv[]) {
    long g = 15;
    long p = 97;
    long b = 0;
    struct sockaddr_in serv_addr;
    char* server;
    int port;
    int sockfd;
    char buffer[MAX_MSG_SIZE];

    if (argc < 3) {
        fprintf(stderr, "usage: %s hostname secret_key\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    server = argv[1];
    port = SERVER_PORT;

    b = atoi(argv[2]);

    // Make connection
    sockfd = setup_client_socket(port, server, &serv_addr);
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    // Send username to server
    memset(buffer, 0, MAX_MSG_SIZE);
    sprintf(buffer, "%s\n", USERNAME);
#ifdef DEBUG
    printf("username msg --- %s", buffer);
#endif
    int msg_size = strlen(USERNAME);
    if (write(sockfd, buffer, msg_size) != msg_size) {
        perror("write username");
        exit(EXIT_FAILURE);
    }

    // Send g^b mod p to server
    memset(buffer, 0, MAX_MSG_SIZE);
    long req = ((long)pow(g, b)) % p;
    sprintf(buffer, "%ld\n", req);
#ifdef DEBUG
#endif
    printf("req1 msg --- %s", buffer);
    msg_size = strlen(buffer);
    if (write(sockfd, buffer, msg_size) != msg_size) {
        perror("write g^b mod p");
        exit(EXIT_FAILURE);
    }

    // read msg
    memset(buffer, 0, MAX_MSG_SIZE);
    if (read(sockfd, buffer, MAX_MSG_SIZE) < 0) {
        perror("read g^a mod p");
        exit(EXIT_FAILURE);
    }
    long rep = atoi(buffer);
#ifdef DEBUG
#endif
    printf("rep1 msg --- %s", buffer);

    // Send 
    memset(buffer, 0, MAX_MSG_SIZE);
    req = ((long)pow(rep, b)) % p;
    sprintf(buffer, "%ld\n", req);
#ifdef DEBUG
#endif
    printf("req2 msg --- %s", buffer);
    msg_size = strlen(buffer);
    if (write(sockfd, buffer, msg_size) != msg_size) {
        perror("write g^ba mod p");
        exit(EXIT_FAILURE);
    }

    // read status
    memset(buffer, 0, MAX_MSG_SIZE);
    if (read(sockfd, buffer, MAX_MSG_SIZE) < 0) {
        perror("read status");
        exit(EXIT_FAILURE);
    }
    rep = atoi(buffer);
#ifdef DEBUG
#endif
    printf("status msg --- %s", buffer);

    return 0;
}
