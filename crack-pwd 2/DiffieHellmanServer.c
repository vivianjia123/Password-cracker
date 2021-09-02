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

/* Create and return a socket bound to the given port */
int create_server_socket(const int port) {
    int sockfd;
    struct sockaddr_in serv_addr;

    /* Create socket */
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* Create listen address for given port number (in network byte order)
     *  for all IP addresses of this machine */
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    /* Reuse port if possible */
    int re = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
        perror("Could not reopen socket");
        exit(EXIT_FAILURE);
    }

    /* Bind address to socket */
    if (bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

int main(int argc, char *argv[]) {
    long g = 15;
    long p = 97;
    long a = 23;

    int port = 7800;

    char buffer[MAX_MSG_SIZE];
    int sockfd, newsockfd;
    sockfd = create_server_socket(port);

    /* Listen on socket, define max. number of queued requests */
    if (listen(sockfd, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    newsockfd = accept(sockfd, NULL, NULL);
    if (newsockfd < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // Read from client
    memset(buffer, 0, MAX_MSG_SIZE);
    if (read(newsockfd, buffer, MAX_MSG_SIZE) <= 0) {
        perror("read");
        exit(EXIT_FAILURE);
    }
    printf("username msg ----- %s", buffer);

    // Read from client - req1 
    memset(buffer, 0, MAX_MSG_SIZE);
    if (read(newsockfd, buffer, MAX_MSG_SIZE) <= 0) {
        perror("read");
        exit(EXIT_FAILURE);
    }
    printf("req1 msg----- %s", buffer);

    // send to client, g^a mod p
    memset(buffer, 0, MAX_MSG_SIZE);
    long rep = ((long)pow(g, a)) % p;
    sprintf(buffer, "%ld\n", rep);
    printf("rep1 msg ---- %s", buffer);
    if (write(newsockfd, buffer, strlen(buffer)) <= 0) {
        perror("send req1");
        exit(EXIT_FAILURE);
    }

    // Read from client - req2 
    memset(buffer, 0, MAX_MSG_SIZE);
    if (read(newsockfd, buffer, MAX_MSG_SIZE) <= 0) {
        perror("read");
        exit(EXIT_FAILURE);
    }
    printf("req2 msg----- %s", buffer);

    int req = atoi(buffer);

    // send to client, g^a mod p
    memset(buffer, 0, MAX_MSG_SIZE);
    if (req == ((long)pow(req, a)) % p)
        sprintf(buffer, "%s\n", "OK");
    else
        sprintf(buffer, "%s\n", "NO");
    printf("status msg ---- %s", buffer);
    if (write(newsockfd, buffer, strlen(buffer)) <= 0) {
        perror("send req2");
        exit(EXIT_FAILURE);
    }

    return 0;
}
