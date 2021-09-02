/**
* COMP30023 Computer Systems 2019
* Project 2: Password cracker
*
* Created by Ziqi Jia on 19/05/19.
* Copyright © 2019 Ziqi Jia. All rights reserved.
*
* References:
* power function
* 	https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/
* main function
* 	comp30023 lab5 solution
*
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

#define HOSTNAME "172.26.37.44"
#define SERVER_PORT 7800
static char *USERNAME = "ziqij";

int power(int a, int b, int p);
/* Iterative Function to calculate modular power */
int power(int a, int b, int p)
{
  int res = 1;
  a = a % p;
  while (b > 0)
  {
    if (b % 2){
      res = (res*a) % p;
    }
    a = (a*a) % p;
    b = b/2;
  }
  return res;
}


/* Main function */
int main(int argc, char * argv[])
{
  // calculate b: convert first 2 hexadecimal digits in integer
  char first_two[3];
  memcpy(first_two, argv[1], 2);
  first_two[2]='\0';

  int b;
  b = (int)strtol(first_two, NULL, 16);
  //sscanf(first_two, "%x", &b);
  printf("b: %d\n", b);

	int g = 15;
	int p = 97;

	// find host
	struct hostent * remote_host;
	remote_host = gethostbyname(HOSTNAME);
	if (remote_host == NULL)
	{
    fprintf(stderr, "ERROR, no such host\n");
    exit(EXIT_FAILURE);
  }

	// create and initialise server address
  struct sockaddr_in serv_addr;
  bzero(&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(SERVER_PORT);
	//serv_addr.sin_addr = *((struct in_addr *)remote_host->h_addr);
	bcopy(remote_host->h_addr_list[0], (char *)&serv_addr.sin_addr.s_addr,
		remote_host->h_length);

  // create socket and connect to the server
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
  {
    perror("ERROR opening socket");
    exit(0);
  }
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
    perror("ERROR connecting");
    exit(EXIT_FAILURE);
  }

  int n;
  char send_buffer[256];

	// send user name
	sprintf(send_buffer, "%s\n", USERNAME);
	//send(sockfd, send_buffer, strlen(send_buffer), 0);
  n = write(sockfd, send_buffer, strlen(send_buffer));
  if(n < 0){
    perror("ERROR: writing to socket");
    exit(EXIT_FAILURE);
  }
	printf("Send username: %s\n", USERNAME);

	// send g^b (mod p)
  bzero(send_buffer, 256);
  int modpow = power(g, b, p);
	sprintf(send_buffer, "%d\n", modpow);
	//send(sockfd, send_buffer, strlen(send_buffer), 0);
  n = write(sockfd, send_buffer, strlen(send_buffer));
  if(n < 0){
    perror("ERROR: writing to socket");
    exit(EXIT_FAILURE);
  }
	printf("Send g^b mod p = %s\n", send_buffer);

  // read the value of g^b (mod p)
  bzero(send_buffer, 256);
  n = read(sockfd, send_buffer, 255);
  printf("Received g^a mod p = %s\n", send_buffer);
  strtok(send_buffer,"\n");
  int recv_number = atoi(send_buffer);

  // send the shared secret
  bzero(send_buffer, 256);
  int modpow2 = power(recv_number, b, p);
  printf("Shared secret = %d\n", modpow2);
  sprintf(send_buffer, "%d\n", modpow2);
  //send(sockfd, send_buffer, strlen(send_buffer), 0);
  n = write(sockfd, send_buffer, strlen(send_buffer));
  if(n < 0){
    perror("ERROR: writing to socket");
    exit(EXIT_FAILURE);
  }

  // read the server response
  bzero(send_buffer, 256);
  n = read(sockfd, send_buffer, 255);
  printf("Status report: %s\n", send_buffer);


	close(sockfd);

	return 0;
}
