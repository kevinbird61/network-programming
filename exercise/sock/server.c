#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "sock.h"

void sigchld_handler(int s);                // handle all dead processes
void *get_in_addr(struct sockaddr *sa);     // get sockaddr, IPv4 or IPv6

int main(void)
{
    int sockfd, newfd; // sock_fd -> listen, new_fd -> new conn
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage user_addr; // user's address info
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // using my IP

    if((rv=getaddrinfo(NULL, PORT, &hints, &servinfo))!=0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // find available interface, and bind it
    for(p=servinfo; p!=NULL; p=p->ai_next){
        if((sockfd=socket(p->ai_family, p->ai_socktype, p->ai_protocol))==-1){
            perror("server: socket");
            continue;
        }

        if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))==-1){
            perror("setsockopt");
            exit(1);
        }

        if(bind(sockfd, p->ai_addr, p->ai_addrlen)==-1){
            perror("server: bind");
            close(sockfd);
            continue;
        }

        break; // finish
    }

    if(p==NULL){
        fprintf(stderr, "server: failed to bind\n");
        return 2;
    }
    
    freeaddrinfo(servinfo); 

    if(listen(sockfd, BACKLOG)==-1){
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // handle all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    // clean the dummy processes
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    // main loop 
    while(1){
        sin_size = sizeof(user_addr);
        newfd = accept(sockfd, (struct sockaddr *)&user_addr, &sin_size);
        if(newfd==-1){
            perror("accept");
            continue;
        }

        inet_ntop(user_addr.ss_family, get_in_addr((struct sockaddr *)&user_addr), s, sizeof(s));
        printf("server: got connection from %s\n", s);

        // create childprocess to answer
        if(!fork()){
            close(sockfd); // need no listener in childp
            if(send(newfd, "Hello, world!", 13, 0)==-1)
                perror("send");
            close(newfd);
            exit(0);
        }
    }

    return 0;
}

void sigchld_handler(int s)
{
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}