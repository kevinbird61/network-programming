#ifndef __SOCK__
#define __SOCK__

#include <netdb.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>

#include <arpa/inet.h>

#define PORT "3490"     // port number
#define BACKLOG 10      // pending connections queue
#define MAXDATASIZE 100 // number of bytes

#endif