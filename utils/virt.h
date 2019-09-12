#ifndef __VIRT__
#define __VIRT__

#include <net/if.h>         // ifreq
#include <sys/types.h>      
#include <sys/stat.h>       
#include <fcntl.h>          
#include <arpa/inet.h>      
#include <sys/ioctl.h>      
#include <linux/if_tun.h>   // tun/tap
#include <errno.h>
#include <unistd.h>         // close

#include <sys/epoll.h>

#define EPOLL_SIZE 50 

// class of virtual device 
typedef struct __virt_t {
    // create TUN device (function)
    int (*vd_tun_init)(struct __virt_t*, char*, char*, char*);
    void (*vd_tun_run)(struct __virt_t*);
    // create TAP device
    // void (*create_tap)(void);

    char ifname[IF_NAMESIZE];
    char ipaddr[16];                    
    char netmask[16];                   
    unsigned char buffer[1024];
    struct epoll_event ev, *events;
    int fd, epfd;                           // fd -> mainly file descriptor
    int noEvents, rcvlen, running;
} virt_t;

virt_t *new_virtd();
int vd_tun_init(virt_t *, char*, char*, char*);
void vd_tun_run(virt_t *);
int tun_alloc(char *dev, int flags);
int set_net(char *dev, char *ipaddr, char *netmask);
void print_ip_packet(unsigned char *packet, int size);

#endif 