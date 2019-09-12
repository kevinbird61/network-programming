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

#define EPOLL_SIZE 5
#define BUF_SIZE 1500       // 1500 (MTU size)

typedef enum {d_TUN=0, d_TAP=1} device_t; 

// class of virtual device 
typedef struct __virt_t {
    // create TUN device (function)
    int (*vd_tun_init)(struct __virt_t*, char*, char*, char*);
    // create TAP device
    int (*vd_tap_init)(struct __virt_t*, char*, char*, char*);
    // run
    void (*vd_tun_run)(struct __virt_t*);


    char ifname[IF_NAMESIZE];
    char ipaddr[16];                    
    char netmask[16];                   
    unsigned char buffer[BUF_SIZE];
    struct epoll_event ev, *events;
    device_t type;
    int fd, epfd;                           // fd -> mainly file descriptor
    int noEvents, rcvlen, running;
} virt_t;

/* member function of virt */
virt_t *new_virtd();
int vd_tun_init(virt_t *, char*, char*, char*);
int vd_tap_init(virt_t *, char*, char*, char*);
void vd_tun_run(virt_t *);

/* helper function */
int tun_alloc(char *dev, int flags);
int set_net(char *dev, char *ipaddr, char *netmask);
void print_ip_packet(unsigned char *packet, int size);
void print_eth_packet(unsigned char *packet, int size);

#endif 