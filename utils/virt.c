/**
 * Create virtual devices/interfaces
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "virt.h"

virt_t* new_virtd()
{
    virt_t *newobj = (virt_t *)malloc(sizeof(virt_t));
    // initialize instance
    newobj->rcvlen=0;
    newobj->running=1;
    if(newobj!=NULL){
        newobj->vd_tun_init = &vd_tun_init;
        newobj->vd_tun_run = &vd_tun_run;
    }

    return newobj;
}

int vd_tun_init(virt_t *obj, char* ifname, char* ipaddr, char* netmask)
{
    /* init & clear */
    memset(obj->ifname, 0 , IF_NAMESIZE);
    memset(obj->ipaddr, 0, 16);
    memset(obj->netmask, 0, 16);

    /* assign */
    strncpy(obj->ifname, ifname, IF_NAMESIZE-1);
    strncpy(obj->ipaddr, ipaddr, 15);
    strncpy(obj->netmask, netmask, 15);

    printf( "Interface: %s\n", obj->ifname );
    printf( "IP Address: %s\n", obj->ipaddr );
    printf( "Netmask: %s\n", obj->netmask );

    /* create tunnel instance */
    if((obj->fd=tun_alloc(obj->ifname, IFF_TUN | IFF_NO_PI)) < 0)
    {
        printf("Create TUN interface fail!\n");
    }

    /* set net (interface) */
    set_net(obj->ifname, obj->ipaddr, obj->netmask);

    /* create epoll */
    obj->epfd = epoll_create(EPOLL_SIZE);
    obj->events = (struct epoll_event*)malloc(EPOLL_SIZE*sizeof(struct epoll_event));
    obj->ev.data.fd = obj->fd;
    obj->ev.events = EPOLLIN | EPOLLET;
    epoll_ctl(obj->epfd, EPOLL_CTL_ADD, obj->fd, &obj->ev);
}

void vd_tun_run(virt_t *obj)
{
    while(obj->running)
    {
        obj->noEvents = epoll_wait(obj->epfd, obj->events, __FD_SETSIZE, -1);
        for(int i=0; i<obj->noEvents; i++)
        {
            if(obj->events[i].events & EPOLLIN && obj->fd == obj->events[i].data.fd)
            {
                memset(obj->buffer, 0, 1024);
                if((obj->rcvlen=read(obj->fd, obj->buffer, 1024))<0)
                {
                    perror("Reading data");
                    obj->running=0;
                }
                else
                {
                    // If using TUN, we parse this as an IP packet
                    // If using TAP, buffer will be an Ethernet frame
                    print_ip_packet(obj->buffer, obj->rcvlen);
                }
                
            }
        }
    }
}

void print_ip_packet(unsigned char *packet, int size)
{
    int ipheaderlen = 0;
    int protocol = 0;
    int i = 0, offset = 0;
    
    if( size < 20 )
    {
        printf( "Size < IP Header!!\n" );
        return;
    }
    
    ipheaderlen = ( packet[0] & 0x0F ) * 4;
    protocol = packet[9];
    
    printf( "=========================================\n" );
    printf( "IP Header:\n\t" );
    
    for( i = 0 ; i < ipheaderlen ; i++ )
    {
        printf( "%02X ", packet[i] );
        
        if( i % 4 == 3 )
        {
            printf( "\n\t" );
        }
    }

    printf( "\n" );
    offset = ipheaderlen;
    
    if( protocol == 6 )
    {
        printf( "TCP Header:\n\t" );
        for( i = 0 ; i < 20 ; i++ )
        {
            printf( "%02X ", packet[offset + i] );
            if( i % 4 == 3 )
            {
                printf( "\n\t" );
            }
        }
        offset += 20;
        printf( "\n" );
    }
    else if( protocol == 17 )
    {
        printf( "UDP Header:\n\t" );
        
        for( i = 0 ; i < 8 ; i++ )
        {
            printf( "%02X ", packet[offset + i] );
        
            if( i % 4 == 3 )
            {
                printf( "\n\t" );
            }
        }
        
        offset += 8;
        printf( "\n" );
    }
    
    printf( "Data Payload:\n\t" );

    for(int i = offset ; i < size ; i++ )
    {
        printf( "%02X ", packet[i] );
        if( i % 8 == ( ( offset - 1) % 8 ) )
        {
            printf( "\n\t" );
        }
    }
    
    printf( "\n" );
    printf( "=========================================\n" );
}

int set_net(char *dev, char *ipaddr, char *netmask)
{
    struct ifreq ifr;
    int err;

    /* ioctl needs one fd as an input 
    * request kernel to give an unused fd.
    * 
    * (enum) IPPROTO_IP: ipv4
    */
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    /* set the interface name */
    if(*dev)
        strncpy(ifr.ifr_name, dev, IF_NAMESIZE);
    ifr.ifr_addr.sa_family=AF_INET; // ipv4

    /* set ip address 
    * The structure of ifr.ifr_addr.sa_data is "struct sockaddr"
    * struct sockaddr
    * {
    *      unsigned short    sa_family;
    *      char              sa_data[14];
    * }
    * This is why +2 is used.
    */
    if((err=inet_pton(AF_INET, ipaddr, ifr.ifr_addr.sa_data+2))!=1)
    {
        perror("Error/Illegal IP address.");
        close(fd);
        return err;
    }
    if((err=ioctl(fd, SIOCSIFADDR, &ifr))<0)
    {
        perror( "IP: ioctl(SIOCSIFADDR)" );
        close(fd);
        return err;
    }

    /* set netmask */
    if((err=inet_pton(AF_INET, netmask, ifr.ifr_addr.sa_data+2))!=1)
    {
        perror( "Error IP address." );
        close(fd);
        return err;
    }
    if((err=ioctl(fd, SIOCSIFNETMASK, &ifr))<0)
    {
        perror( "Netmask: ioctl(SIOCSIFNETMASK)" );
        close(fd);
        return err;
    }

    /* enable the interface 
    * get the interface flag first and add IFF_UP | IFF_RUNNING.
    */
    if((err=ioctl(fd, SIOCGIFFLAGS, &ifr))<0)
    {
        perror( "ioctl(SIOCGIFFLAGS)" );
        close(fd);
        return err;
    }
    ifr.ifr_flags |= ( IFF_UP | IFF_RUNNING );
    if((err=ioctl(fd, SIOCGIFFLAGS, &ifr))<0)
    {
        perror( "ioctl(SIOCGIFFLAGS)" );
        close(fd);
        return err;
    }

    close(fd);
    return 1;
}

// using flag to create TUN or TAP
int tun_alloc(char *dev, int flags)
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if((fd=open(clonedev, O_RDWR )) < 0) 
    {
        perror( "Opening /dev/net/tun");
        return fd;
    }

    memset( &ifr, 0, sizeof( ifr ) );

    ifr.ifr_flags = flags;
    
    // set the interface name if available
    if(strlen(dev) > 0)
    {
        /* if a device name was specified, put it in the structure; otherwise,
        * the kernel will try to allocate the "next" device of the
        * specified type */
        strncpy(ifr.ifr_name, dev, IF_NAMESIZE );
    }

    // try to create the 
    if((err=ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) 
    {
        perror( "ioctl(TUNSETIFF)" );
        close( fd );
        return err;
    }

    /* if the operation was successful, write back the name of the
    * interface to the variable "dev", so the caller can know
    * it. Note that the caller MUST reserve space in *dev (see calling
    * code below) */
    strcpy(dev, ifr.ifr_name );


    /* this is the special file descriptor that the caller will use to talk
    * with the virtual interface */
    return fd;
}