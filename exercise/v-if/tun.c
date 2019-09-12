#include <stdio.h>
#include <stdlib.h>

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

#include <string.h>

int tun_alloc(char *dev, int flags);
int set_ip(char *dev, char *ipaddr, char *netmask);
void print_ip_packet(unsigned char *packet, int size);

int main(int argc, char *argv[])
{
    char ifname[IF_NAMESIZE];
    char ipaddr[16];
    char netmask[16];
    int tunfd = 0;

    int                 epfd;           // EPOLL file descriptor
    struct epoll_event  ev, events[5];  // Used for EPOLL
    unsigned char       buffer[1024];   // Receive packet buffer
    int                 noEvents;       // EPOLL event number
    int                 rcvlen=0, running=1;
    
    memset(ifname, 0, IF_NAMESIZE);
    memset(ipaddr, 0, 16);
    memset(netmask, 0, 16);

    if( argc == 4 )
    {
        strncpy( ifname, argv[1], IF_NAMESIZE - 1 );
        strncpy( ipaddr, argv[2], 15 );
        strncpy( netmask, argv[3], 15 );
    }
    else
    {
        exit(1);
    }

    printf( "Interface: %s\n", ifname );
    printf( "IP Address: %s\n", ipaddr );
    printf( "Netmask: %s\n", netmask );
    
    // IFF_TUN: 
    // namely network tunnel, simulates a network layer device and it
    // operates with layer 3 packets like IP packets. 
    // IFF_TAP:
    // namely network tap, simulates a link layer device and it operates 
    // with layer 2 packets like Ethernet frames.
    // IFF_NO_PI:
    // tells the kernel to not provide packet information. 

    // create our tunnel instance
    if( ( tunfd = tun_alloc( ifname, IFF_TUN | IFF_NO_PI ) ) < 0 )
    {
        printf( "Create TUN/TAP interface fail!!\n" );
    }
    set_ip( ifname, ipaddr, netmask );

    // create epoll fd
    epfd = epoll_create(5);

    // Add socket into the EPOLL set
    ev.data.fd = tunfd;
    ev.events = EPOLLIN | EPOLLET;
    epoll_ctl(epfd, EPOLL_CTL_ADD, tunfd, &ev);

    // Use ctrl-c to interrupt the process 
    while(running)
    {
        noEvents = epoll_wait(epfd, events, __FD_SETSIZE, -1);

        for(int i=0; i<noEvents; i++)
        {
            if(events[i].events & EPOLLIN && tunfd == events[i].data.fd)
            {
                memset(buffer, 0, 1024);
                if((rcvlen = read(tunfd, buffer, 1024)) < 0)
                {
                    perror("Reading data");
                    running = 0;
                }
                else
                {
                    // If using TUN, we parse this as an IP packet
                    // If using TAP, buffer will be an Ethernet frame
                    print_ip_packet(buffer, rcvlen);
                }
                
            }
        }
    }

    close(tunfd);

    return 0;
}

int tun_alloc( char *dev, int flags)
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if( ( fd = open( clonedev , O_RDWR ) ) < 0 ) 
    {
        perror( "Opening /dev/net/tun" );
        return fd;
    }

    memset( &ifr, 0, sizeof( ifr ) );

    ifr.ifr_flags = flags;
    
    // Set the interface name.
    if ( strlen( dev ) > 0 ) 
    {
        strncpy( ifr.ifr_name, dev, IF_NAMESIZE );
    }

    if( ( err = ioctl( fd, TUNSETIFF, (void *)&ifr ) ) < 0 ) 
    {
        perror( "ioctl(TUNSETIFF)" );
        close( fd );
        return err;
    }

    strcpy( dev, ifr.ifr_name );

    return fd;
}

int set_ip(char *dev, char *ipaddr, char *netmask)
{
    struct ifreq ifr;
    int err;
    
    // ioctl needs one fd as an input.
    // Request kernel to give me an unused fd. 
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    
    // Set the interface name.
    if ( *dev ) 
    {
        strncpy( ifr.ifr_name, dev, IF_NAMESIZE );
    }
    ifr.ifr_addr.sa_family = AF_INET;
    
    // Set IP address
    // The structure of ifr.ifr_addr.sa_data is "struct sockaddr"
    // struct sockaddr
    // {
    //      unsigned short    sa_family;
    //      char              sa_data[14];
    // }
    // This is why +2 is used.
    if( ( err = inet_pton( AF_INET, ipaddr, ifr.ifr_addr.sa_data + 2 ) ) != 1 )
    {
        perror( "Error IP address." );
        close( fd );
        return err;
    }
    if( ( err = ioctl( fd, SIOCSIFADDR, &ifr ) ) < 0 )
    {
        perror( "IP: ioctl(SIOCSIFADDR)" );
        close( fd );
        return err;
    }
    
    // Set netmask
    if( ( err = inet_pton( AF_INET, netmask, ifr.ifr_addr.sa_data + 2 ) ) != 1 )
    {
        perror( "Error IP address." );
        close( fd );
        return err;
    }
    if( ( err = ioctl( fd, SIOCSIFNETMASK, &ifr ) ) < 0 )
    {
        perror( "Netmask: ioctl(SIOCSIFNETMASK)" );
        close( fd );
        return err;
    }
    
    // Enable the interface
    // Get the interface flag first and add IFF_UP | IFF_RUNNING.
    if( ( err = ioctl( fd, SIOCGIFFLAGS, &ifr ) ) < 0 )
    {
        perror( "ioctl(SIOCGIFFLAGS)" );
        close( fd );
        return err;
    }

    ifr.ifr_flags |= ( IFF_UP | IFF_RUNNING );
    if( ( err = ioctl( fd, SIOCSIFFLAGS, &ifr ) ) < 0 )
    {
        perror( "ioctl(SIOCSIFFLAGS)" );
        close( fd );
        return err;
    }
    
    close( fd );
    
    return 1;
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