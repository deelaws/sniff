/* ldev.c
   Martin Casado
   
   To compile:
   >gcc ldev.c -lpcap

   Looks for an interface, and lists the network ip
   and mask associated with that interface.


   Run this Program as root.

*/
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>         /* GIMME a libpcap plz! */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h> /* includes ethernet.h */
#include <netinet/ip.h>
#include <netinet/ether.h>


/*
    Questions:
    
    What is u_char.

    How does the include pcap.h work?
*/


/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts)
{
    static char timestamp_string_buf[256];

    sprintf( timestamp_string_buf, "%d.%06d", 
             (int) ts.tv_sec, 
             (int) ts.tv_usec ) ;

    return timestamp_string_buf ;
}

void capture_one_packet( pcap_t *handle )
{
    char *dev;                       /* name of the device to use */ 
    char *net;                       /* dot notation of the network address */
    char errbuf[PCAP_ERRBUF_SIZE];
    char *mask;                      /* dot notation of the network mask    */
    int ret, i=0, interface, inum;   /* return code */
    bpf_u_int32 netp;                /* ip          */
    bpf_u_int32 maskp;               /* subnet mask */
    struct in_addr addr;
    pcap_if_t *alldevs, *d;
    struct pcap_pkthdr hdr ;     /* pcap.h */
    const u_char *packet ;
    struct ether_header *eptr ;
    u_char *temp_ptr ;

    /* Grab packet. */
    packet = pcap_next( handle, &hdr); /* packet contains the data in the packet */
    
    if ( NULL == packet )
    {
        printf("Didn't grab packet\n") ;
        exit(1);
    }

    printf("Grabbed Packet of length %d\n", hdr.len) ;
    printf("Recieved at ..... %s\n", timestamp_string(hdr.ts) ) ; 
    printf("Ethernet address length is %d\n", ETHER_HDR_LEN) ;

    eptr = (struct ether_header *) packet;

    printf("Data type is %s\n", 
            pcap_datalink_val_to_name(pcap_datalink(handle)));
    printf("Data Type description %s\n",
            pcap_datalink_val_to_description( pcap_datalink(handle) )) ;
    
    /* Check the type of Packet that we have. */
    if ( ETHERTYPE_IP == ntohs( eptr->ether_type))
    {
        printf( "Ethernet type hex:%x dec:%d is an IP packet\n",
                ntohs( eptr->ether_type),
                ntohs( eptr->ether_type)
              ) ;
    }
    else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    {
        printf( "Ethernet type hex:%x dec:%d is an ARP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type)
              ) ;
    }
    else
    {
        printf( "Ethernet type %x not IP packet\n", ntohs(eptr->ether_type) ) ;
    }

    /* Print ethernet destination address. */
    temp_ptr = eptr->ether_dhost ;
    i = ETHER_ADDR_LEN ;          /* Found in linux/if_ether.h */
    printf( "Destination Address: " ) ;
    while( i > 0 )
    {
        printf( "%s%x", ( i == ETHER_ADDR_LEN ) ? " " : ":", *temp_ptr++ ) ;
        i-- ;
    }
    printf( "\n" ) ;
    
    /* Print ethernet source address. */
    temp_ptr = eptr->ether_shost ;
    i = ETHER_ADDR_LEN ;
    printf( "Source Address: ") ;
    while ( i > 0 )
    {
        printf( "%s%x", ( i == ETHER_ADDR_LEN ) ? " " : ":", *temp_ptr++ ) ;
        i-- ;
    }
    printf( "\n" ) ;
    

}


u_int16_t handle_ethernet( u_char *args,
                           const struct pcap_pkthdr* pkthdr,
                           const u_char *packet ) ;

u_int handle_ip( u_char *args,
                 const struct pcap_pkthdr *pkthdr,
                 u_char **packet );

/*
 * pcap_handler callback function which is passed to pcap_loop.
 */
void custom_pcap_callback( u_char                   *arg,
                           const struct pcap_pkthdr *pkthdr,
                           const u_char             *packet )
{
    u_int pkt_length ;
    
    /* Helper Function. */
    u_short type = handle_ethernet( arg, pkthdr, packet ) ;
    if( type == ETHERTYPE_IP )
    {
        /* handle IP packet */
        pkt_length = handle_ip( arg, pkthdr, &packet ) ;
    }
    else if( type == ETHERTYPE_ARP )
    {
        /* handle arp packet */
    }
    else if( type == ETHERTYPE_REVARP )
    {
        /* handle reverse arp packet */
    }
    else
    {
        /* Ignore for now. */
    }
}

void handle_tcp( u_char *args,
                 u_int pkt_length,
                 const u_char *packet )
{
    
}

/*
 * Used to process the IP packets.
 * It returns the underlying protocols segment. i.e TCP/UDP.
 */
u_int handle_ip( u_char *args,
                 const struct pcap_pkthdr *pkthdr,
                 u_char *packet )
{
    u_int pkt_length = pkthdr->len ;
    u_int hdr_len, version ;

    unsigned short int offset ;
    struct iphdr *ip_hdr ;
    int i, total_len ;
    struct in_addr source ;
    struct in_addr destination ;
    
    /* Jump pass the ethernet header. */
    ip_hdr = (struct iphdr *) ( &packet + sizeof(struct ether_header) ) ;
    pkt_length -= sizeof( struct ether_header ) ;

    total_len = ntohs(ip_hdr->tot_len) ;   /* Total length of the packet */
    hdr_len = ntohs( ip_hdr->ihl ) ;       /* Header length. */
    version =  ip_hdr->version  ;   /* Version */
    offset  = ntohs( ip_hdr->frag_off );   /* Offset */

    /* check to see we have a packet of valid length */
    if ( pkt_length < sizeof( struct iphdr ) )
    {
        printf("Truncated ip %d", pkt_length) ;
        return -1 ;
    }
    
    /* check version */
    if ( version != 4 )
    {
      fprintf(stdout,"Unknown version %d\n",version);
      return -1;
    }

    /* Check header length. IHL is in multiples of 4 bytes. */
    if( hdr_len < 5 ) 
    {
        fprintf(stdout,"bad-hlen %d \n", hdr_len);
    }

    /* See if we have as much packet as we should */
    if( pkt_length < total_len)
    {
        /* So the actual length of this packet is less then the 
           Length specified in the IP Header. It must be delivered
           in fragments. */
        printf("\nTruncated IP - %d bytes missing\n",total_len - pkt_length);
    }
    
    source.s_addr = ip_hdr->saddr ;
    destination.s_addr = ip_hdr->daddr ;

    if ( (offset & 0x1FFF) == 0 )
    {
        fprintf( stdout, "IP: ") ;
        fprintf( stdout, "source %s", inet_ntoa( source )) ;
        fprintf( stdout, "to destination %s. Version %d, Offset %d\n",
                 inet_ntoa(destination), version, offset & 0x1fff ) ;
    }

    fflush(stdout) ;
    /* Subtract the size of the IP header from the packet. */
    pkt_length -= (hdr_len*4) ;
    &packet = &packet + sizeof(struct ether_header) + (hdr_len*4) ; 
    return pkt_length ;
}



/*
 * This is called by the pcap_callback function to get
 * additional information regarding the packet
 */
u_int16_t handle_ethernet( u_char *args,
                           const struct pcap_pkthdr* pkthdr,
                           const u_char *packet )
{
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;
    u_int caplen = pkthdr->caplen;
    
    if (caplen < ETHER_HDR_LEN)
    {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);


    fprintf(stdout,"ETH: ");
    fprintf(stdout,"%s "
            , ether_ntoa((struct ether_addr*)eptr->ether_shost));
    fprintf(stdout,"%s"
            ,ether_ntoa((struct ether_addr*)eptr->ether_dhost));

    /* check to see if we have an ip packet */
    if ( ether_type == ETHERTYPE_IP)
    {
        fprintf(stdout,"(IP)") ;
    }
    else  if (ether_type == ETHERTYPE_ARP)
    {
        fprintf(stdout,"(ARP)");
    }
    else  if (ether_type == ETHERTYPE_REVARP)
    {
        fprintf(stdout,"(RARP)");
    }
    else 
    {
        fprintf(stdout,"(?)");
        //exit(1);
    }
    fprintf(stdout,"\n");

    return ether_type;
}

   
int main(int argc, char **argv)
{
    char *dev; /* name of the device to use */ 
    char *net; /* dot notation of the network address */
    char errbuf[PCAP_ERRBUF_SIZE];
    char *mask;/* dot notation of the network mask    */
    int ret, i=0, interface, inum;   /* return code */
    bpf_u_int32 netp; /* ip          */
    bpf_u_int32 maskp;/* subnet mask */
    struct in_addr addr;
    pcap_if_t *alldevs, *d;
    pcap_t *handle;
    struct pcap_pkthdr hdr ;     /* pcap.h */
    const u_char *packet ;
    struct ether_header *eptr ;
    u_char *temp_ptr ;
    struct bpf_program fp;      /* hold compiled program     */


    /* ask pcap to find a valid device for use to sniff on */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
       fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
       exit(1);
    }

    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description){
            printf(" (%s)\n", d->description);
        }
        else{
            printf(" (No description available)\n");
        }
    }

    printf("Enter the interface number (1-%d):",i) ;
    scanf("%d", &interface) ;

    // Jump to the selected interface
    for(d=alldevs, i=0; i< interface-1 ;d=d->next, i++) ;

    dev = d->name ; 
    /* ask pcap for the network address and mask of the device */
    ret = pcap_lookupnet(dev,&netp,&maskp,errbuf) ;

    if(ret == -1)
    {
         printf("%s\n",errbuf);
         exit(1);
    }

    /* get the network address in a human readable form */
    addr.s_addr = netp;
    net = inet_ntoa(addr);

    if(net == NULL)
    {
        perror("inet_ntoa");
        exit(1);
    }

    /* This is the interface's subnet. */
    printf("NET: %s\n",net);

    /* do the same as above for the device's mask */
    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
  
    if(mask == NULL)
    {
        perror("inet_ntoa");
        exit(1);
    }
  
    /* This is the interface's subnet mask. */
    printf("MASK: %s\n",mask);


    /* Open device for listening. */
    /* pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms,
        char *ebuf)*/
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if( handle == NULL )
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    /* Capture Several Packets. */
    if (argc > 2)
    {
        if( -1 == pcap_compile( handle, &fp, argv[2], 0, netp) )
        {
            fprintf(stderr,"Error calling pcap_compile\n") ; 
            exit(1) ;
        }
        
        if( pcap_setfilter( handle, &fp) == -1 )
        {
            fprintf(stderr,"Error setting filter\n") ;
            exit(1) ;
        }
    }
    /* int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
     * Set cnt to -1 to capture infinite packets.
     */
    pcap_loop( handle, atoi(argv[1]), custom_pcap_callback, NULL ) ;  

    return 0;
}









