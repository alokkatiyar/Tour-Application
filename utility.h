#include <string.h>
#include <time.h>
#include "unp.h"

#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> 
#include <netinet/ip_icmp.h> 
#include <netinet/ip.h> 
#include <sys/socket.h>
#include <setjmp.h>
#include <sys/un.h>
#include <errno.h>

#include "hw_addrs.h"


#define MAX_TOUR_NODES 128
#define MULTICAST_ADDRESS "229.100.137.107"
#define MULTICAST_PORT 5039
#define PROTOCOL_IP_TOUR 215
#define PROTOCOL_IP_TOUR_ID 8011
#define DOMAIN_SUN_PATH "/tmp/akatiyar"

#define PROTOCOL_ETH_ARP 8737
#define ARP_ID 0x962

typedef struct TourPacket {
   char multicastIP[INET_ADDRSTRLEN];
   int multicastPort;
   int numTourNodes;
   // Index of the current destination
   int currentNodeIndex;
   unsigned int tourNodeIP[MAX_TOUR_NODES];
} TourPacket;

typedef struct TourNode {
   int routingSocket;
   int pingInSocket;
   int pingOutSocket;
   int multicastSocket;
   // At any given moment one tour will be active. Maintain it
   unsigned int tourSourceIP;
   // Previous node in the tour
   // currently pinging
   //int isPinging;
   // Total ping response received
   int numPingResponseReceived;
   // Multicast Port of the tour
   int tourMultiCastPort;
   char tourMultiCastIP[INET_ADDRSTRLEN];
   int nodeIsDestination;
   unsigned int destTourPrevIP;
} TourNode;


typedef struct PingThread {
  unsigned int tourPrevIP;
  // Next ping sequence number
  int nextPingSequenceNum;
  pthread_mutex_t threadLock;
  int threadPleaseExit;
} PingThread;

typedef struct HWaddr {
   int             sll_ifindex;  /* Interface number */
   unsigned short  sll_hatype;   /* Hardware type */
   unsigned char   sll_halen;    /* Length of address */
   unsigned char   sll_addr[8];	 /* Physical layer address */
} HWaddr;

typedef struct ArpNode {
   int domainSocket;
   int pfPacketSocket;
   struct sockaddr_ll pfPacketSocketAddress;
} ArpNode;

typedef struct ArpCache {
   unsigned int IPAddress;
   unsigned char addr[8];
   int ifindex;
   unsigned short hatype;
   int connectionFd;
   struct ArpCache * next;
} ArpCache;

typedef enum ArpPacketType {
   ARP_REQUEST = 1,
   ARP_REPLY
} ArpPacketType;

typedef struct ArpPacket {
    unsigned short id;
    ArpPacketType type;
    char senderMac[IF_HADDR];
    unsigned int senderIP;
    char targetMac[IF_HADDR];
    unsigned int targetIP;
} ArpPacket;

