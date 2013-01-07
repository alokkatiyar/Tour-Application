#include "utility.h"


unsigned int selfIPAddr;
char selfIPAddrStr[INET_ADDRSTRLEN];
char selfHostName[256];
char selfEthernetAddress[IF_HADDR];
int selfEth0InterfaceIndex;
TourNode tourNode;

PingThread pingThread[50];
int numPingThreads;

void InitializeSelf()
{
   int retval;
   struct hostent *hostEntry;
   struct sockaddr_in address;

   retval = gethostname(selfHostName, sizeof (selfHostName));
   if (retval < 0) {
      printf("Error getting hostname.\n");
      exit(0);
   }

   if (NULL == (hostEntry = gethostbyname(selfHostName))) {
      printf("Error getting IP address for self hostname %s.\n", selfHostName);
      exit(0);
   }

   selfIPAddr = (((struct in_addr *)hostEntry->h_addr)->s_addr);
   Inet_ntop(AF_INET, (struct in_addr *)hostEntry->h_addr_list[0], selfIPAddrStr, INET_ADDRSTRLEN);
}

void DumpTourPacket(TourPacket *tourPacket)
{
   int i;
   printf("Multicast Address %s Port %d\n", tourPacket->multicastIP, tourPacket->multicastPort);
   printf("Total tour nodes %d currentNodeIndex %d\n", tourPacket->numTourNodes, tourPacket->currentNodeIndex);
   /*for (i = 0; i < tourPacket->numTourNodes; i++) {
      printf("IP address at index %d is %d\n", i, tourPacket->tourNodeIP[i]);
   }*/
}

InitializeTour(int argc, char *argv[], TourPacket * tourPacket)
{
   int currentIndex = 0;
   struct hostent *hostEntry;
   memset(tourPacket, 0, sizeof(*tourPacket));

   memcpy(tourPacket->multicastIP, MULTICAST_ADDRESS, INET_ADDRSTRLEN);
   tourPacket->multicastPort = MULTICAST_PORT;


   tourPacket->tourNodeIP[currentIndex] = selfIPAddr;
   currentIndex++;

   while(argv[currentIndex]) {
      if (NULL == (hostEntry = gethostbyname(argv[currentIndex]))) {
         printf("Tour has a node which is invalid. node %s is unrecognized.\n", argv[currentIndex]);
         exit(0);
      }

      tourPacket->tourNodeIP[currentIndex] = (((struct in_addr *)hostEntry->h_addr)->s_addr);
      currentIndex++;
   }

   tourPacket->numTourNodes = currentIndex;
   tourPacket->currentNodeIndex = 1;
   DumpTourPacket(tourPacket);
}

void InitializeTourNode(TourNode * tourNode, int tourOriginator)
{
   int on = 1;
   // ttl option (multicast) has to be character
   char ttlOption = 1;
   struct sockaddr_in multicastAddr;
   struct ip_mreq mrequest;

   memset(&multicastAddr, 0, sizeof (multicastAddr));
   memset(&mrequest, 0, sizeof (mrequest));

   tourNode->routingSocket = socket(AF_INET, SOCK_RAW, PROTOCOL_IP_TOUR);
   if(tourNode->routingSocket < 0) {
      printf("Error creating routing socket.\n");
      exit(0);
   }

   if(setsockopt(tourNode->routingSocket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
      printf("Error setting IP_HDRINCL on routing socket.\n");
      exit(0);
   }

   tourNode->pingInSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
   if(tourNode->pingInSocket < 0) {
         printf("Error creating the pingInSocket\n");
         exit(0);
   }

   tourNode->pingOutSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
   if (tourNode->pingOutSocket < 0) {
      printf("Error creating the pingInSocket\n");
      exit(0);
   }

   tourNode->multicastSocket = socket(AF_INET, SOCK_DGRAM, 0);
   if (tourNode->multicastSocket < 0) {
      printf("Error creating the pingInSocket\n");
      exit(0);
   }

   // Set REUSEADDR so that we can bind multiple instances of this program for testing
   on = 1;
   if (setsockopt(tourNode->multicastSocket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
      printf("Error setting SO_REUSEADDR on multicast socket.\n");
      //exit(0);
   }

   if (setsockopt(tourNode->multicastSocket, IPPROTO_IP, IP_MULTICAST_TTL, &ttlOption, sizeof(ttlOption)) < 0) {
      printf("Error setting TTL=1 on multicast socket.\n");
      exit(0);
   }

   // Bind to multicast address inaddrany/port
   multicastAddr.sin_family = AF_INET;
   multicastAddr.sin_port = htons(MULTICAST_PORT);
   // Bind to INADDR_ANY to be able to send and receive on same multicast socket.
   multicastAddr.sin_addr.s_addr = htonl(INADDR_ANY);

   Bind(tourNode->multicastSocket, (struct sockaddr *)&multicastAddr, sizeof (multicastAddr));

   if (tourOriginator) {
      // Join multicast group
      Inet_pton(AF_INET, MULTICAST_ADDRESS, &mrequest.imr_multiaddr);
      mrequest.imr_interface.s_addr = htonl(INADDR_ANY);

      if (setsockopt(tourNode->multicastSocket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mrequest, sizeof(mrequest)) < 0) {
         printf("Error setting setsockopt IP_ADD_MEMBERSHIP\n");
         exit(0);
      }
      tourNode->tourMultiCastPort = MULTICAST_PORT;
      memcpy(tourNode->tourMultiCastIP, MULTICAST_ADDRESS, INET_ADDRSTRLEN);
   }

}

void
SendIPPacket(TourPacket *payLoad, unsigned int sourceIP, unsigned int destIP)
{
   struct ip *ipHeader;
   char *ipPacket;
   struct sockaddr_in destination;
   int retval;

   ipPacket = (char *)calloc(1, sizeof(*ipHeader) + sizeof(*payLoad));
   if (!ipPacket) {
      printf("Unable to allocate IP header.\n");
      return;
   }
   ipHeader = (struct ip *)ipPacket;
   ipHeader->ip_v = IPVERSION;
   ipHeader->ip_hl = sizeof(struct ip) / 4; // size of struct ip = 20 bytest 20 / 4 = 5
   ipHeader->ip_tos = 0;
   ipHeader->ip_p = PROTOCOL_IP_TOUR;
   ipHeader->ip_len = htons(sizeof(*ipHeader) + sizeof(*payLoad));
   ipHeader->ip_id = htons(PROTOCOL_IP_TOUR_ID);
   ipHeader->ip_off = 0;
   ipHeader->ip_ttl = htons(64); // ttl is 64 hops
   ipHeader->ip_sum  = 0;
   ipHeader->ip_src.s_addr = sourceIP;
   ipHeader->ip_dst.s_addr = destIP;

   memcpy(ipPacket + sizeof(*ipHeader), payLoad, sizeof(*payLoad));

   ipHeader->ip_sum = in_cksum((ushort *)ipHeader, sizeof(*ipHeader) + sizeof(*payLoad));

   destination.sin_family = AF_INET;
   destination.sin_addr.s_addr = destIP;

   retval = sendto(tourNode.routingSocket, ipPacket, sizeof(*ipHeader) + sizeof(*payLoad), 0, (struct sockaddr *)&destination, sizeof(destination));
   if (retval < 0) {
      printf("Failed to send Tour IP packet %s.\n", strerror(errno));
   }

   free(ipHeader);
}

void
SendTour(TourPacket *tourPacket)
{
   //printf("Sending tour packet.\n");
   SendIPPacket(tourPacket, tourPacket->tourNodeIP[0], tourPacket->tourNodeIP[tourPacket->currentNodeIndex]);
}

#define ICMPCHECKSUMLEN (8 + 56)
#define IPCHECKSUMLEN (ICMPCHECKSUMLEN + sizeof(struct ip))
#define TOTALICMPLEN (IPCHECKSUMLEN  + sizeof(struct ethhdr))

void *
StartPingForTour(void *arg)
{
   PingThread *myPingData = (PingThread *)arg;
   char buf[TOTALICMPLEN];
   int retval;
   struct sockaddr_ll pfAddress;
   struct sockaddr_in destIPAddr;
   struct HWaddr hwaddr;
   socklen_t sockAddrLen;
   int i;
   struct ethhdr *ethernetHeader;
   struct ip     *ipHeader;
   struct icmp   *icmpHeader;
   unsigned int pingTargetIP = myPingData->tourPrevIP;
   char pingTargetHostName[256];
   struct hostent *hostEntry = NULL;
   char pingTargetIPStr[INET_ADDRSTRLEN];   

   pthread_detach(pthread_self());
   
   if ((hostEntry = gethostbyaddr(&pingTargetIP, 4 , AF_INET)) == NULL) {
      pingTargetHostName[0] = 0;
      printf("gethostbyaddr failed.\n");
   } else {
      strcpy(pingTargetHostName, hostEntry->h_name);
   }

   Inet_ntop(AF_INET, (struct in_addr *)hostEntry->h_addr_list[0], pingTargetIPStr, INET_ADDRSTRLEN);
   
   printf("PING %s (%s): %d data bytes\n", pingTargetHostName, pingTargetIPStr, 56);

while(1) {
   //printf("Pinging...\n");
   memset(buf, 0, TOTALICMPLEN);
   memset(&pfAddress, 0, sizeof(struct sockaddr_ll));
   memset(&hwaddr, 0, sizeof(hwaddr));

   destIPAddr.sin_family = AF_INET;
   destIPAddr.sin_addr.s_addr = myPingData->tourPrevIP; 

   sockAddrLen = sizeof(struct sockaddr_in);

   hwaddr.sll_ifindex = selfEth0InterfaceIndex;
   hwaddr.sll_hatype = ARPHRD_ETHER;
   hwaddr.sll_halen  = ETH_ALEN;

   printf("Tour at node %s: areq: Requesting hardware address for %s.\n", selfHostName, pingTargetIPStr);
   retval = areq((struct sockaddr *)&destIPAddr, sockAddrLen, &hwaddr);
   if (retval < 0) {
      printf("Tour at node %s: areq: Failed to get hardware address for IP %s. ARP module may not be running on either source or destination node.\n", selfHostName, pingTargetIPStr);
      goto retry;
   } else {
      printf("Tour at node %s: areq: returned hardware address %.2x:%.2x:%.2x:%.2x:%.2x:%.2x for %s.\n", selfHostName, hwaddr.sll_addr[0] & 0xff, hwaddr.sll_addr[1] & 0xff, hwaddr.sll_addr[2] & 0xff, hwaddr.sll_addr[3] & 0xff, hwaddr.sll_addr[4] & 0xff, hwaddr.sll_addr[5] & 0xff, pingTargetIPStr);
   }

   pfAddress.sll_family = PF_PACKET;        
   pfAddress.sll_hatype = ARPHRD_ETHER;
   pfAddress.sll_pkttype = PACKET_OTHERHOST;
   pfAddress.sll_halen = ETH_ALEN;
   pfAddress.sll_protocol = htons(ETH_P_IP);
   pfAddress.sll_ifindex = selfEth0InterfaceIndex;

   for (i = 0; i < ETH_ALEN; i++) {
      pfAddress.sll_addr[i] = hwaddr.sll_addr[i];
   }

   ethernetHeader = (struct ethhdr *)buf;
   memcpy(buf, (void *)hwaddr.sll_addr, ETH_ALEN);
   memcpy(buf + ETH_ALEN, (void* )selfEthernetAddress, ETH_ALEN);
   ethernetHeader->h_proto = htons(ETH_P_IP);

   ipHeader = (struct ip *)(buf + sizeof(struct ethhdr));
   ipHeader->ip_v = IPVERSION;
   ipHeader->ip_hl = sizeof(struct ip) / 4 ;
   ipHeader->ip_p = IPPROTO_ICMP;
   ipHeader->ip_len = htons(IPCHECKSUMLEN);
   ipHeader->ip_sum = 0;
   ipHeader->ip_id = 0;
   ipHeader->ip_off = 0;
   ipHeader->ip_tos = 0;
   ipHeader->ip_ttl = htons(64);
   ipHeader->ip_src.s_addr = selfIPAddr;
   ipHeader->ip_dst.s_addr = myPingData->tourPrevIP;

   icmpHeader = (struct icmp *)(buf + sizeof(struct ethhdr) + sizeof(struct ip));
   icmpHeader->icmp_type = ICMP_ECHO;
   icmpHeader->icmp_id = getpid() & 0xffff;
   icmpHeader->icmp_seq = ++(myPingData->nextPingSequenceNum);
   icmpHeader->icmp_code = 0;
   memset(icmpHeader->icmp_data, 0xa5, 56);
   gettimeofday((struct timeval *)icmpHeader->icmp_data, NULL);
   icmpHeader->icmp_cksum = in_cksum((ushort *)icmpHeader, ICMPCHECKSUMLEN);
   ipHeader->ip_sum = in_cksum ((ushort *)ipHeader, IPCHECKSUMLEN);

   retval = sendto(tourNode.pingOutSocket, buf, TOTALICMPLEN, 0, (struct sockaddr*)&pfAddress, sizeof(pfAddress));
   if (retval < 0) {
      printf("Sending the ping ethernet packet failed.\n");
   }
   pthread_mutex_lock(&myPingData->threadLock);
   if (myPingData->threadPleaseExit) {
      pthread_mutex_unlock(&myPingData->threadLock);
      break;
   }
   pthread_mutex_unlock(&myPingData->threadLock);

retry:
   sleep(1);
   pthread_mutex_lock(&myPingData->threadLock);
   if (myPingData->threadPleaseExit) {
      pthread_mutex_unlock(&myPingData->threadLock);
      break;
   }
   pthread_mutex_unlock(&myPingData->threadLock);
}
exit:
   return NULL;
}

#undef ICMPCHECKSUMLEN
#undef IPCHECKSUMLEN
#undef TOTALICMPLEN

void DoMultiCast(char *msg, int msgSize)
{
   struct sockaddr_in multicastAddr;
   int retval;

   memset(&multicastAddr, 0, sizeof(multicastAddr));
   multicastAddr.sin_family = AF_INET;
   multicastAddr.sin_port = htons(tourNode.tourMultiCastPort);
   inet_pton(AF_INET, tourNode.tourMultiCastIP, &multicastAddr.sin_addr);
   printf("Node %s. Sending: %s\n", selfHostName, msg);
   retval = sendto(tourNode.multicastSocket, msg, msgSize, 0, (struct sockaddr*)&multicastAddr, sizeof(multicastAddr));
   if (retval < 0) {
      printf("Error sending mulitcast message %s.\n", msg);
   }
   return;
}


void
HandleRoutingSocket()
{
   char *routingPacket;
   struct ip *ipHeader;
   char *ipPacket;
   TourPacket *tourPacket;
   char buf[256];
   time_t ticks;
   struct hostent *hostEntry = NULL;
   char sourceHostName[256];
   unsigned int sourceHostIP;
   int nodeVisitedFirstTime = 0;
   int nodeIsDestination = 0;
   pthread_t threadId;
   int i;
   int alreadyPingingPrevNode = 0;

   routingPacket = calloc(1, sizeof (char) * 16 * 1024);

   if (!routingPacket) {
      printf("Unable to allocate space for routing packet.\n");
      return;
   }

   Recvfrom(tourNode.routingSocket, routingPacket, 16*1024, 0,  NULL, NULL);

   ipHeader = (struct ip *)routingPacket;
   tourPacket = (TourPacket *)(routingPacket + sizeof(*ipHeader));

   if (ntohs(ipHeader->ip_id) != PROTOCOL_IP_TOUR_ID) {
      printf("Received invalid routing packet. Ignoring it.\n");
      goto exit;
   }

   ticks = time(NULL);
   sprintf(buf, "%.24s", ctime(&ticks));
   sourceHostIP = ipHeader->ip_src.s_addr;
   //tourStartHostIP = tourPacket->tourNodeIP[0];
   if ((hostEntry = gethostbyaddr(&sourceHostIP, 4 , AF_INET)) == NULL) {
      sourceHostName[0] = 0;
      printf("gethostbyaddr failed.\n");
   } else {
      strcpy(sourceHostName, hostEntry->h_name);
   }

   printf("%s: Tour at node %s received source routing packet from %s\n", buf, selfHostName, sourceHostName);
   
   if ((tourPacket->currentNodeIndex + 1) == tourPacket->numTourNodes) {
      nodeIsDestination = 1;
      tourNode.nodeIsDestination = 1;
   } else {
      tourNode.nodeIsDestination = 0;
   }
   if (tourNode.tourSourceIP != tourPacket->tourNodeIP[0]) {
      nodeVisitedFirstTime = 1;
      //printf("Destination node is being visited first time.\n");
      // Todo fix some variables
      tourNode.tourSourceIP = tourPacket->tourNodeIP[0];
   } else {
      nodeVisitedFirstTime = 0;
      //printf("Destination node has already been visited once.\n");
   }

   if (nodeVisitedFirstTime) {
      struct ip_mreq mrequest;

      tourNode.tourMultiCastPort = tourPacket->multicastPort;
      memcpy(tourNode.tourMultiCastIP, tourPacket->multicastIP, INET_ADDRSTRLEN);

      // Join multicast group
      Inet_pton(AF_INET, tourPacket->multicastIP, &mrequest.imr_multiaddr);
      mrequest.imr_interface.s_addr = htonl(INADDR_ANY);

      if (setsockopt(tourNode.multicastSocket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mrequest, sizeof(mrequest)) < 0) {
         printf("Error setting setsockopt IP_ADD_MEMBERSHIP in HandleRoutingSocket\n");
      }
   }

   // Check if we are already ping our previous node
   for (i = 0; i < numPingThreads; i++) {
      if (pingThread[i].tourPrevIP == tourPacket->tourNodeIP[tourPacket->currentNodeIndex -1]) {
         // This node is already visited and is being pinged
         alreadyPingingPrevNode = 1;
         break;
      }
   }

   if (!alreadyPingingPrevNode) {
      pthread_mutex_init(&(pingThread[numPingThreads].threadLock), NULL);
      pingThread[numPingThreads].threadPleaseExit = 0;
      pingThread[numPingThreads].tourPrevIP = tourPacket->tourNodeIP[tourPacket->currentNodeIndex -1];
      if (pthread_create(&threadId, NULL, StartPingForTour, &(pingThread[numPingThreads])) != 0) {
         printf("Error creating ping thread.\n");
      }
      numPingThreads++;
   }

   if (nodeIsDestination) {
      printf("Tour at node: %s Tour is ending. It has reached destination node.\n", selfHostName);
      tourNode.destTourPrevIP = tourPacket->tourNodeIP[tourPacket->currentNodeIndex - 1];
   } else {
      tourPacket->currentNodeIndex++;
      SendIPPacket(tourPacket, tourPacket->tourNodeIP[tourPacket->currentNodeIndex - 1],
                   tourPacket->tourNodeIP[tourPacket->currentNodeIndex]);
   }

exit:
   free(routingPacket);
}


void
tv_sub(struct timeval *out, struct timeval *in)
{
   if ((out->tv_usec -= in->tv_usec) < 0) {
      --out->tv_sec;
      out->tv_usec += 1000000;
   }
   out->tv_sec -= in->tv_sec;
}

void
StopPingingAndDoMulticast()
{
   char msg[256];
   int i;
   // Stop ping
   for (i = 0; i < numPingThreads; i++) {
      pthread_mutex_lock(&(pingThread[i].threadLock));
      pingThread[i].threadPleaseExit = 1;
      pthread_mutex_unlock(&(pingThread[i].threadLock));
   }
   numPingThreads = 0;
   sprintf(msg, "<<<<<This is node %s. Tour has ended. Group members please identify yourselves>>>>>", selfHostName);
   DoMultiCast(msg, sizeof(msg));
}

void
HandlePingInSocket()
{
   struct sockaddr_in pingInAddr;
   int pingInAddrLen;
   char buf[ETH_FRAME_LEN];
   struct ip *ipHeader;
   struct icmp *icmpHeader;
   int numRecv;
   struct timeval *tvsend;
   struct timeval tvrecv;
   char senderIP[INET_ADDRSTRLEN];
   double rtt;
   int icmplen;

   memset(buf, 0, sizeof(buf));
   pingInAddrLen = sizeof(pingInAddr);

   numRecv = recvfrom(tourNode.pingInSocket, buf, sizeof(buf), 0, (struct sockaddr*) &pingInAddr, &pingInAddrLen);
   if (numRecv < 0) {
      printf("Ping in socket is set.\n");
      return;
   }

   ipHeader = (struct ip*)buf;
   icmpHeader = (struct icmp*)(buf + (ipHeader->ip_hl << 2));
   if ((icmplen = (numRecv - (ipHeader->ip_hl << 2))) < 8) {
      printf("Ping in packet has error in icmp header length. Malformed packet\n");
      return;
   }

   if ((icmpHeader->icmp_type != ICMP_ECHOREPLY) || (icmpHeader->icmp_id != (getpid() & 0xffff))) {
      return;
   }

   if (numPingThreads == 0) {
      // Ignore any response packet if we have stopped pinging
      return;
   }

   gettimeofday(&tvrecv, NULL);
   tvsend = (struct timeval*)icmpHeader->icmp_data;
   tv_sub(&tvrecv, tvsend);
   rtt = tvrecv.tv_sec * 1000.0 + tvrecv.tv_usec / 1000.0;
   Inet_ntop(AF_INET, &pingInAddr.sin_addr, senderIP, INET_ADDRSTRLEN);

   printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n", icmplen, senderIP, icmpHeader->icmp_seq, ipHeader->ip_ttl, rtt);

   if (tourNode.nodeIsDestination == 1) {
      // Count the number of ping responses from the previous node of the destination of the tour
      if (pingInAddr.sin_addr.s_addr == tourNode.destTourPrevIP) {
            tourNode.numPingResponseReceived++;
      }
      if (tourNode.numPingResponseReceived == 5) {
         StopPingingAndDoMulticast();
      }
   }
}

void
HandleMulticastSocket()
{
   int retval;
   struct sockaddr_in multicastAddr;
   int multicastAddrLen = sizeof (multicastAddr);
   char msg[256];
   struct timeval timeout = {5, 0};
   fd_set rset, rsetBackup;
   int maxfdp1;
   int i;

   retval = recvfrom(tourNode.multicastSocket, msg, sizeof(msg), 0, (struct sockaddr*) &multicastAddr, &multicastAddrLen);
   if (retval < 0) {
      printf("Tour at node: %s Error receiving from multicast socket.\n", selfHostName);
      return;
   }

   for (i = 0; i < numPingThreads; i++) {
      pthread_mutex_lock(&(pingThread[i].threadLock));
      pingThread[i].threadPleaseExit = 1;
      pthread_mutex_unlock(&(pingThread[i].threadLock));
   }

   printf("Node %s. Received: %s\n", selfHostName, msg);
   sprintf(msg, "<<<<<Node %s. I am a member of the group.>>>>>", selfHostName);
   DoMultiCast(msg, sizeof(msg));

   FD_ZERO(&rsetBackup);
   FD_SET(tourNode.multicastSocket, &rsetBackup);
   maxfdp1 = tourNode.multicastSocket + 1;
Loop:
   rset = rsetBackup;
   timeout.tv_sec = 4;
   retval = Select(maxfdp1, &rset, NULL, NULL, &timeout);
   if (retval == 0) {
      printf("Tour at node %s: Finished waiting for any more multicast group messages. Exiting tour process gracefully.\n", selfHostName);      
      // timeout done
      return;
   }

   if (FD_ISSET(tourNode.multicastSocket, &rset)) {
      multicastAddrLen = sizeof (multicastAddr);
      retval = recvfrom(tourNode.multicastSocket, msg, sizeof(msg), 0, (struct sockaddr*)&multicastAddr, &multicastAddrLen);
      if(retval < 0) {
         printf("Tour at node: %s Error receiving from multicast socket.\n", selfHostName);
         return;
      }
      printf("Node %s. Received: %s\n", selfHostName, msg);
   }
   goto Loop;
}



int main(int argc, char *argv[])
{
   TourPacket tourPacket;
   fd_set rset, rsetBackup;
   int maxfdp1;
   struct hwa_info *hptr, *kptr;
   struct timeval timer = { 5, 0 };
   int n;
   time_t timeStart, timeNow;

   InitializeSelf();

   if (argc > 1) {
      InitializeTour(argc, argv, &tourPacket);
   }

   hptr = get_hw_addrs();
   if (hptr) {
      for(kptr = hptr; kptr != NULL; kptr = kptr->hwa_next) {
         if(!strncmp(kptr->if_name, "eth0", 4) && kptr->ip_alias != IP_ALIAS) {
            memcpy(selfEthernetAddress, kptr->if_haddr, IF_HADDR);
            selfEth0InterfaceIndex = kptr->if_index;
            break;
         }
      }
      printf("Tour at node %s: IP Address string %s IP Address %d\n", selfHostName, selfIPAddrStr, selfIPAddr);
      printf("Tour at node %s: Self Mac address %.2x:%.2x:%.2x:%.2x:%.2x:%.2x Interface Index %d\n", selfHostName, selfEthernetAddress[0] & 0xff, selfEthernetAddress[1] & 0xff, selfEthernetAddress[2] & 0xff, selfEthernetAddress[3] & 0xff, selfEthernetAddress[4] & 0xff, selfEthernetAddress[5] & 0xff, selfEth0InterfaceIndex);
      free_hwa_info(hptr);
      hptr = NULL;
   }

   InitializeTourNode(&tourNode, (argc > 1) ? 1 : 0);

   if (argc > 1) {
      SendTour(&tourPacket);
   } else {
      printf("Tour at node %s: Waiting for tour to begin\n", selfHostName);
   }

   FD_ZERO(&rsetBackup);
   FD_SET(tourNode.routingSocket, &rsetBackup);
   FD_SET(tourNode.pingInSocket, &rsetBackup);
   // pingOut socket is handled in a separate thread
   FD_SET(tourNode.multicastSocket, &rsetBackup);
   maxfdp1 = tourNode.multicastSocket + 1;

   while(1) {
      rset = rsetBackup;
      if (tourNode.nodeIsDestination) {
         // Ping timeout to do multicast
         timer.tv_sec = 5;
         timer.tv_usec = 0;
         n = Select(maxfdp1, &rset, NULL, NULL, &timer);
         time(&timeNow);
         if (n == 0 || ((timeNow - timeStart ) > 6)) {
            // Timeout pinging for destination. Start multicast
            StopPingingAndDoMulticast();
         }
      } else {
         Select(maxfdp1, &rset, NULL, NULL, NULL);
      }

      if (FD_ISSET(tourNode.routingSocket, &rset)) {
         //printf("Routing socket is set for readin.\n");
         HandleRoutingSocket();
         if (tourNode.nodeIsDestination) {
            time(&timeStart);
         }
      }

      if (FD_ISSET(tourNode.multicastSocket, &rset)) {
         //printf("Multicast socket is set for readin.\n");
         HandleMulticastSocket();
         // We are done gracefully exit tour application
         return;
      }

      if (FD_ISSET(tourNode.pingInSocket, &rset)) {
         //printf("Ping in socket is set for readin.\n");
         HandlePingInSocket();
      }

   }
}

int areq(struct sockaddr *IPAddr, socklen_t sockaddrlen, struct HWaddr *hwaddr)
{
   int domainSockfd;
   struct sockaddr_un domainAddress;
   fd_set rset;
   struct timeval timeout = {5, 0};
   int retval = -1;

   char buf[sizeof(struct sockaddr) + sizeof(struct HWaddr)];

   memset(buf, 0, sizeof(struct sockaddr) + sizeof(struct HWaddr));
   memset(&domainAddress, 0, sizeof(domainAddress));

   domainSockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
   if (domainSockfd < 0) {
      printf("Tour at node %s: areq: Error in creating domain socket.\n", selfHostName);
      return retval;
   }

   domainAddress.sun_family = AF_LOCAL;
   strcpy(domainAddress.sun_path, DOMAIN_SUN_PATH);

   retval = connect(domainSockfd, (struct sockaddr *)&domainAddress, sizeof(struct sockaddr));
   if (retval < 0){
      printf("Tour at node %s: areq: Error in connecting to ARP module.\n", selfHostName);
      close(domainSockfd);
      return -1;
   }

   memcpy(buf, IPAddr, sockaddrlen);
   memcpy(buf + sockaddrlen, hwaddr, sizeof(*hwaddr));

   retval = write(domainSockfd, buf, sockaddrlen + sizeof(*hwaddr));
   if (retval < 0){
      printf("Tour at node %s: areq: Error sending IPaddr to ARP.\n", selfHostName);
      close(domainSockfd);
      return -1;
   }

   FD_ZERO(&rset);
   FD_SET(domainSockfd, &rset);

  
   retval = select(domainSockfd + 1, &rset, NULL, NULL, &timeout);
   if (retval < 0) {
      printf("Tour at node %s: areq: Error in select.\n", selfHostName);
      close(domainSockfd);
      return -1;
   }

   if(retval == 0) {
      printf("Tour at node %s: areq: Timedout waiting for reply from ARP.\n", selfHostName);
      close(domainSockfd);
      return -1;
   }

   if(FD_ISSET(domainSockfd, &rset)) {
      retval = read(domainSockfd, hwaddr, sizeof(*hwaddr));
      if(retval <= 0) {
         printf("Tour at node %s: areq: Error reading HW address from ARP.\n", selfHostName);
         close(domainSockfd);
         return -1;
      }
   }

   close(domainSockfd);
   return 0;
}





