#include "utility.h"

char selfNodeName[128];
unsigned int selfIPAddr;
char selfIPAddrStr[INET_ADDRSTRLEN];
char selfEthernetAddress[IF_HADDR];
int selfEth0InterfaceIndex;
ArpNode arpNode;
ArpCache *arpCacheHead;

void DumpHWAddrsInfo()
{
   struct hwa_info *hptr, *kptr;
   struct sockaddr *sa;
   printf("Begin list of interfaces on node\n");
   printf("--------------------------------\n");

   hptr = get_hw_addrs();
   
   if (hptr) {
      for (kptr = hptr; kptr != NULL; kptr = kptr->hwa_next) {
         if (!strncmp(kptr->if_name, "eth0", 4)) {
            printf("%s : %s\n", kptr->if_name, (kptr->ip_alias == IP_ALIAS) ? "(alias)" : "");
            if ((sa = kptr->ip_addr) != NULL) {
               printf("IP address : %s\n", Sock_ntop_host(sa, sizeof(*sa)));
               if (kptr->ip_alias != IP_ALIAS) {
                  struct sockaddr_in  *sin = (struct sockaddr_in *) sa;
                  memcpy(&selfIPAddr, &sin->sin_addr, sizeof(unsigned int));
                  memcpy(selfIPAddrStr, Sock_ntop_host(sa, sizeof(*sa)), INET_ADDRSTRLEN);
               }
            }
            if (kptr->ip_alias != IP_ALIAS) {
               memcpy(selfEthernetAddress, kptr->if_haddr, IF_HADDR);
               selfEth0InterfaceIndex = kptr->if_index;               
            }
            
            printf("Interface index : %d\n", kptr->if_index);
            printf("Hardware Mac address %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", kptr->if_haddr[0] & 0xff, kptr->if_haddr[1] & 0xff, kptr->if_haddr[2] & 0xff, kptr->if_haddr[3] & 0xff, kptr->if_haddr[4] & 0xff, kptr->if_haddr[5] & 0xff);
         }
      }
      free_hwa_info(hptr);
      hptr = NULL;
   }
   printf("--------------------------------\n");
   printf("End list of interfaces on node\n");

   gethostname(selfNodeName, sizeof (selfNodeName));

   //printf("Eth0 Hardware Mac address %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", selfEthernetAddress[0] & 0xff, selfEthernetAddress[1] & 0xff, selfEthernetAddress[2] & 0xff, selfEthernetAddress[3] & 0xff, selfEthernetAddress[4] & 0xff, selfEthernetAddress[5] & 0xff);
   //printf("Eth0 Interface Index %d\n", selfEth0InterfaceIndex);
   //printf("Eth0 IP address : %s %d", selfIPAddrStr, selfIPAddr);
}

void SigIntHandler(int signum)
{
   //printf("SIGINT received.\n");
   unlink(DOMAIN_SUN_PATH);
   exit(0);
}

void
InitializeArpNode()
{
   int retval;
   struct sockaddr_un domainSocketAddress;
   struct sockaddr_ll pfPacketSocketAddress;

   memset(&domainSocketAddress, 0, sizeof(domainSocketAddress));
   memset(&pfPacketSocketAddress, 0, sizeof(pfPacketSocketAddress));

   unlink(DOMAIN_SUN_PATH);
   domainSocketAddress.sun_family = AF_LOCAL;
   strcpy(domainSocketAddress.sun_path, DOMAIN_SUN_PATH);

   arpNode.domainSocket = socket(AF_LOCAL, SOCK_STREAM, 0);
   if (arpNode.domainSocket < 0) {
      printf("ARP at node %s: Error creating domain socket.\n", selfNodeName);
      exit(0);
   }

   retval = bind(arpNode.domainSocket, (struct sockaddr *)&domainSocketAddress, sizeof(domainSocketAddress));
   if (retval < 0) {
      printf("ARP at node %s: Error binding domain socket.\n", selfNodeName);
      exit(0);
   }

   // Handle upto 2 request queue at a time
   retval = listen(arpNode.domainSocket, 2);
   if (retval < 0) {
      printf("ARP at node %s: Error in listen for domain socket.\n", selfNodeName);
      exit(0);
   }

   arpNode.pfPacketSocket = socket(PF_PACKET, SOCK_RAW, htons(PROTOCOL_ETH_ARP));
   if (arpNode.pfPacketSocket < 0) {
      printf("ARP at node %s: Error creating PF_PACKET socket.\n", selfNodeName);
      exit(0);
   }

   pfPacketSocketAddress.sll_family  = PF_PACKET;
   pfPacketSocketAddress.sll_protocol = htons(PROTOCOL_ETH_ARP);
   pfPacketSocketAddress.sll_halen   = ETH_ALEN;
   pfPacketSocketAddress.sll_ifindex = selfEth0InterfaceIndex;
   pfPacketSocketAddress.sll_hatype  = ARPHRD_ETHER;
   pfPacketSocketAddress.sll_pkttype = PACKET_OTHERHOST;
   pfPacketSocketAddress.sll_addr[0] = 0xff;
   pfPacketSocketAddress.sll_addr[1] = 0xff;
   pfPacketSocketAddress.sll_addr[2] = 0xff;
   pfPacketSocketAddress.sll_addr[3] = 0xff;
   pfPacketSocketAddress.sll_addr[4] = 0xff;
   pfPacketSocketAddress.sll_addr[5] = 0xff;

   retval = bind(arpNode.pfPacketSocket, (struct sockaddr*)&pfPacketSocketAddress, sizeof(pfPacketSocketAddress));
   if (retval < 0) {
      printf("ARP at node %s: Error binding PF_PACKET socket.\n", selfNodeName);
      exit(0);
   }
   arpNode.pfPacketSocketAddress = pfPacketSocketAddress;
   return;
}

void
DeinitializeArpNode()
{
   close(arpNode.pfPacketSocket);
   close(arpNode.domainSocket);
   unlink(DOMAIN_SUN_PATH);
}

ArpCache *
ArpCacheGetEntry(ArpCache **cacheHead, unsigned int IPAddress)
{
   ArpCache *temp;
   if (!cacheHead) {
      return NULL;
   }

   temp = *cacheHead;
   while (temp) {
      if (temp->IPAddress == IPAddress) {
         return temp;
      }
      temp = temp->next;
   }
   return NULL;
}

void
ArpCacheAddEntry(ArpCache **cacheHead, ArpCache *entry)
{
   ArpCache *temp;
   if (!cacheHead) {
      return;
   }

   temp = *cacheHead;
   if (!temp) {
      *cacheHead = entry;
   } else {
      while (temp->next) {
         temp = temp->next;
      }
      temp->next = entry;
   }
   return;
}

void
ArpCacheDeleteEntry(ArpCache **cacheHead, unsigned int IPAddress)
{
   ArpCache *temp;
   ArpCache *prev = NULL;

   if (!cacheHead || !*cacheHead) {
      return;
   }

   temp = *cacheHead;
   while (temp) {
      if (temp->IPAddress == IPAddress) {
         if (temp == *cacheHead) {
            *cacheHead = temp->next;
            free(temp);
            temp = *cacheHead;
         } else {
            prev->next = temp->next;
            free(temp);
            temp = prev->next;
         }
      } else {
         prev = temp;
         temp = temp->next;
      }
   }
}

void HandleDomainSocket()
{
   char buf[sizeof(struct sockaddr) + sizeof(struct HWaddr)];
   struct sockaddr_in tourAddress;
   int connectionFd;
   int tourAddressLen = sizeof(tourAddress);
   HWaddr *hwAddr;
   struct sockaddr_in *tourInfo;
   int retval;
   unsigned int targetIPAddr;
   ArpCache *cacheEntry;
   
   memset(buf, 0, sizeof (buf));
   tourInfo = (struct sockaddr_in*)buf;
   hwAddr = (HWaddr *)(buf + sizeof(struct sockaddr_in));

   connectionFd = accept(arpNode.domainSocket, (struct sockaddr *)&tourAddress, &tourAddressLen);
   if (connectionFd < 0) {
      printf("ARP at node %s: Error accepting connection from tour node.\n", selfNodeName);
      return;
   }

   retval = read(connectionFd, buf, sizeof(buf));
   if (retval < 0) {
      printf("ARP at node %s: Error reading from connected domain socket.\n", selfNodeName);
      close(connectionFd);
      return;
   }

   targetIPAddr = tourInfo->sin_addr.s_addr;
   cacheEntry = ArpCacheGetEntry(&arpCacheHead, targetIPAddr);
   if (!cacheEntry) {
      ArpCache *newCacheEntry;
      char *ethernetFrameBuffer;
      struct ethhdr *ethernetHeader;
      ArpPacket *arpPacket;
      char targetIPStr[INET_ADDRSTRLEN];

      newCacheEntry = (ArpCache *)calloc(1, sizeof(*newCacheEntry));
      if (!newCacheEntry) {
         printf("ARP at node %s: Unable to allocate new cache entry.\n", selfNodeName);
         return;
      }

      newCacheEntry->IPAddress = targetIPAddr;
      newCacheEntry->ifindex = hwAddr->sll_ifindex;
      newCacheEntry->hatype = hwAddr->sll_hatype;
      newCacheEntry->connectionFd = connectionFd;

      ArpCacheAddEntry(&arpCacheHead, newCacheEntry);

      ethernetFrameBuffer = (char *)calloc(1, ETH_FRAME_LEN);
      if (!ethernetFrameBuffer) {
         printf("ARP at node %s: Unable to allocate ethernetFrameBuffer.\n", selfNodeName);
         return;
      }
      ethernetHeader = (struct ethhdr *)ethernetFrameBuffer;

      memset(ethernetHeader->h_dest, 0xff, ETH_ALEN);
      memcpy(ethernetHeader->h_source, selfEthernetAddress, ETH_ALEN);
      ethernetHeader->h_proto = htons(PROTOCOL_ETH_ARP);

      // 6 + 6 + 2
      arpPacket = (ArpPacket *)(ethernetFrameBuffer + 14);
      arpPacket->id = ARP_ID;
      arpPacket->type = ARP_REQUEST;
      arpPacket->senderIP = selfIPAddr;
      arpPacket->targetIP = targetIPAddr;
      memcpy(arpPacket->senderMac, selfEthernetAddress, IF_HADDR);

      retval = sendto(arpNode.pfPacketSocket, ethernetFrameBuffer, ETH_FRAME_LEN, 0, (struct sockaddr *)&arpNode.pfPacketSocketAddress, sizeof (arpNode.pfPacketSocketAddress));
      if (retval < 0) {
         printf("ARP at node %s: Error sending ARP request on PF Packet socket.\n", selfNodeName);
         ArpCacheDeleteEntry(&arpCacheHead, newCacheEntry->IPAddress);
         free(ethernetFrameBuffer);
         return;
      }

      printf("ARP at node %s: ARP_REQUEST sent from %s\n", selfNodeName, selfIPAddrStr);
      printf("ARP at node %s: ARP_REQUEST Ethernet header source: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x ==> dest: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", selfNodeName,
             ethernetHeader->h_source[0] & 0xff, ethernetHeader->h_source[1] & 0xff, ethernetHeader->h_source[2] & 0xff, ethernetHeader->h_source[3] & 0xff, ethernetHeader->h_source[4] & 0xff, ethernetHeader->h_source[5] & 0xff,
             ethernetHeader->h_dest[0] & 0xff, ethernetHeader->h_dest[1] & 0xff, ethernetHeader->h_dest[2] & 0xff, ethernetHeader->h_dest[3] & 0xff, ethernetHeader->h_dest[4] & 0xff, ethernetHeader->h_dest[5] & 0xff);
      Inet_ntop(AF_INET, &arpPacket->targetIP, targetIPStr, INET_ADDRSTRLEN);

      printf("ARP at node %s: ARP_REQUEST sender mac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x ==> target mac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", selfNodeName,
             arpPacket->senderMac[0] & 0xff, arpPacket->senderMac[1] & 0xff, arpPacket->senderMac[2] & 0xff, arpPacket->senderMac[3] & 0xff, arpPacket->senderMac[4] & 0xff, arpPacket->senderMac[5] & 0xff,
             arpPacket->targetMac[0] & 0xff, arpPacket->targetMac[1] & 0xff, arpPacket->targetMac[2] & 0xff, arpPacket->targetMac[3] & 0xff, arpPacket->targetMac[4] & 0xff, arpPacket->targetMac[5] & 0xff);
      printf("ARP at node %s: ARP_REQUEST sender IP: %s ==> target IP: %s\n", selfNodeName, selfIPAddrStr, targetIPStr);

      free(ethernetFrameBuffer);
   } else {
      if (!(cacheEntry->addr[0] == 0 &&
            cacheEntry->addr[1] == 0 &&
            cacheEntry->addr[2] == 0 &&
            cacheEntry->addr[3] == 0 &&
            cacheEntry->addr[4] == 0 &&
            cacheEntry->addr[5] == 0 &&
            cacheEntry->addr[6] == 0 &&
            cacheEntry->addr[7] == 0
            )) {
         HWaddr hwAddrReply;
         memset(&hwAddrReply, 0, sizeof(hwAddrReply));

         hwAddrReply.sll_ifindex = cacheEntry->ifindex;
         hwAddrReply.sll_hatype = cacheEntry->hatype;
         hwAddrReply.sll_halen = IF_HADDR;
         memcpy(&hwAddrReply.sll_addr, cacheEntry->addr, IF_HADDR);
         printf("ARP at node %s: ARP Cache has an entry for the harware address. Serving ARP_REPLY from cache.\n", selfNodeName);
         retval = write(connectionFd, &hwAddrReply, sizeof(struct HWaddr));
         if (retval < 0) {
            printf("ARP at node %s: Error writing to connected domain socket.\n", selfNodeName);
         }
         close(connectionFd);
         cacheEntry->connectionFd = -1;
      } else {
         printf("ARP at node %s: Found entry in cache but hardware address is still not available.\n", selfNodeName);
         return;
      }
   }
}

void HandlePFPacketSocket()
{
   int retval = 0;
   char buf[ETH_FRAME_LEN];
   ArpPacket *arpPacketReceived;
   struct ethhdr *ethernetHeaderReceived;

   memset(buf, 0, sizeof(buf));

   retval = recvfrom(arpNode.pfPacketSocket, buf, sizeof(buf), 0, NULL, NULL);
   if (retval < 0) {
      printf("ARP at node %s: Error reading from PF Packet socket.\n", selfNodeName);
      return;
   }

   ethernetHeaderReceived = (struct ethhdr *)(buf);
   // 6 + 6 + 2
   arpPacketReceived = (ArpPacket *)(buf + 14);

   if (ethernetHeaderReceived->h_proto != htons(PROTOCOL_ETH_ARP)) {
      printf("ARP at node %s: PF Packet ethernet protocol is not same as ours. Ignoring it.\n", selfNodeName);
      return;
   }

   if (arpPacketReceived->id != ARP_ID) {
      printf("ARP at node %s: Ignoring packet with unknown ARP Id.\n", selfNodeName);
      return;
   }

   if (arpPacketReceived->type == ARP_REPLY) {
      ArpCache *cacheEntry = NULL;
      char targetIPStr[INET_ADDRSTRLEN];
      char senderIPStr[INET_ADDRSTRLEN];

      cacheEntry = ArpCacheGetEntry(&arpCacheHead, arpPacketReceived->senderIP);
      if (cacheEntry) {
         HWaddr hwAddrReply;
         memset(&hwAddrReply, 0, sizeof(hwAddrReply));

         printf("ARP at node %s: ARP_REPLY received at %s\n", selfNodeName, selfIPAddrStr);
         printf("ARP at node %s: ARP_REPLY Ethernet header source: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x ==> dest: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", selfNodeName,
                ethernetHeaderReceived->h_source[0] & 0xff, ethernetHeaderReceived->h_source[1] & 0xff, ethernetHeaderReceived->h_source[2] & 0xff, ethernetHeaderReceived->h_source[3] & 0xff, ethernetHeaderReceived->h_source[4] & 0xff, ethernetHeaderReceived->h_source[5] & 0xff,
                ethernetHeaderReceived->h_dest[0] & 0xff, ethernetHeaderReceived->h_dest[1] & 0xff, ethernetHeaderReceived->h_dest[2] & 0xff, ethernetHeaderReceived->h_dest[3] & 0xff, ethernetHeaderReceived->h_dest[4] & 0xff, ethernetHeaderReceived->h_dest[5] & 0xff);
         Inet_ntop(AF_INET, &arpPacketReceived->senderIP, senderIPStr, INET_ADDRSTRLEN);
         Inet_ntop(AF_INET, &arpPacketReceived->targetIP, targetIPStr, INET_ADDRSTRLEN);

         printf("ARP at node %s: ARP_REPLY sender mac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x ==> target mac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", selfNodeName,
                arpPacketReceived->senderMac[0] & 0xff, arpPacketReceived->senderMac[1] & 0xff, arpPacketReceived->senderMac[2] & 0xff, arpPacketReceived->senderMac[3] & 0xff, arpPacketReceived->senderMac[4] & 0xff, arpPacketReceived->senderMac[5] & 0xff,
                arpPacketReceived->targetMac[0] & 0xff, arpPacketReceived->targetMac[1] & 0xff, arpPacketReceived->targetMac[2] & 0xff, arpPacketReceived->targetMac[3] & 0xff, arpPacketReceived->targetMac[4] & 0xff, arpPacketReceived->targetMac[5] & 0xff);
         printf("ARP at node %s: ARP_REPLY sender IP: %s ==> target IP: %s\n", selfNodeName, senderIPStr, targetIPStr);
         // Update cache entry
         cacheEntry->ifindex = selfEth0InterfaceIndex;
         cacheEntry->hatype = ARPHRD_ETHER;
         memcpy(cacheEntry->addr, arpPacketReceived->senderMac, IF_HADDR);       

         hwAddrReply.sll_ifindex = cacheEntry->ifindex;
         hwAddrReply.sll_hatype = cacheEntry->hatype;
         hwAddrReply.sll_halen = IF_HADDR;
         memcpy(&hwAddrReply.sll_addr, cacheEntry->addr, IF_HADDR);
         retval = write(cacheEntry->connectionFd, &hwAddrReply, sizeof(struct HWaddr));
         if (retval < 0) {
            // Delete an entry because ARP client has already closed the connection and write failed.
            ArpCacheDeleteEntry(&arpCacheHead, cacheEntry->IPAddress);
         }
         close(cacheEntry->connectionFd);
         cacheEntry->connectionFd = -1;
      } else {
         printf("ARP at node %s: Arp cache entry was not found. Ignoring PF Packet.\n", selfNodeName);
         return;
      }
   } else if (arpPacketReceived->type == ARP_REQUEST) {
      ArpCache *cacheEntry = NULL;
      char targetIPStr[INET_ADDRSTRLEN];
      char senderIPStr[INET_ADDRSTRLEN];

      // If the arp request was not targetted to us then just update our cache entry from the sender
      if (arpPacketReceived->targetIP != selfIPAddr) {
         cacheEntry = ArpCacheGetEntry(&arpCacheHead, arpPacketReceived->senderIP);
         if (cacheEntry) {
            // Update cache entry
            cacheEntry->ifindex = selfEth0InterfaceIndex;
            cacheEntry->hatype = ARPHRD_ETHER;
            memcpy(cacheEntry->addr, arpPacketReceived->senderMac, IF_HADDR);       
         }
      } else {
         // ARP request was targetted for us
         struct sockaddr_ll pfPacketSocketAddress;
         char *ethernetFrameBuffer;
         struct ethhdr *ethernetHeaderToSend;
         ArpPacket *arpPacketToSend;

         printf("ARP at node %s: ARP_REQUEST received at %s\n", selfNodeName, selfIPAddrStr);
         printf("ARP at node %s: ARP_REQUEST Ethernet header source: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x ==> dest: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", selfNodeName,
                ethernetHeaderReceived->h_source[0] & 0xff, ethernetHeaderReceived->h_source[1] & 0xff, ethernetHeaderReceived->h_source[2] & 0xff, ethernetHeaderReceived->h_source[3] & 0xff, ethernetHeaderReceived->h_source[4] & 0xff, ethernetHeaderReceived->h_source[5] & 0xff,
                ethernetHeaderReceived->h_dest[0] & 0xff, ethernetHeaderReceived->h_dest[1] & 0xff, ethernetHeaderReceived->h_dest[2] & 0xff, ethernetHeaderReceived->h_dest[3] & 0xff, ethernetHeaderReceived->h_dest[4] & 0xff, ethernetHeaderReceived->h_dest[5] & 0xff);
         Inet_ntop(AF_INET, &arpPacketReceived->senderIP, senderIPStr, INET_ADDRSTRLEN);
         Inet_ntop(AF_INET, &arpPacketReceived->targetIP, targetIPStr, INET_ADDRSTRLEN);

         printf("ARP at node %s: ARP_REQUEST sender mac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x ==> target mac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", selfNodeName,
                arpPacketReceived->senderMac[0] & 0xff, arpPacketReceived->senderMac[1] & 0xff, arpPacketReceived->senderMac[2] & 0xff, arpPacketReceived->senderMac[3] & 0xff, arpPacketReceived->senderMac[4] & 0xff, arpPacketReceived->senderMac[5] & 0xff,
                arpPacketReceived->targetMac[0] & 0xff, arpPacketReceived->targetMac[1] & 0xff, arpPacketReceived->targetMac[2] & 0xff, arpPacketReceived->targetMac[3] & 0xff, arpPacketReceived->targetMac[4] & 0xff, arpPacketReceived->targetMac[5] & 0xff);
         printf("ARP at node %s: ARP_REQUEST sender IP: %s ==> target IP: %s\n", selfNodeName, senderIPStr, targetIPStr);

         cacheEntry = ArpCacheGetEntry(&arpCacheHead, arpPacketReceived->senderIP);
         if (cacheEntry) {
            // Update cache entry
            cacheEntry->ifindex = selfEth0InterfaceIndex;
            cacheEntry->hatype = ARPHRD_ETHER;
            memcpy(cacheEntry->addr, arpPacketReceived->senderMac, IF_HADDR);       
         } else {
            ArpCache *newCacheEntry;
            
            newCacheEntry = (ArpCache *)calloc(1, sizeof(*newCacheEntry));
            if (!newCacheEntry) {
               printf("ARP at node %s: Unable to allocate new cache entry.\n", selfNodeName);
               return;
            }

            newCacheEntry->IPAddress = arpPacketReceived->senderIP;
            newCacheEntry->ifindex = selfEth0InterfaceIndex;
            newCacheEntry->hatype = ARPHRD_ETHER;
            newCacheEntry->connectionFd = -1;
            memcpy(newCacheEntry->addr, arpPacketReceived->senderMac, IF_HADDR);       

            ArpCacheAddEntry(&arpCacheHead, newCacheEntry);
         }

         memset(&pfPacketSocketAddress, 0, sizeof (pfPacketSocketAddress));

         pfPacketSocketAddress.sll_protocol = htons(PROTOCOL_ETH_ARP);
         pfPacketSocketAddress.sll_halen   = ETH_ALEN;
         pfPacketSocketAddress.sll_ifindex = selfEth0InterfaceIndex;
         pfPacketSocketAddress.sll_hatype  = ARPHRD_ETHER;
         pfPacketSocketAddress.sll_pkttype = PACKET_OTHERHOST;
         pfPacketSocketAddress.sll_addr[0] = arpPacketReceived->senderMac[0];
         pfPacketSocketAddress.sll_addr[1] = arpPacketReceived->senderMac[1];
         pfPacketSocketAddress.sll_addr[2] = arpPacketReceived->senderMac[2];
         pfPacketSocketAddress.sll_addr[3] = arpPacketReceived->senderMac[3];
         pfPacketSocketAddress.sll_addr[4] = arpPacketReceived->senderMac[4];
         pfPacketSocketAddress.sll_addr[5] = arpPacketReceived->senderMac[5];

         ethernetFrameBuffer = (char *)calloc(1, ETH_FRAME_LEN);
         if (!ethernetFrameBuffer) {
            printf("ARP at node %s: Unable to allocate ethernetFrameBuffer.\n", selfNodeName);
            return;
         }
         ethernetHeaderToSend = (struct ethhdr *)ethernetFrameBuffer;

         memcpy(ethernetHeaderToSend->h_dest, ethernetHeaderReceived->h_source, ETH_ALEN);
         memcpy(ethernetHeaderToSend->h_source, selfEthernetAddress, ETH_ALEN);
         ethernetHeaderToSend->h_proto = htons(PROTOCOL_ETH_ARP);

         // 6 + 6 + 2
         arpPacketToSend = (ArpPacket *)(ethernetFrameBuffer + 14);
         arpPacketToSend->id = ARP_ID;
         arpPacketToSend->type = ARP_REPLY;
         arpPacketToSend->senderIP = selfIPAddr;
         arpPacketToSend->targetIP = arpPacketReceived->senderIP;
         memcpy(arpPacketToSend->senderMac, selfEthernetAddress, IF_HADDR);
         memcpy(arpPacketToSend->targetMac, arpPacketReceived->senderMac, IF_HADDR);

         retval = sendto(arpNode.pfPacketSocket, ethernetFrameBuffer, ETH_FRAME_LEN, 0, (struct sockaddr *)&pfPacketSocketAddress, sizeof(pfPacketSocketAddress));
         if (retval < 0) {
            printf("ARP at node %s: Error sending ARP reply on PF Packet socket.\n", selfNodeName);
            free(ethernetFrameBuffer);
            return;
         }

         printf("ARP at node %s: ARP_REPLY sent from %s\n", selfNodeName, selfIPAddrStr);
         printf("ARP at node %s: ARP_REPLY Ethernet header source: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x ==> dest: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", selfNodeName,
                ethernetHeaderToSend->h_source[0] & 0xff, ethernetHeaderToSend->h_source[1] & 0xff, ethernetHeaderToSend->h_source[2] & 0xff, ethernetHeaderToSend->h_source[3] & 0xff, ethernetHeaderToSend->h_source[4] & 0xff, ethernetHeaderToSend->h_source[5] & 0xff,
                ethernetHeaderToSend->h_dest[0] & 0xff, ethernetHeaderToSend->h_dest[1] & 0xff, ethernetHeaderToSend->h_dest[2] & 0xff, ethernetHeaderToSend->h_dest[3] & 0xff, ethernetHeaderToSend->h_dest[4] & 0xff, ethernetHeaderToSend->h_dest[5] & 0xff);
         Inet_ntop(AF_INET, &arpPacketToSend->targetIP, targetIPStr, INET_ADDRSTRLEN);

         printf("ARP at node %s: ARP_REPLY sender mac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x ==> target mac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", selfNodeName,
                   arpPacketToSend->senderMac[0] & 0xff, arpPacketToSend->senderMac[1] & 0xff, arpPacketToSend->senderMac[2] & 0xff, arpPacketToSend->senderMac[3] & 0xff, arpPacketToSend->senderMac[4] & 0xff, arpPacketToSend->senderMac[5] & 0xff,
                   arpPacketToSend->targetMac[0] & 0xff, arpPacketToSend->targetMac[1] & 0xff, arpPacketToSend->targetMac[2] & 0xff, arpPacketToSend->targetMac[3] & 0xff, arpPacketToSend->targetMac[4] & 0xff, arpPacketToSend->targetMac[5] & 0xff);
         printf("ARP at node %s: ARP_REPLY sender IP: %s ==> target IP: %s\n", selfNodeName, selfIPAddrStr, targetIPStr);

         free(ethernetFrameBuffer);
      }
   } else {
      printf("ARP at node %s: Ignoring unknown ARP Packet type\n", selfNodeName);
   }
}

int main(int argc, char *argv[])
{
   fd_set rset, rsetBackup;
   int maxfdp1;
   DumpHWAddrsInfo();

   // Handle SIGINT by unlinking file
   Signal(SIGINT, SigIntHandler);
   // Ignore sigpipe on write on close socket
   Signal(SIGPIPE, SIG_IGN);

   InitializeArpNode();

   FD_ZERO(&rsetBackup);
   FD_SET(arpNode.domainSocket, &rsetBackup);
   FD_SET(arpNode.pfPacketSocket, &rsetBackup);
   maxfdp1 = arpNode.pfPacketSocket + 1;

   while(1) {
      rset = rsetBackup;
      Select(maxfdp1, &rset, NULL, NULL, NULL);
      if (FD_ISSET(arpNode.domainSocket, &rset)) {
         //printf("Domain socket is set for readin.\n");
         HandleDomainSocket();
      }

      if (FD_ISSET(arpNode.pfPacketSocket, &rset)) {
         //printf("PFPacket socket is set for readin.\n");
         HandlePFPacketSocket();
      }
   }

   DeinitializeArpNode();
}

