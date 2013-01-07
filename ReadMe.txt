                                                                                                              
Team
Alok Katiyar : 108943744
Rohan Babtiwale : 108687468

We have implemented all parts in the assignment.


Features implemented in the assignment are as follows:
-----------------------------------------------------

1. Walk around the ordered list of nodes using IP raw Sockets
2. Every node in the tour pings its preceeding node. This means that if a node is visited more than once in tour then it may ping more than one node.
3. Exchange of multicast messages after tour completion. Note that multicast messages are exchanged even if ping to previous node is timing out. As long as tour reaches destination node it will finish.
4. "areq()" API function for communication between Tour and ARP process. For every ping request Tour application queries ARP application for the hardware address.
5. All tour process exit after tour is completed.



How to run the program:
----------------------

./akatiyar_tour ...(list of VMs to be visited)-- for source node
./akatiyar_tour -- for rest of the nodes
./akatiyar_arp

The tour process will take VMs to be visited as command line arguments and initiate the walk around the mentioned nodes with each node pinging the previous node along the way. It issues an "areq()" API function call to ARP process for retrieving hardware address of the preiovus node for initiating IPCM echo request messages. Upon receiving ARP request the ARP process replies with hardware address if it is already available in the cache otherwise it issues an ARP_REQUEST to other ARP nodes over its PF Packet. On receiving ARP_REPLY from the target ARP node ARP notifies tour application about the hw address.


Tour Implementation:
--------------------

On starting tour application the node initializes itself using "gethostbyname()" function. It stores and prints its host name and IP address. The tour is initialized by calling "InitializeTour()" function. The command line arguments and a pointer to "TourPacket" structure are passed as parameters to the function. Only eth0 interface is used for this assignment

The TourPacket structure is shown below

typedef struct TourPacket {
   char multicastIP[INET_ADDRSTRLEN];
   int multicastPort;
   int numTourNodes;
   // Index of the current destination
   int currentNodeIndex;
   unsigned int tourNodeIP[MAX_TOUR_NODES]; 
} TourPacket;

TourPacket is passed to different nodes of the tour. Multicast address and port number is stored in the structure. IP address of every destination is stored in the tourNodeIP[] array. The source node of the tour process prints the total number of nodes to be visited. The  "get_hw_addr()" function is called to retrieve eth0 interface mac address and number. It also initializes the hostname and IP address. As the packet traverses through different node currentNodeIndex is modified to indicate the index to the next IP in tourNodeIP[]

The "eth0" interface ethernet address and interface index are extracted from the list and stored separately. After extracting the "eth0" interface address and index the list of interfaces is freed. "InitializeTourNode()" function is called with a pointer to tour node as a parameter. It creates the sockets described below.

The TourNode structure is as follows

typedef struct TourNode {
   int routingSocket;
   int pingInSocket;
   int pingOutSocket;
   int multicastSocket;
   // At any given moment one tour will be active. Maintain it
   unsigned int tourSourceIP;
   // Previous node in the tour
   unsigned int tourPrevIP;
   // currently pinging
   int isPinging;
   // Next ping sequence number
   int nextPingSequenceNum;
   // Total ping response received
   int numPingResponseReceived;
   // Multicast Port of the tour
   int tourMultiCastPort;
   char tourMultiCastIP[INET_ADDRSTRLEN];
   int nodeIsDestination;
} TourNode;

Every tour node creates a routingSocket. This socket is used to route the tourPacket to the next node in the tour. "IP_HDRINCL" socket option is set for routing socket. Two ping sockets are created one for the outing ping ICMP requests and the second for the receving the Ping ICMP responses.
Ping out socket of PF_PACKET type is created along with routing socket. "SO_REUSEADDR" option is set for newly created multicast socket. Every node in the tour joins the multicast group only once when it visited the 1st time in the tour. Tour packet is sent to the next node in the list by filling the ipheader.We only use one multicast for sending and receiving the multicast messages. We dont bind it to any address or port.

The tour application then waits on all the sockets (routing, multicast and ping in) for them to become readable. PingOut socket is handled in separate thread. If application receives data on routing socket, source IP and destination IP is extracted from IP header. The application check whether the current node has been previously visited or not by using "tourNodeIP[]" array. If the node is visited for the first time then the multicast socket at the node joins the multicast group. In addition if the node is not already pinging it previous node then it starts a new separatee thread to ping that previous node.


Threading for pinging
---------------------

The functionality of sending IP packet to next node and pinging to the previous node is handled concurrently by threading. The pinging thread detaches itself from the main thread and start pinging the previous node. It invokes ARP process by using "areq()" function to find destination MAC address for previous node. It fills the PF_SOCKET structure, ethernet header, ip header and icmp header structures. ICMP echo request is sent on pingoutsocket to previous node. The ping out thread keeps pinging its previous node once every 1 second until it is stopped by the main thread (because a node has reached multicast message from the destination and now it is time to stop pinging and send multicast messages) or when 5 ping responses are received and this is the destination node and it has to start the multicast.


Handling PingIn socket
----------------------

Functionality of pingin socket is handled in "HandlePingInSocket()" function. The application checks the icmp header of the received socket for icmp type. The received packet is discarded if the type is other than ICMP_ECHOREPLY or broadcast message. The node stops pinging if it receives 5 ping responses. It current node is the destination node in the tour, process prints the message stating that the tour has ended and sends the message on multicast address asking all the intermediate nodes to identify themselves.


Handling Multicast socket
-------------------------

If the multicast socket receives message asking it to identify itself for the first time, the node identifies itself by sending a message on multicast address. The application then waits for 5 seconds and receives other multicast messages from other members of the group.


"areq()" API function
-----------------

The "areq()" API function creates a TCP unix domain socket. Tour process sends the IP address of the node whose MAC address is needed along with the source IP address. It writes through unix domain socket and waits for a reply from ARP process for 5 seconds by using timeout. In case of a timeout tour process closes the domain socket and exits. If tour process gets a reply from ARP, it reads hardware address of the node from the domain socket.


ARP Implementation:
-------------------

Basic functionality of ARP module is to find hardware address of the node requested by tour process. First hardware addresses of all the interfaces of a node are stored in a list. "eth0" interface hardware address and index is stored separately. The list of interfaces on a node is printed. Signal handler is set to detect "SIGINT" signal. "SIGPIPE" signal is ignored to to not kill the application when the socket attempts to write on a closed socket. "InitializeArpNode()" is used to initialize an ARP node. All previous domain socket paths are unlinked to avoid an error in binding new unix domain TCP socket. We set up the socket to listen to 2 requests in a queue at a time. A PF_PACKET socket is also created to send ethernet packet to the node requested by tour process.


Handle Unix Domain Socket:
--------------------------

ARP process then waits for data to arrive on either unix domain socket or PF_PACKET socket. When ARP process receives hardware address request for a node from tour process on a unix domain socket, it accepts the connection from domain socket and reads from that socket. Target IP address is extracted from tour info structure present in the data received from tour process. ARP process calls "ArpCacheGetEntry()" function to check whether an entry for the requested node already exists in ARP cache. If there is no entry present in ARP cache for requested node, a new entry is created. An ethernet frame is formed and sent using PF_PACKET sockets with source and destination IP address as its payload. A message is printed indicating the source and destination nodes for ARP message. If an entry is present for the requested node, that entry is extracted from cache is sent to tour process via unix domain socket.

"ArpCache" structure used to create cache of nodes in the network is as follows:

typedef struct ArpCache {
   unsigned int IPAddress;
   unsigned char addr[8]; 
   int ifindex;
   unsigned short hatype;
   int connectionFd;
   struct ArpCache * next;
} ArpCache;


Handle PF_PACKET socket:
------------------------

When ARP process receives data from PF_PACKET socket, an ethernet protocol number and ARP Id is checked first. If ethernet protocol number and ARP Id values received are different from our values then the received frame is discarded. If received packet is of type "ARP_REPLY" then ARP cache is checked for an entry for sender's IP address. If an entry exists it is updated and ARP process writes to tour process using unix domain socket and ARP process closes the domain socket. 

When received packet is of type ARP_REQUEST, if request is not targeted for current node then cache of current node is updated from the sender if an entry already exist. If the entry does not exist then no new entry is mad. If ARP request is targeted for current node the ARP cache is updated. An ARP packet structure is filled and sent to the destination node using PF_PACKET socket. A message is printed stating source and destination node. All other types of ARP packets are ignored.

The ArpPacket structure used is as follows:

typedef struct ArpPacket {
    unsigned short id;
    ArpPacketType type;
    char senderMac[IF_HADDR];
    unsigned int senderIP;
    char targetMac[IF_HADDR];
    unsigned int targetIP;
} ArpPacket;

