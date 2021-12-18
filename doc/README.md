# Design Overview

## Part 3

In Part 3 I implemented a relatively straightforward implementation Djikstra's algorithm.
For every switch, I use Djikstra's to calculate the distance to every other switch in the network.
Further, since when setting up the output packets on the correct port in order to reach the next switch
in the path, for each switch I have to store the parent switch that was used to reach the shortest path
to a given destination. Thus I use the data structure `HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>>`
so that given a switch and a destination, we can obtain the next switch in the path from the given switch with:
`AllShortestsPaths.get(switch).get(destination)`. The remainder of the work for this path was just to set up the correct
rules and installing the correctly to every switch in the network - and rebuilding the flow tables accordingly as switches
enter/leave/move throughout the network. I opted to simply recompute everything when changes occur to the system since it was 
simpler to implement, but this could be made more efficient in a future improvement.

## Part 4

For Part 4, there were two main objectives. One was two install rules in every switch in the network to notify
the controller whenever a client initiates a TCP connection with a virtual IP and for when the client issues an
ARP request for the MAC address associated with a virtual IP. For this, I looped through every switch in the network
by utilizing the `instances` class variable. And then I would install the corresponding IPv4 and ARP rules as well as all
rules for all other packet types. Additionally, as each switched joined the network, I would install connection-specific rules
for rewriting IP/MAC addresses of TCP packets sent between the client and the server.

Lastly, the connection-specific rules would match packets according to various types, like Ethernet type, source IP address, 
destination IP address, etc. To give more precedence to these rules, I ensured these rules were installed with a priority higher
than the default. Further, there was an `IDLE_TIMEOUT` of 20 seconds to be given to these connection-specific rules, so that once TCP
connections ends, by default the rules would be removed after 20 seconds. 
