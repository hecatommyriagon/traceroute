# Traceroute
### Cristian Madrazo
This program is a simple traceroute utility. Network layer IP datagrams are crafted with an 
ICMP echo request payload. The Time To Live (TTL) is incremented on each send and 
the program listens for a set amount of time (default 15 seconds) for an ICMP echo response or
an ICMP time-to-live-exceeded response until we send the max amount of datagrams or we get the
echo response from the destination.

Note: This will only work on Linux due to network stack 

### Building
To build, execute the command `make` in the project directory

### Running
To run, execute the command `./traceroute -d <ip>` in the project directory with the required `-d` flag
    - You may need to grant execute permissions by running the command `chmod +x rft-client`
    - You must use the required `-d` flag to specify a destination IP
        - Must be in dotted decimal format
        - Example `./traceroute -d 8.8.8.8`
    - You can use the optional `-v` flag to run in verbose mode
        - This flag has a mandatory argument, which can be an integer value in the range of 0-6
        - Example `./traceroute -d 8.8.8.8 -v 5`
