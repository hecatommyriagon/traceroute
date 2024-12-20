#include "traceroute.h"

// seconds to wait before sending another packet
const int TTL_TIMEOUT = 15;
const int PAYLOAD_SIZE = 36;
const int FIRST_TTL = 2;
const int TOTAL_OUT = 30;
const int PACKET_LEN = 64; // this is all th eoutgoing packets

// Function to print ICMP header -debug only because it clogs the output
void print_icmp_header (struct icmphdr* icmp_header) {
    std::cout << "---- ICMP Header ----" << std::endl;
    std::cout << "Memory address: " << static_cast<void*> (icmp_header) << std::endl;
    std::cout << "Type: " << (int)icmp_header->type << std::endl;
    std::cout << "Code: " << (int)icmp_header->code << std::endl;
    std::cout << "Checksum: 0x" << std::hex << ntohs (icmp_header->checksum) << std::dec << std::endl;
    std::cout << "Identifier (ID): " << ntohs (icmp_header->un.echo.id) << std::endl;
    std::cout << "Sequence Number: " << ntohs (icmp_header->un.echo.sequence) << std::endl;
    std::cout << "--------------------\n";
}

// funciton to print ip header, same as icmp debug only
void print_ip_header (struct iphdr* ip_header) {
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    inet_ntop (AF_INET, &ip_header->saddr, source_ip, INET_ADDRSTRLEN);
    inet_ntop (AF_INET, &ip_header->daddr, dest_ip, INET_ADDRSTRLEN);

    std::cout << "---- IP Header ----\n";
    std::cout << "Memory address: " << static_cast<void*> (ip_header) << std::endl;
    std::cout << "Version: " << (unsigned int)ip_header->version << "\n";
    std::cout << "Header Length: " << (unsigned int)ip_header->ihl * 4 << " bytes\n";
    std::cout << "Type of Service: " << (unsigned int)ip_header->tos << "\n";
    std::cout << "Total Length: " << ntohs (ip_header->tot_len) << " bytes\n";
    std::cout << "Identification: " << ntohs (ip_header->id) << "\n";
    std::cout << "Fragment Offset: " << (ntohs (ip_header->frag_off) & 0x1FFF) << "\n";
    std::cout << "Time to Live: " << (unsigned int)ip_header->ttl << "\n";
    std::cout << "Protocol: " << (unsigned int)ip_header->protocol << "\n";
    std::cout << "Header Checksum: " << ntohs (ip_header->check) << "\n";
    std::cout << "Source IP: " << source_ip << "\n";
    std::cout << "Destination IP: " << dest_ip << "\n";
    std::cout << "--------------------\n";
}

// ****************************************************************************
// * Compute the Internet Checksum over an arbitrary buffer.
// * (written with the help of ChatGPT 3.5)
// ****************************************************************************
uint16_t checksum (unsigned short* buffer, int size) {
    DEBUG << "Calculating checksum of buffer at " << static_cast<void*> (buffer) << " with size "
          << size << ENDL;
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }
    if (size == 1) {
        sum += *(unsigned char*)buffer;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Function to calculate the ICMP checksum
unsigned short calculate_checksum (void* buffer, int length) {
    unsigned short* data = (unsigned short*)buffer;
    unsigned long sum = 0;

    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    if (length == 1) {
        sum += *(unsigned char*)data;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

// function to fill in the ip values initially
void fill_in_IP_header (char* packet) {

    struct iphdr* ip = (struct iphdr*)packet;
    ip->version = 4; // ipv4
    ip->ihl = 5; // Header length in 32-bit words (5 * 4 = 20 bytes)
    ip->tos = 0; // tyupe of Service
    ip->tot_len = htons (64); // Total length (to be set later when data is added)
    // \\ip->id = htons (getpid ()); // Identification will be set by kerbel
    ip->frag_off = 0; // frafgment offset, not sure what this is actually
    ip->ttl = 64; // Time to Live (common default value) in case we forget to set down the line for some reason
    ip->protocol = IPPROTO_ICMP; // Protocol (TCP in this example)
    INFO << "Filled in IP header at address " << static_cast<void*> (packet) << ENDL;
}

// function to fill in the icmp values initially
void fill_in_ICMP_header (char* packet) {

    struct icmphdr* icmp_header = (struct icmphdr*)packet;
    icmp_header->type = ICMP_ECHO; // Echo request
    icmp_header->code = 0;
    icmp_header->un.echo.id = htons (getpid ()); // Identifier
    icmp_header->un.echo.sequence = htons (1);   // Sequence number

    INFO << "Filled in ICMP header at address " << static_cast<void*> (packet) << ENDL;
}


int main (int argc, char* argv[]) {
    std::string destIP;

    // process cmd line args
    int opt = 0;
    while ((opt = getopt (argc, argv, "d:v:")) != -1) {

        switch (opt) {
        case 'd': destIP = optarg; break;
        case 'v':
            LOG_LEVEL = atoi (optarg);
            ;
            break;
        case ':':
        case '?':
        default:
            std::cout << "useage: " << argv[0] << " -d [destination ip] -v [Log Level]" << std::endl;
            exit (-1);
        }
    }

    int length = PACKET_LEN; // hardcode packet length to make it easier
    char* packet = new char[length](); // buffer for sending
    char* icmp_hd = ((packet + sizeof (struct iphdr))); // super weird memory issues without this 
    memset (packet, 0, length); // set all of packet to 0s
    fill_in_IP_header (packet); 
    fill_in_ICMP_header (icmp_hd);

    // Create send socket
    int send_socket = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_socket < 0) {
        ERROR << "Send socket creation failed" << ENDL;
        return 1;
    }

    else {
        INFO << "Send socket creation success" << ENDL;
    }

    // Create receive socket
    int rcv_socket = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (rcv_socket < 0) {
        ERROR << "Receive socket creation failed" << ENDL;
        return 1;
    }

    else {
        INFO << "Receive socket creation success" << ENDL;
    }

    bool reply_received = false;
    int current_ttl = FIRST_TTL;

    // this is the main loop of the prgoram
    // it ends when the destination answers an echo OR when we sent max amt of ackets 
    while (current_ttl <= (FIRST_TTL + TOTAL_OUT) && !reply_received) {

        // Set up the destination address
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr (destIP.c_str ()); // Destination IP

        // Set the TTL field to current ttl
        struct iphdr* ip = (struct iphdr*)packet; // Cast to iphdr
        ip->ttl = current_ttl;                    // Update the TTL value
        DEBUG << "Setting IP TTL to: " << current_ttl << ENDL;
        ip->daddr = inet_addr (destIP.c_str ()); // Set destination IP

        // Calculate ICMP checksum
        struct icmphdr* icmp_header = ((struct icmphdr*)icmp_hd); // cast to ICMP header
        icmp_header->checksum = calculate_checksum ((void*)icmp_hd, sizeof (struct icmphdr*) + PAYLOAD_SIZE);
        DEBUG << "Setting ICMP checksum to: " << icmp_header->checksum << ENDL;

        bool first_check = false;

        // Send the packet
        if (sendto (send_socket, packet, 64, 0, (struct sockaddr*)&dest, sizeof (dest)) < 0) {
            ERROR << "sendto failed" << ENDL;
            close (send_socket);
            return 1;
        }

        else {
            // Issue a timestamp to debug packets arriving before listenign
            auto now = std::chrono::system_clock::now ();
            std::time_t current_time_t = std::chrono::system_clock::to_time_t (now);
            auto now_us =
            std::chrono::duration_cast<std::chrono::microseconds> (now.time_since_epoch ()) % 1000000;

            // Format the time
            INFO << "Sent packet: " << std::put_time (std::localtime (&current_time_t), "%Y-%m-%d %H:%M:%S")
                 << "." << std::setfill ('0') << std::setw (6) << now_us.count ()
                 << " (microseconds)" << ENDL;
        }

        bool packet_received = false;

        while (true) {

            // Use select() to monitor the raw socket
            fd_set read_fds;
            struct timeval timeout;
            char buffer[1024]; // not a pointer woohoo
            struct sockaddr_in source_addr;
            socklen_t addr_len = sizeof (source_addr);
            timeout.tv_sec = 5; // stimeout to 5 seconds
            timeout.tv_usec = 0;

            FD_ZERO (&read_fds);            // cear the set
            FD_SET (rcv_socket, &read_fds); // add raw socket to the set

            if (!first_check) {
                first_check = true;

                // again show timestamp to debug certain issue with timing of packet arrivals
                auto now = std::chrono::system_clock::now ();
                std::time_t current_time_t = std::chrono::system_clock::to_time_t (now);
                auto now_us =
                std::chrono::duration_cast<std::chrono::microseconds> (now.time_since_epoch ()) % 1000000;

                // formmat the time and show it
                INFO << "Started listening for replies: "
                     << std::put_time (std::localtime (&current_time_t), "%Y-%m-%d %H:%M:%S") << "."
                     << std::setfill ('0') << std::setw (6) << now_us.count () << " (microseconds)" << ENDL;
            }

            // wait for activity on the socket
            int activity = select (rcv_socket + 1, &read_fds, nullptr, nullptr, &timeout);

            if (activity < 0) {
                perror ("Select error");
                break;
            }

            else if (activity == 0) {
                INFO << TTL_TIMEOUT << " sec time out for TTL " << current_ttl << ENDL;

                if (!packet_received) {
                    std::cout << "\n\033[33m"
                              << "No response with TTL of " << current_ttl << "\033[0m"
                              << "\n";
                }
                break;
            }

            if (FD_ISSET (rcv_socket, &read_fds)) {
                // receive the incoming packet
                memset (buffer, 0, sizeof (buffer));
                int bytes_received = recvfrom (
                rcv_socket, buffer, sizeof (buffer), 0, (struct sockaddr*)&source_addr, &addr_len);
                if (bytes_received < 0) {
                    perror ("Failed to receive data");
                    continue;
                }

                // extract ip header by casting it
                struct iphdr* ip_header = (struct iphdr*)buffer;

                // get IP address
                char source_ip[INET_ADDRSTRLEN];
                inet_ntop (AF_INET, &ip_header->saddr, source_ip, sizeof (source_ip));

                INFO << "Packet from " << source_ip << " received with size: " << bytes_received << " bytes"
                     << " and type " << ip_header->protocol << ENDL;

                // Verify is ICMP
                if (ip_header->protocol != IPPROTO_ICMP) {
                    WARNING << "Received non-ICMP packet" << ENDL;
                }

                else {

                    // similar to IP extract the ICMP header (after the IP header)
                    size_t ip_header_length = ip_header->ihl * 4; // ihl is in 32-bit words
                    struct icmphdr* icmp_header = (struct icmphdr*)(buffer + ip_header_length);

                    // Print ICMP type
                    INFO << "Received ICMP packet of type: " << (int)icmp_header->type << ENDL;

                    if ((int)icmp_header->type == ICMP_ECHOREPLY) {
                        reply_received = true; // this will exit our big loop which leads to exit program
                        packet_received = true;

                        // print nice message to command line
                        std::cout << "\n\033[1;36m"
                                  << "Packet reached destination " << destIP << "\033[0m" << "\n\n";

                    }

                    else if ((int)icmp_header->type == (int)ICMP_TIME_EXCEEDED) {
                        packet_received = true;

                        // print nice msg to comamn line
                        std::cout << "\n\033[33m" << source_ip << "\033[0m"
                                  << "\n";

                        break;
                    }
                }
            }
        }

        current_ttl++;
    }

    // Close the sockets
    delete[] packet;
    close (send_socket);
    close (rcv_socket);
    return 0;
}
