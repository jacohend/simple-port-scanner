#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <pcap.h>
#include <pthread.h>
#include <ctype.h>
#define __USE_BSD         
#include <netinet/ip.h>
#define __FAVOR_BSD        
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <netinet/ether.h>

#define MAX_ADDR 20
#define HOST_NAME_SIZE 255
#define OPTIONS_LENGTH 100
#define SYN_PACKET_SIZE 4096
#define REC_TIMEOUT 200
#define SRC_PORT 9701
#define FIN  0x01
#define SYN  0x02
#define RST  0x04
#define PSH 0x08
#define ACK  0x10
#define URG  0x20
#define XMAS (0x08 | 0x20 | 0x01)
#define UDP 0x17
#define OPEN 1
#define CLOSED 2
#define FILTERED 3
#define UNFILTERED 4
#define OPENFILTERED 5

int args;
int upper_port;
int lower_port;
int next_port;
int syn_settings = 1;
int null_settings = 1;
int fin_settings = 1;
int xmas_settings = 1;
int ack_settings = 1;
int udp_settings = 1;
int speedup = 0;
char ip[INET_ADDRSTRLEN]; 
int ip_set = 0;
char address[INET_ADDRSTRLEN];
int port_array[OPTIONS_LENGTH];
int num_ports;
int individual_ports = 0;
struct addr_array* addresses;
pcap_t *cap;
pthread_mutex_t array_mutex;
pthread_mutex_t port_mutex;
pthread_mutex_t option_mutex;


//holds scan results for our decider algorithm. 
//1 is open, 2 is closed, 3 is filtered, except for the last int
struct addr_array{
    //holds the scan type as defined by the constants above:
    //1 is open, 2 is closed, 3 is filtered for the following:
    int xmasresult; 
    int synresult;
    int ackresult;
    int finresult;
    int nullresult;
    int udpresult;
    int timeout; //temporary value for timeouts to determine filtering
};

struct scan{
    unsigned char type;
    int port;
};

struct pseudohdr {
    unsigned int src;
    unsigned int dst;
    unsigned char space;
    unsigned char protocol;
    unsigned short len;
};

void show_help(){
    printf("\nUSAGE:\n--help <display invocation options>\n--ports <[lowest port] - [highest port]> or individual ports\n--ip <IP address to scan>\n--prefix <IP prefix to scan>\n--file [file name containing IP addresses to scan]\n--transport <TCP or UDP>\n--speedup <parallel threads to use>\n--scan <One or more scans>\n");
}

void set_ip(char* setting){
    ip_set = 1;
    memset(ip, 0, INET_ADDRSTRLEN);
    strcpy(ip, setting);
}

void error(const char *message) {
    fprintf(stderr, message);
    exit(1);
}

void set_ports(int low, int high){    
    lower_port = low;
    upper_port = high; 
}


void finalize_ports(){
    if (num_ports == 1){
        lower_port = upper_port = port_array[0];
        return;
    }
    int max, min, i;
    min = max = port_array[0];
    for (i = 0; i < num_ports; i++){
        if (port_array[i] > max){
            max = port_array[i];
        }
        else if (port_array[i] < min){
            min = port_array[i];
        }
    }
    lower_port = min;
    upper_port = max;
}


void set_port(char* s, int i){
    port_array[i] = atoi(s);
}

//SYN, NULL, FIN, XMAS, ACK, UDP settings
void set_scan(char* scan){
    printf("adding scan %s to scan list\n", scan);
    if (!strcmp(scan, "SYN")){
        syn_settings = 1;
        return;
    }
    if (!strcmp(scan, "FIN")){
        fin_settings = 1;
        return;
    }
    if (!strcmp(scan, "NULL")){
        null_settings = 1;
        return;
    }
    if (!strcmp(scan, "XMAS")){
        xmas_settings = 1;
        return;
    }
    if (!strcmp(scan, "ACK")){
        ack_settings = 1;
        return;
    }
    if (!strcmp(scan, "UDP")){
        udp_settings = 1;
        return;
    }
}

//finds our IP
void find_src_ip(){
    struct ifaddrs *addresses = NULL;
    struct ifaddrs *iterate = NULL;
    void *ptr = NULL;
    getifaddrs(&addresses);
    for (iterate = addresses; iterate != NULL; iterate = iterate->ifa_next) {
        if (iterate->ifa_addr->sa_family==AF_INET) {
            ptr=&((struct sockaddr_in *)iterate->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, ptr, address, INET_ADDRSTRLEN);
            if (((address[0] == '1') && (address[1] == '0') && (address[2] == '.')) ||
                    ((address[0] == '1') && (address[1] == '2') && (address[2] == '7')) ||
                    ((address[0] == '0'))){
                continue;
            }else{
                return;
            }
        }           
    }
    //strcpy(address, "127.0.0.1");
    return;
}


//sets default options values
void set_defaults(){
    find_src_ip();
    printf("Scanning from IP %s\n", address);
    syn_settings = null_settings = fin_settings = xmas_settings = ack_settings = udp_settings = 1;
    lower_port = 1;
    upper_port = 1024;
    memset(ip, 0, MAX_ADDR);
}


/* Parses the command line arguments */
int find_option (char** option, int parameter){
    int i = 1;
    int n = 0;
    if (option[parameter][1] == '-'){
        i = 2;
    }
    switch(option[parameter][i]){
        case('h'):
            show_help();
            return 1;
        case('p'):
            if(option[parameter][i+1] == 'o'){
                if ((option[parameter + 2]) && (option[parameter + 2][0] == '-') && (strlen(option[parameter + 2]) == 1) && (isdigit(option[parameter + 3][0]))){
                    isdigit(option[parameter + 1][0]) ? set_ports(atoi(option[parameter + 1]), atoi(option[parameter + 3])) : printf("port number required\n");   
                    printf("attempting to assign port range %d to %d for scan\n", atoi(option[parameter + 1]), atoi(option[parameter + 3]));
                }else{
                    individual_ports = 1;
                    n = parameter + 1;
                    i = 0;
                    while((n < args) && (option[n][0] != '-')) {
                        set_port(option[n], i);
                        n++;
                        i++;
                    }
                    num_ports = i;
                    finalize_ports();
                }
                return 1;
            }
            if(option[parameter][i+1] == 'r'){
                //  isdigit(option[parameter + 1][0]) ? set_prefix(atoi(option[parameter + 1])) : printf("prefix number required\n");   
            }
            return 1;
        case('i'):
            set_ip(option[parameter + 1]);          
            return 1;
        case('s'):
            if (option[parameter][i+1] == 'p'){
                speedup = atoi(option[parameter + 1]);
                return 1;
            }
            syn_settings = 0;
            null_settings = 0;
            fin_settings = 0;
            xmas_settings = 0;
            ack_settings = 0;
            udp_settings = 0;
            n = parameter + 1;
            while((n < args) && (option[n][0] != '-')) {
                set_scan(option[n]);
                n++;
            }
            return 1;
        default:
            show_help();
            return 0;
    }
}

//calculates ip checksum. Modified from wiretap's UDP checksum
unsigned short checksum(unsigned short* address, int length){
    unsigned long sum;
    const unsigned short *buf = (unsigned short*) address;
    int len;
    for(len = length; len > 1; len-= 2){    
        sum += *buf++;         
    }
    if (len&1){ 
        sum += *((unsigned char *)buf);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);  
    unsigned short checksum = (unsigned short) ~sum;
    return checksum;
}

//checksum used in wiretap assignment
unsigned short udp_sum(unsigned length, unsigned short *src, unsigned short *dest, unsigned short *udp){
    unsigned long sum = 0;
    const unsigned short *buf = (unsigned short *)udp;
    unsigned short prototype = 17;
    int len;
    for(len = ntohs(length); len > 1; len-= 2){    
        sum += *buf++;         //add byte from header
        if (sum & 0x80000000){ //add words 
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    if (len&1){  //if byte length of header is odd, add a zero
        sum += *((unsigned char *)buf);
    }
    sum +=  *(src++);    //start pseudoheader, 2 bytes
    sum += *src;         //2 bytes
    sum += *(dest++);     //2 bytes
    sum += *dest;         //2 bytes
    sum += htons(17) + htons(length); //add UDP length and protocol 
    while (sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16); //slice off first 16 bit, add the carry bit
    }
    return ((unsigned short) ~sum);
}


//calculates tcp checksum. Calculates everything in host order first then reverses the endianness of the entire result.
//Somewhat cleaner than UDP method from previous assignment
unsigned short tcp_sum(unsigned short length, unsigned short *src, unsigned short *dest, unsigned short *tcp){
    long sum = 0;
    unsigned short prototype = 6;
    int i;
    //pads 0s to make 16 bit word, as defined by the RFC standard
    if ((length % 2) == 1){
        tcp[length] = 0;
        length += 1;
    }
    //constructs header entirely in host endianness
    sum += ntohs(src[0]);
    sum += ntohs(src[1]);
    sum += ntohs(dest[0]);
    sum += ntohs(dest[1]);
    sum += length;
    sum += prototype; 
    for(i = 0; i < (length/2); i++){    
        sum += ntohs(tcp[i]);         
    } 
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);  
    sum = ~sum;
    //convert to network order before we send
    return htons(((unsigned short) sum));
} 


//sets the result array with the results of the particular scan. Used by callback. 
void setresult(int port, unsigned char args, int result){ 
    if (args == UDP){    
        addresses[port - lower_port].udpresult = result;
        return;
    }
    if (args == XMAS){    
        addresses[port - lower_port].xmasresult = result;
        return;
    }
    if (args == SYN){    
        addresses[port - lower_port].synresult = result;
        return;
    }
    if (args == ACK){    
        addresses[port - lower_port].ackresult = result;
        return;
    }
    if (args == FIN){   
        addresses[port - lower_port].finresult = result;
        return;
    }
    if (args == 0){    
        addresses[port - lower_port].nullresult = result;
        return;
    }
}

//callback function. Does tcp, but could do udp/icmp with some modifications
void syn_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet_buffer){
    struct scan* scan_data = (struct scan*) args;
    int port = scan_data->port;
    unsigned char type = scan_data->type;
    addresses[port - lower_port].timeout = 0;
    int result = 0;
    struct ip *ip = (struct ip *)(packet_buffer + sizeof(struct ether_header));
    if ((ip->ip_p == IPPROTO_UDP) && (type == 0x17)){
        result = 1;
    }else if (ip->ip_p == IPPROTO_ICMP){
        struct icmphdr *icmp = (struct icmphdr*) (packet_buffer + sizeof(struct ether_header) + sizeof(struct ip));
        if (icmp->type == 3){
            if ((icmp->code == 3) && (type == UDP)){
                result = 2;
            }else{
                result = 3;
            }
        }
    }else if (ip->ip_p == IPPROTO_TCP){
        struct tcphdr *tcphdr = (struct tcphdr *) (packet_buffer + sizeof(struct ether_header) + sizeof(struct ip));
        if (((tcphdr->th_flags & 0x02) == 0x02) && ((tcphdr->th_flags & 0x10) == 0x10)){ //looks for SYN 0x02 and ACK 0x10 flags that signal an open port
            //  printf("Port %d from IP %s is open\n", port, ip);
            result = 1;
        }else if ((tcphdr->th_flags & 0x04) == 0x04){ //looks for RST 0x04 flag indicating closed port
            //   printf("Port %d from IP %s is closed\n", port, ip);
            if (type == ACK){
                result = 4;
            }else{
                result = 2;
            }   
        }
    }
    setresult(port, (u_char) type, result);
}


//crafts a TCP scan packet
int scan(int port, unsigned char type){
    struct hostent *host;
    int tcpsocket;
    struct sockaddr_in serv;
    struct sockaddr_in me; 
    socklen_t socket_size;
    if ((tcpsocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        error("socket error\n");
    }
    serv.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &(serv.sin_addr));
    inet_pton(AF_INET, address, &(me.sin_addr));
    char packet_buffer[SYN_PACKET_SIZE];
    memset(packet_buffer, 0, SYN_PACKET_SIZE);
    struct ip *iphdr = (struct ip *)packet_buffer;
    struct tcphdr *tcphdr = (struct tcphdr *) (packet_buffer + sizeof(struct ip));
    struct pseudohdr phdr;
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    iphdr->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iphdr->ip_id = htons(0);
    iphdr->ip_off = 0;
    iphdr->ip_ttl = 255;
    iphdr->ip_p = IPPROTO_TCP;
    iphdr->ip_src.s_addr = me.sin_addr.s_addr;
    iphdr->ip_dst.s_addr = serv.sin_addr.s_addr;
    iphdr->ip_sum = 0;
    tcphdr->th_sport = htons(SRC_PORT);               
    tcphdr->th_dport = htons(port);                   
    tcphdr->th_seq = random();                   
    tcphdr->th_ack = 0;                          
    tcphdr->th_x2 = 0;              
    tcphdr->th_off = 5;
    if (type == SYN){ 
        tcphdr->th_flags =  0x02; 
    }else if (type==  ACK){
        tcphdr->th_flags =  0x10; 
    }else if (type == FIN){
        tcphdr->th_flags =  0x01; 
    }else if (type == XMAS){
        tcphdr->th_flags =  0x08 | 0x20 | 0x01;
    } else if (type == 0){
        tcphdr->th_flags = 0;
    }
    tcphdr->th_win = (65535);                    
    tcphdr->th_sum = 0;                       
    tcphdr->th_urp = 0;     
    tcphdr->th_sum = tcp_sum(20, (unsigned short *)&(iphdr->ip_src.s_addr),(unsigned short *) &(iphdr->ip_dst.s_addr), (unsigned short *) tcphdr);
    // tcphdr->th_sum = htons(checksum((unsigned short *)tcphdr,sizeof(struct pseudohdr) + sizeof(struct tcphdr)));
    iphdr->ip_sum = checksum((unsigned short*) iphdr, sizeof(struct ip));
    int one = 1;
    const int *val = &one;
    if (setsockopt(tcpsocket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
        fprintf(stderr, "Warning: Cannot set HDRINCL for port %d\n",port);
    }
    if (sendto(tcpsocket, packet_buffer, iphdr->ip_len, 0, (struct sockaddr *)&serv, sizeof(serv)) < 0) {
        fprintf(stderr, "Error sending datagram for port %d\n", next_port);
    }
    struct scan this_scan;
    this_scan.type = type;
    this_scan.port = port;
    pthread_mutex_lock (&array_mutex);
    addresses[port - lower_port].timeout = 1;  //temporary variable in case we time out, if we don't then our callback sets it to zero
    pcap_dispatch(cap, 1, syn_callback, (u_char*) &this_scan); 
    if (addresses[port - lower_port].timeout){    
        if ((type == 0) || (type == XMAS) || (type == FIN)){
            setresult(port, type, OPENFILTERED);        //store the filtered result in the proper struct variable
        }else{
            setresult(port, type, FILTERED);     
        }
        // printf("Port %d from IP %s is filtered\n", port, ip);
        addresses[port - lower_port].timeout = 0;  
    }
    pthread_mutex_unlock (&array_mutex);
    close(tcpsocket);
}



int udp_scan(int port, unsigned char type){
    struct hostent *host;
    int udpsocket;
    struct sockaddr_in serv;
    struct sockaddr_in me; 
    socklen_t socket_size;
    if ((udpsocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        error("socket error\n");
    }
    serv.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &(serv.sin_addr));
    inet_pton(AF_INET, address, &(me.sin_addr));
    char packet_buffer[SYN_PACKET_SIZE];
    memset(packet_buffer, 0, SYN_PACKET_SIZE);
    struct ip *iphdr = (struct ip *)packet_buffer;
    struct udphdr *udp = (struct udphdr *) (packet_buffer + sizeof(struct ip)); 
    struct pseudohdr phdr;
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    iphdr->ip_len = sizeof(struct ip) + sizeof(struct udphdr);
    iphdr->ip_id = htons(0);
    iphdr->ip_off = 0;
    iphdr->ip_ttl = 255;
    iphdr->ip_p = IPPROTO_UDP;
    iphdr->ip_src.s_addr = me.sin_addr.s_addr;
    iphdr->ip_dst.s_addr = serv.sin_addr.s_addr;
    iphdr->ip_sum = 0;
    udp->uh_sport = htons(SRC_PORT);
    udp->uh_dport = htons(port);
    udp->uh_ulen = htons(8);
    udp->uh_sum = 0;
    udp->uh_sum = udp_sum(8, (unsigned short *)&(iphdr->ip_src.s_addr),(unsigned short *) &(iphdr->ip_dst.s_addr), (unsigned short *) udp);
    iphdr->ip_sum = checksum((unsigned short*) iphdr, sizeof(struct ip));
    int one = 1;
    const int *val = &one;
    if (setsockopt(udpsocket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
        fprintf(stderr, "Warning: Cannot set HDRINCL for port %d\n",port);
    }
    if (sendto(udpsocket, packet_buffer, iphdr->ip_len, 0, (struct sockaddr *)&serv, sizeof(serv)) < 0) {
        fprintf(stderr, "Error sending datagram for port %d\n", port);
    }
    struct scan this_scan;
    this_scan.type = type;
    this_scan.port = port;
    pthread_mutex_lock (&array_mutex);
    addresses[port - lower_port].timeout = 1;  //temporary variable in case we time out, if we don't then our callback sets it to zero
    pcap_dispatch(cap, 1, syn_callback, (u_char*) &this_scan); 
    if (addresses[port - lower_port].timeout){    
        setresult(port, type, OPENFILTERED);        //store the filtered result in the proper struct variable
        // printf("Port %d from IP %s is filtered\n", port, ip);
        addresses[port - lower_port].timeout = 0;  
    }
    pthread_mutex_unlock (&array_mutex);
    close(udpsocket);
}

//thread 1, grabs incoming packets
pcap_t *pcap_setup(){
    struct pcap_pkthdr pkthdr;
    char* packet_buffer = malloc(SYN_PACKET_SIZE);
    pcap_t *capture = NULL;
    char errbuf[256];
    char filter_program[30];
    struct bpf_program filter;
    sprintf(filter_program, "src host %s", ip); //insert target host's ip into filter comment so we only get pcap from the target
    printf("filter: %s\n", filter_program);
    if ((capture = pcap_open_live ("eth0", 65535, 0, REC_TIMEOUT, errbuf)) == NULL) {  //SPECIFY ETH0 or WIFI INTERFACE HERE
        error("pcap session failed\n");
    }
    if (pcap_compile(capture, &filter, filter_program, 0, 0) == -1) {
        error("can't compile pcap filter\n");
    }
    if (pcap_setfilter(capture, &filter) == -1) {
        error("can't set filter\n");
    }
    //loops while looking for packets. This can probably be done better with a callback, but we'd have to use mutexes. 
    return capture;
}


//scans port range as long as you pass it the proper scan constant
void *run_scan(){
    pthread_mutex_lock(&option_mutex);
    int syn_setting = syn_settings;
    int ack_setting = ack_settings;
    int fin_setting = fin_settings;
    int null_setting = null_settings;
    int udp_setting = udp_settings;
    int xmas_setting = xmas_settings;
    pthread_mutex_unlock(&option_mutex);
    int i;
    int port;
    int indi_ports;
    int total;
    printf("Working...\n");
    pthread_mutex_lock(&port_mutex);
    indi_ports = individual_ports;
    total = num_ports;
    while(1){
        if (indi_ports){
            if (next_port < total){
                port = port_array[next_port];
            }else
                return;
        }else{
            if (next_port <= upper_port){
                port = next_port;
            }else
                return;
        }
        next_port++;
        pthread_mutex_unlock (&port_mutex);
        if (syn_setting){
            scan(port, SYN);
        }
        if (ack_setting){
            scan(port, ACK);
        }
        if (fin_setting){
            scan(port, FIN);
        }
        if (xmas_setting){
            scan(port, XMAS);
        }
        if (null_setting){
            scan(port, 0);
        }
        if (udp_setting){
            udp_scan(port, 0x17);
        }
    }
}

//scans port range as long as you pass it the proper scan constant
void *run_syn_scan(){
    int i;
    printf("Working...\n");
    //1 is open, 2 is closed, 3 is filtered for the following:
    if(individual_ports){
        for(i = 0; i < num_ports; i++){
            next_port = port_array[i];
            if (syn_settings){
                scan(next_port, SYN);
            }
            if (ack_settings){
                scan(next_port, ACK);
            }
            if (fin_settings){
                scan(next_port, FIN);
            }
            if (xmas_settings){
                scan(next_port, XMAS);
            }
            if (null_settings){
                scan(next_port, 0);
            }
            if (udp_settings){
                udp_scan(next_port, 0x17);
            }
        }
    }else{
        for(next_port = lower_port; next_port <= upper_port; next_port++){
            if (syn_settings){
                scan(next_port, SYN);
            }
            if (ack_settings){
                scan(next_port, ACK);
            }
            if (fin_settings){
                scan(next_port, FIN);
            }
            if (xmas_settings){
                scan(next_port, XMAS);
            }
            if (null_settings){
                scan(next_port, 0);
            }
            if (udp_settings){
                udp_scan(next_port, 0x17);
            }
        }
    }
}

void result(int port, int result, char* type){
    printf("Port %d %s scan result: ", port, type);
    if (result == FILTERED){
        printf("filtered\n");
    }
    if (result == OPEN){
        printf("open\n");
    }
    if (result == CLOSED){
        printf("closed\n");
    }
    if (result == OPENFILTERED){
        printf("open or filtered\n");
    }
    if (result == UNFILTERED){
        printf("unfiltered\n");
    }
}

void service_running(int port){
    switch(port){
        case(21):
            printf("Service Running: FTP\n");
            break;
        case(22):
            printf("Service Running: SSH\n");
            break;
        case(23):
            printf("Service Running: Telnet\n");
            break;
        case(25):
            printf("Service Running: SMTP\n");
            break;
        case(53):
            printf("Service Running: DNS\n");
            break;
        case(80):
            printf("Service Running: HTTP\n");
            break;
        case(110):
            printf("Service Running: POP\n");
            break;
        case(119) :
            printf("Service Running: NNTP\n");
            break;
        case(143):
            printf("Service Running: IMAP\n");
            break;
        case(161):
            printf("Service Running: SNMP\n");
            break;
        case(443):
            printf("Service Running: HTTPS\n");
            break;
     }
}

//need to make this decide between more than just syn
void decider(){
    int i;
    int n = 0;
    int xmasresult; 
    int synresult;
    int ackresult;
    int finresult;
    int nullresult;
    int udpresult;
    for (i = 0; i < ((upper_port - lower_port) + 1); i++){
        if (individual_ports){
            if (i != port_array[n] - lower_port){
                continue;
            }else{
                n++;
            }
        }
        synresult = xmasresult = ackresult = finresult = nullresult = udpresult = 0;
        int port = i + lower_port;
        if (syn_settings){
            synresult = addresses[i].synresult; 
            result(port, synresult, "SYN");
        }
        if (xmas_settings){
            xmasresult = addresses[i].xmasresult;
            result(port, xmasresult, "XMAS");
        }
        if (ack_settings){
            ackresult = addresses[i].ackresult;
            result(port, ackresult, "ACK");
        }
        if (fin_settings){
            finresult = addresses[i].finresult;
            result(port, finresult, "FIN");
        }
        if (null_settings){
            nullresult = addresses[i].nullresult;
            result(port, nullresult, "NULL");
        }
        if (udp_settings){
            udpresult = addresses[i].udpresult;
            result(port, udpresult, "UDP");
        }
        service_running(i + lower_port);
        printf("CONCLUSION: ");
        if ((synresult == OPEN)){
                printf("Port %d for IP %s is open\n", i + lower_port, ip);
        }else if((synresult == CLOSED) && (udpresult == OPEN)){ 
            printf("Port %d for IP %s is open to UDP but closed to TCP\n", i + lower_port, ip);
        }else if ((synresult == CLOSED) && ((xmasresult == OPENFILTERED) || (finresult == OPENFILTERED) || (nullresult == OPENFILTERED)) && 
                    ((udpresult == CLOSED) || (udpresult == OPENFILTERED) || (udpresult == FILTERED))){
            printf("Port %d for IP %s is closed or heavily filtered\n", i + lower_port, ip);
        }else if ((synresult == CLOSED) && ((xmasresult == CLOSED) || (nullresult == CLOSED) || (finresult == CLOSED)) && 
                ((udpresult == CLOSED) || (udpresult == OPENFILTERED))){ 
            printf("Port %d for IP %s is closed\n", i + lower_port, ip);
        }else if (((synresult == FILTERED) || (ackresult == FILTERED)) && ((xmasresult == OPENFILTERED) || (finresult == OPENFILTERED) || 
                    (nullresult == OPENFILTERED) || (xmasresult == FILTERED) || (nullresult == FILTERED) || (finresult == FILTERED)) && ((udpresult == FILTERED) || 
                    (udpresult == OPENFILTERED))){ 
            printf("Port %d for IP %s is filtered\n", i + lower_port, ip);
        }else if ((synresult == FILTERED) && (ackresult == FILTERED) || ((udpresult == CLOSED) || (udpresult == OPENFILTERED))){ 
            printf("Port %d for IP %s is filtered\n", i + lower_port, ip);
        }
        printf("\n");
    }

}

int main(int argc, char** argv){
    int i = 0;
    set_defaults();
    args = argc;
    for(i = 1; i < argc; i++){
        switch((char) argv[i][0]){
            case '-': 
                if (argv[i][1] == '-'){
                    if (!find_option(argv, i)){       
                        printf("Error: Unable to parse input\n");
                        exit(0);
                    }
                }
                break;
            default: 
                break;
        }
    } 
    printf("lower: %d, upper: %d\n", lower_port, upper_port);
    if (ip_set == 0){
        error("Requires ip address\n");
    }
    addresses = (struct addr_array*)malloc(sizeof(struct addr_array) * (1 + (upper_port - lower_port)));
    cap = pcap_setup();
    if (speedup){
        if (individual_ports){
            next_port = 0;
        }else{
            next_port = lower_port;
        }
        pthread_t* threads = (pthread_t*) malloc(sizeof(pthread_t) * speedup);
        int t = 0;
        for (t = 0; t < speedup; t++){
            pthread_create(&threads[t], NULL, run_scan, NULL);
        }
        for (t = 0; t < speedup; t++){
            pthread_join(threads[t], NULL);
        }
    }else{
        pthread_t thread;
        pthread_create(&thread, NULL, run_syn_scan, NULL); 
        pthread_join(thread, NULL);
    }
    decider();
    return 0;
}
