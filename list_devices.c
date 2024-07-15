/*
 * list_devices.c
 */

#include <pcap.h>
#include <stdio.h>

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }
    
    /* Print the list */
    int i = 0;
    for(d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    
    /* Free the device list */
    pcap_freealldevs(alldevs);
    
    return 0;
}
