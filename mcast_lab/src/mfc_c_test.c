#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/mroute.h>

void die(const char *s) {
    perror(s);
    exit(1);
}

void print_hex(const unsigned char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ifindex_in> <ifindex_out>\n", argv[0]);
        exit(1);
    }

    int ifindex_in = atoi(argv[1]);
    int ifindex_out = atoi(argv[2]);
    printf("[C Tool] Adding route: VIF 0 (ifindex %d) -> VIF 1 (ifindex %d)\n", ifindex_in, ifindex_out);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
    if (sock < 0) die("socket");

    if (setsockopt(sock, IPPROTO_IP, MRT_INIT, &(int){1}, sizeof(int)) < 0) die("setsockopt MRT_INIT");

    struct vifctl vc;

    // Add VIF 0 (input)
    memset(&vc, 0, sizeof(vc));
    vc.vifc_vifi = 0;
    vc.vifc_flags = VIFF_USE_IFINDEX;
    vc.vifc_lcl_ifindex = ifindex_in;
    if (setsockopt(sock, IPPROTO_IP, MRT_ADD_VIF, &vc, sizeof(vc)) < 0) die("setsockopt MRT_ADD_VIF 0");

    // Add VIF 1 (output)
    memset(&vc, 0, sizeof(vc));
    vc.vifc_vifi = 1;
    vc.vifc_flags = VIFF_USE_IFINDEX;
    vc.vifc_lcl_ifindex = ifindex_out;
    if (setsockopt(sock, IPPROTO_IP, MRT_ADD_VIF, &vc, sizeof(vc)) < 0) die("setsockopt MRT_ADD_VIF 1");

    // Add the MFC entry
    struct mfcctl mfc;
    memset(&mfc, 0, sizeof(mfc));
    mfc.mfcc_origin.s_addr = inet_addr("0.0.0.0");
    mfc.mfcc_mcastgrp.s_addr = inet_addr("239.1.2.3");
    mfc.mfcc_parent = 0; // Input is VIF 0
    mfc.mfcc_ttls[1] = 1; // Output is VIF 1

    printf("[C Tool] MFC struct bytes (hex): ");
    print_hex((const unsigned char *)&mfc, sizeof(mfc));
    printf("\n[C Tool] MFC struct size: %zu\n", sizeof(mfc));

    if (setsockopt(sock, IPPROTO_IP, MRT_ADD_MFC, &mfc, sizeof(mfc)) < 0) die("setsockopt MRT_ADD_MFC");

    printf("[C Tool] SUCCESS: VIFs and MFC entry added. Holding for 10s...\n");
    sleep(10);

    printf("[C Tool] Shutting down.\n");
    setsockopt(sock, IPPROTO_IP, MRT_DONE, &(int){1}, sizeof(int));
    close(sock);

    return 0;
}