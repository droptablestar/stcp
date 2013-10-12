/*
 * transport.c 
 *
 * CS536 PA2 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <sys/time.h>
#include <unistd.h>

enum { CSTATE_ESTABLISHED };    /* obviously you should have more states */

/* this structure is global to a mysocket descriptor */
typedef struct {
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    /* any other connection-wide global variables go here */
    tcp_seq th_local, th_remote, send_base, th_recvtop;
    
    char *window;
    uint32_t *unacked;
} context_t;

/********************** MY GLOBAL ADDITIONS **************************/
const short PACKET_SIZE = 536;
const short HEADER_SIZE = 20;
const short TOUT = 300;
uint16_t WINDOW_SIZE;

typedef struct packet_t {
    struct timeval sent;
    tcp_seq seq;
    char *payload;
} Packet;

typedef struct wqueue {
    uint32_t front, back, size, max;
    packet_t *buffer;
} Queue;

char *rbuf;
short *sizes;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
static void clear_hdr(tcphdr *);
static void clear_hdr(tcphdr *);
static void make_queue(wqueue *, context_t *);
static void destroy_queue(wqueue *);
static int enqueue(wqueue *, tcphdr *, char *);
static packet_t *dequeue(wqueue *);
static void print_packet(char *);
static void print_queue(wqueue *);
void cumulative_ack(wqueue *, tcp_seq);
int check_timeout(wqueue *);
void retransmit(mysocket_t, int, wqueue *);
unsigned long int tv2ms(struct timeval *);

/********************************************************************/

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active) {
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    ctx->th_local = ctx->initial_sequence_num;
    ctx->send_base = ctx->initial_sequence_num;
    
    printf("initial sequence number: %u\n", ctx->initial_sequence_num);
    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */
    tcphdr *hdr;
    hdr = (tcphdr *) calloc(1, sizeof(tcphdr));
    if (is_active) {
        ctx->th_local = 79;
        ctx->th_remote = 175;
        WINDOW_SIZE = 3072;

        // Phase 1: send SYN and seqx
        hdr->th_flags = TH_SYN;
        hdr->th_seq = ctx->th_local;
        hdr->th_win = WINDOW_SIZE;
        stcp_network_send(sd, (void *)hdr, sizeof(tcphdr), NULL);

        // Phase 2: Receive SYN_ACK and seqy
        stcp_network_recv(sd, (void *)hdr, sizeof(tcphdr));
        ctx->th_remote = hdr->th_seq;
        /* printf("ack: %d in: %d\n", hdr->th_ack, ctx->th_local); */
        
        // check for Phase 2 issues
        if (hdr->th_flags != (TH_SYN | TH_ACK) || ctx->th_local+1 != hdr->th_ack) {
            hdr->th_flags = TH_FIN;
            stcp_network_send(sd, (void *)hdr, sizeof(tcphdr), NULL);

            errno = ECONNREFUSED; perror("handshake");
            return;
        }
        // Phase 3: send ACK and complete transaction
        hdr->th_flags = TH_ACK;
        stcp_network_send(sd, (void *)hdr, sizeof(tcphdr), NULL);
    }
    else {
        ctx->th_remote = 79;
        ctx->th_local = 175;
        // Phase 1: Receive SYN and seqx
        stcp_network_recv(sd, (void *)hdr, sizeof(tcphdr));
        ctx->th_remote = hdr->th_seq;
        WINDOW_SIZE = hdr->th_win;

        // sanity check on SYN
        if (hdr->th_flags != TH_SYN || ctx->th_remote > 255) {
            hdr->th_flags = TH_FIN;
            stcp_network_send(sd, (void *)hdr, sizeof(tcphdr), NULL);
            
            return;
        }

        // Phase 2: send SYN_ACK and seqy
        hdr->th_flags = TH_SYN|TH_ACK;
        hdr->th_seq = ctx->th_local;
        hdr->th_ack = ctx->th_remote + 1;
        stcp_network_send(sd, (void *)hdr, sizeof(tcphdr), NULL);

        // Phase 3: receive ACK
        stcp_network_recv(sd, (void *)hdr, sizeof(tcphdr));
        if (hdr->th_flags != TH_ACK) {
            errno = ECONNREFUSED; perror("handshake"); return;
        }
    }
    rbuf = (char *) calloc(1, WINDOW_SIZE);
    sizes = (short *) calloc(WINDOW_SIZE, sizeof(short));
    
    ctx->th_local++;
    ctx->th_remote++;
    ctx->th_recvtop = ctx->initial_sequence_num;
    ctx->th_recvtop = ctx->th_local;
    ctx->send_base = ctx->th_local;

    ctx->window = (char *)calloc(1, WINDOW_SIZE);
    ctx->unacked = (uint32_t *)calloc(WINDOW_SIZE, sizeof(uint32_t));
    
    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
    free(hdr);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx) {
    assert(ctx);

    #ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
    #else
    /* you have to fill this up */
    unsigned int *seed = (unsigned int *)&ctx;
    srand((*seed));
    ctx->initial_sequence_num = rand()%256;
    #endif
}

/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx) {
    assert(ctx);

    tcphdr *hdr;
    hdr = (tcphdr *) calloc(1, sizeof(tcphdr));

    wqueue s_queue, r_queue;
    make_queue(&s_queue, ctx);
    make_queue(&r_queue, ctx);
    
    while (!ctx->done)
    {
        unsigned int event = 0;
        
        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, APP_DATA | NETWORK_DATA, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA) {
            /* the application has requested that data be sent */
            if (ctx->th_local < ctx->send_base + WINDOW_SIZE) {
                printf("*********APP SEND************\n");
                printf("next: %d base: %d\n", ctx->th_local, ctx->send_base);
                char data[PACKET_SIZE - HEADER_SIZE] = {0};
                stcp_app_recv(sd, data, (PACKET_SIZE - HEADER_SIZE-1));
                /* printf("data: [%s]\n", data); */
                /* printf("data: [%s] length: %lu\n", data, strlen(data)); */
                 
                // construct header for this packet
                hdr->th_seq = ctx->th_local;
                hdr->th_win = WINDOW_SIZE;

                printf("hdr->seq: %d ctx->local: %d\n",hdr->th_seq,ctx->th_local);
                stcp_network_send(sd, hdr, HEADER_SIZE, data,
                                  PACKET_SIZE - HEADER_SIZE, NULL);

                
                enqueue(&s_queue, hdr, data);
                /* print_queue(&s_queue); */
                ctx->th_local += strlen(data)+1;
                printf("packet: %d sent local: %d\n", hdr->th_seq, ctx->th_local);
                printf("*********APP SEND************\n");

                clear_hdr(hdr);
            }
        } // if (APP_DATA)

        if (event & NETWORK_DATA) {
            printf("*********NETWORK RECEIVE************\n");
            char buf[PACKET_SIZE] = {0};
            char data[PACKET_SIZE - HEADER_SIZE] = {0};
            stcp_network_recv(sd, buf, PACKET_SIZE);

            memcpy(hdr, buf, HEADER_SIZE);
            memcpy(data, &(buf[HEADER_SIZE]), PACKET_SIZE - HEADER_SIZE);
            
            printf("expected: %d received: %d\n", ctx->th_remote, hdr->th_seq);
            ctx->th_recvtop = ctx->th_remote+strlen(data) + 1;

            // ACK received
            if (hdr->th_flags == TH_ACK) {
                printf("*********ACK receieved***********\n");
                printf("local: %d remote: %d base: %d ack: %d seq: %d\n",
                       ctx->th_local, ctx->th_remote, ctx->send_base,
                       hdr->th_ack, hdr->th_seq);
                if (ctx->send_base <= hdr->th_ack) {
                    ctx->send_base = hdr->th_ack;
                    cumulative_ack(&s_queue, hdr->th_ack);
                }
            }
            // send ACK
            else if (hdr->th_seq < (ctx->th_remote+WINDOW_SIZE-1)) {
                // correct next packet
                printf("SEGMENT RECEIVED: seq: %d remote: %d\n",
                       hdr->th_seq, ctx->th_remote);
                hdr->th_flags = TH_ACK; 
                if (hdr->th_seq == ctx->th_remote) {
                    stcp_app_send(sd, data, strlen(data));
                    ctx->th_recvtop = ctx->th_remote + strlen(data);
                    ctx->th_remote += strlen(data)+1;
                    hdr->th_ack = ctx->th_remote;
                    stcp_network_send(sd, hdr, HEADER_SIZE, NULL);
                    printf("*********ACK SENT: seq: %d ack: %d************\n",
                           hdr->th_seq, hdr->th_ack);
                }
                else if (hdr->th_seq < ctx->th_remote) {
                    hdr->th_ack = ctx->th_remote;
                    stcp_network_send(sd, hdr, HEADER_SIZE, NULL);
                    printf("*********ACK SENT: seq: %d ack: %d************\n",
                           hdr->th_seq, hdr->th_ack);
                }
                // out of order packet
                /* else { */
                /*     sizes[seq] = strlen(data); */
                /*     strcpy(&(rbuf[seq]), data); */
                /*     ctx->th_recvtop = seq; */
                /* } */
            }
            clear_hdr(hdr);
        } // if (NETWORK_DATA)

        int start;
        if ((start = check_timeout(&s_queue)) != -1) 
            retransmit(sd, start, &s_queue);
    }

    free(hdr);
    /* free(&s_queue); */
    /* free(&r_queue); */
}

void clear_hdr(tcphdr *hdr) {
    hdr->th_flags = 0;
    hdr->th_ack = 0;
    hdr->th_seq = 0;
    hdr->th_win = 0;
}

int check_timeout(wqueue *queue) {
    uint32_t i = queue->front;
    /* print_queue(queue); */
    struct timeval now;
    gettimeofday(&now, NULL);
    /* printf("CHECKING TIMOUT front: %d back: %d seq: %d now: %lu then: %lu\n", */
    /*        queue->front, queue->back, queue->buffer[i].seq, */
    /*        tv2ms(&now), tv2ms(&queue->buffer[i].sent)); */
    for (; i<queue->back; i++) {
        if ((tv2ms(&now) - tv2ms(&queue->buffer[i].sent)) > TOUT)
            return i;
    }
    return -1;
}

void make_queue(wqueue *queue, context_t *ctx) {
    queue->front = ctx->th_local; queue->back = queue->front;
    queue->size = 0; queue->max = WINDOW_SIZE;
    queue->buffer = (packet_t *) calloc(WINDOW_SIZE, sizeof(packet_t));
}

void destroy_queue(wqueue *queue) {
    free(queue->buffer);
}

int enqueue(wqueue *queue, tcphdr *hdr, char *data) {
    ssize_t len = strlen(data)+HEADER_SIZE+1;
    printf("ENQUEUING: seq: %d \n", hdr->th_seq);

    char *packet = (char *) calloc(1, len);
    memcpy(packet, hdr, sizeof(tcphdr));
    memcpy(&packet[HEADER_SIZE], data, len-HEADER_SIZE);

    packet_t pack;
    pack.seq = hdr->th_seq;
    pack.payload = (char *) malloc(len);
    gettimeofday(&pack.sent, NULL);
    memcpy(pack.payload, packet, len);

    queue->buffer[queue->back] = pack;
    queue->back = (queue->back+1) % queue->max;
    queue->size += len-HEADER_SIZE;

    return len;
}

void print_queue(wqueue *queue) {
    printf("QUEUE front: %u size: %u\n", queue->front, queue->size);
    uint32_t i=queue->front;
    for (; i<queue->back; i++) {
        packet_t p = queue->buffer[i];
        printf("______index: %d_______\n", i);
        print_packet(p.payload);
    }
}

packet_t *dequeue(wqueue *queue) {
    if (queue->size == 0) return NULL;

    packet_t *p = &(queue->buffer[queue->front]);
    printf("****REMOVING: %d***\n", p->seq);
    queue->front = (queue->front+1) % queue->max;
    queue->size -= strlen(&(p->payload[HEADER_SIZE]))+1;

    return p;
}

void cumulative_ack(wqueue *queue, tcp_seq ack) {
    uint32_t i = queue->front;
    packet_t *p = &(queue->buffer[i]);
    /* printf("CUMUL_ACK: front: %d back: %d seq: %d ack: %d\n", */
    /*        queue->front, queue->back, p->seq, ack); */
    for (; i<queue->back; i++) {
        if (queue->buffer[i].seq < ack) p = dequeue(queue);
        else break;
        printf("**ACKING: %d**\n", p->seq);
    }        
}

void retransmit(mysocket_t sd, int start, wqueue *queue) {
    /* printf("RETRANSMITTING: %d seq: %d\n", start, queue->buffer[start].seq); */
    stcp_network_send(sd, queue->buffer[start].payload, PACKET_SIZE, NULL);
}

void print_packet(char *packet) {
    tcp_seq seq, ack;
    uint8_t off, flags;
    uint16_t win;

    tcphdr *hdr;
    hdr = (tcphdr *)calloc(1, sizeof(tcphdr));
    memcpy(hdr, packet, HEADER_SIZE);

    char data[PACKET_SIZE-HEADER_SIZE];
    memcpy(data, packet+HEADER_SIZE, strlen(packet+HEADER_SIZE)+1);
    
    seq=hdr->th_seq;ack=hdr->th_ack;off=hdr->th_off;flags=hdr->th_flags;win=hdr->th_win;
    printf("*****************PACKET******************\n");
    printf("SEQ: %u ACK: %u OFF: %d FLAGS: %d WIN: %d\n",seq,ack,off,flags,win);
    /* printf("DATA: [%s]", data); */
    printf("\n*****************************************\n");

    free(hdr);
}

/* convert struct timeval to ms(milliseconds) */
/* FROM: http://enl.usc.edu/enl/trunk/peg/testPlayer/timeval.c */
unsigned long int tv2ms(struct timeval *a) {
    return ((a->tv_sec * 1000) + (a->tv_usec / 1000));
}

/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
    void our_dprintf(const char *format,...) {
    printf("our_dprintf\n");
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}

