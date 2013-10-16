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
#include "mysock_impl.h"
#include "stcp_api.h"
#include "transport.h"
#include <sys/time.h>
#include <unistd.h>

enum { CSTATE_ESTABLISHED };    /* obviously you should have more states */

/* this structure is global to a mysocket descriptor */
typedef struct {
    bool_t done;    /* TRUE once connection is closed */
    bool_t r_fin, l_fin;
    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    /* any other connection-wide global variables go here */
    tcp_seq th_local, th_remote, send_base;
} context_t;

/********************** MY GLOBAL ADDITIONS **************************/
int length=-1;
double transmitted=0.0, current=0.0;
bool_t isctrl = true, isactive;
const short PACKET_SIZE = 536;
const short HEADER_SIZE = 20;
const short TOUT = 500;
uint16_t WINDOW_SIZE;

typedef struct packet_t {
    struct timeval sent;
    uint32_t tries;
    tcp_seq seq;
    char *payload;
    packet_t *next, *prev;
    size_t len;
} Packet;

typedef struct ooorder {
    packet_t *head, *tail;
} OOOrder;

typedef struct wqueue {
    uint32_t front, back, size, max;
    packet_t *buffer;
} Queue;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
static void clear_hdr(tcphdr *);
static void clear_hdr(tcphdr *);
static void make_queue(wqueue *, context_t *);
static void destroy_queue(wqueue *);
static int enqueue(wqueue *, tcphdr *, char *, size_t);
static packet_t *dequeue(wqueue *);
static void print_packet(char *);
static void print_queue(wqueue *);
void cumulative_ack(wqueue *, tcp_seq);
int check_timeout(wqueue *);
void retransmit(mysocket_t, int, wqueue *);
unsigned long int tv2ms(struct timeval *);
void retransmit_ack(mysocket_t, wqueue *, tcp_seq);
uint32_t scanbuffer(wqueue *);
void init_ooorder(ooorder *);
void insert(ooorder *, tcphdr *, const char *, size_t);
void remove(ooorder *r_buf, tcp_seq);
void print_ooorder(ooorder *);
int topinorder(mysocket_t, ooorder *, tcp_seq);
void get_fsize(char *line);
void print_progress(double);

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
    
    ctx->l_fin = false, ctx->r_fin = false;
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
        isactive = true;
        
        // sender always has this size (as per instructiosn)
        WINDOW_SIZE = 3072;

        // Phase 1: send SYN and seqx
        hdr->th_flags = TH_SYN;
        hdr->th_seq = ctx->th_local;
        hdr->th_win = WINDOW_SIZE;
        stcp_network_send(sd, hdr, sizeof(tcphdr), NULL);
        
        // Phase 2: Receive SYN_ACK and seqy
        stcp_network_recv(sd, (void *)hdr, sizeof(tcphdr));
        ctx->th_remote = hdr->th_seq;
        
        // check for Phase 2 issues
        if (hdr->th_flags != (TH_SYN | TH_ACK) ||
            ctx->th_local+1 != hdr->th_ack) {

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
        isactive = false;
        
        /* Phase 1: Receive SYN and seqx */
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

    // modify the initial set up a bit and initialize some more variables
    ctx->th_local++;
    ctx->th_remote++;
    ctx->send_base = ctx->th_local;

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

    // use this header when parsing the incoming TCP header, or for
    // constructing an
    // outgoing SEGMENT
    tcphdr *hdr;
    hdr = (tcphdr *) calloc(1, sizeof(tcphdr));

    // this is the queue of outgoing segments from the sender
    wqueue s_queue;
    make_queue(&s_queue, ctx);

    // a linked list of out of order segments received by receiver
    ooorder r_buf;
    init_ooorder(&r_buf);

    // timeout for event
    timespec to;
    while (!ctx->done)
    {
        unsigned int event = 0;

        // set up timeout values and call wait_for_event()
        to.tv_sec = time(NULL) + 2;
        to.tv_nsec = 0;
        event = stcp_wait_for_event(sd, APP_DATA | NETWORK_DATA, &to);

        // received data from network layer
        if (event & NETWORK_DATA) {
            // read the segment into this buffer (SHOULDNT be larger than
            // PACKET_SIZE)
            char buf[PACKET_SIZE] = {0};
            // payload from segment
            char data[PACKET_SIZE - HEADER_SIZE] = {0};
            size_t rcvd = stcp_network_recv(sd, buf, PACKET_SIZE)-HEADER_SIZE;

            // copy into appropriate locations
            memcpy(hdr, buf, HEADER_SIZE);
            memcpy(data, &(buf[HEADER_SIZE]), rcvd);

            /* ACK received */
            if (hdr->th_flags == TH_ACK) {
                if (ctx->l_fin && ctx->r_fin) {  // last ACK from 4 way term
                    ctx->done = true;
                    continue;
                }

                // received an ack larger than the sendbase, receiver is ahead
                if (ctx->send_base < hdr->th_ack) {
                    ctx->send_base = hdr->th_ack;
                    // remove everything up to this ACK from sender buffer and
                    // retransmit
                    cumulative_ack(&s_queue, hdr->th_ack);
                    retransmit_ack(sd, &s_queue, hdr->th_ack);
                }
            }
            // data received inside window, send ACK, buffer if out of order
            else if (hdr->th_seq < (ctx->th_remote+WINDOW_SIZE-1)) {
                if (isctrl && isactive) {
                    isctrl = false;
                    char *copy = strdup(data);
                    get_fsize(copy);
                    free(copy);
                    if (length == -1) {
                        mysock_context_t *ctx_s = _mysock_get_context(sd);
                        ctx_s->close_requested = true;
                        continue;
                    }
                    else 
                        transmitted -= strlen(data);

                }
                    
                // insert this segment into out of order buffer
                if (hdr->th_seq >= ctx->th_remote) 
                    insert(&r_buf, hdr, data, rcvd);

                // received FIN
                if (hdr->th_flags == TH_FIN) {
                    if (!ctx->l_fin) {
                        mysock_context_t *ctx_s = _mysock_get_context(sd);
                        ctx_s->close_requested = true;
                    }
                    ctx->r_fin = true;
                }
                // correct next packet
                else if (ctx->th_remote == hdr->th_seq) {
                    hdr->th_flags = TH_ACK;
                    // send data to app
                    transmitted += rcvd;
                    print_progress(transmitted);

                    stcp_app_send(sd, data, rcvd);
                    // obtain the proper ACK (if there are more packets that
                    // were received out of order
                    int newack = topinorder(sd, &r_buf,
                                            hdr->th_seq+rcvd);
                    newack = newack == -2 ?
                        hdr->th_seq+rcvd : newack;


                    ctx->th_remote = newack;
                    hdr->th_ack = ctx->th_remote;
                    stcp_network_send(sd,hdr, HEADER_SIZE, NULL);
                    // check to see if both parties are finished
                    if (ctx->l_fin && ctx->r_fin) ctx->done = true;
                }
                // if this segment has already been ACK'd send another

                /* else if (hdr->th_seq < ctx->th_remote) { */
                else if (hdr->th_seq < ctx->th_remote+WINDOW_SIZE-1) {
                    hdr->th_flags = TH_ACK;
                    hdr->th_ack = ctx->th_remote;
                    stcp_network_send(sd, hdr, HEADER_SIZE, NULL);
                }
            }
            clear_hdr(hdr);
        } // if (NETWORK_DATA)

        // APP sending data
        if (event & APP_DATA) {
            /* the application has requested that data be sent */
            if (ctx->th_local < ctx->send_base + WINDOW_SIZE) {
                // get data for this packet
                char data[PACKET_SIZE - HEADER_SIZE] = {0};
                size_t len = stcp_app_recv(sd, data,
                                            (PACKET_SIZE - HEADER_SIZE));
                 
                // construct header for this packet
                hdr->th_seq = ctx->th_local;
                hdr->th_win = WINDOW_SIZE;

                size_t sent = stcp_network_send(sd, hdr, HEADER_SIZE, data,
                                                len, NULL)-HEADER_SIZE;
                
                enqueue(&s_queue, hdr, data, sent);
                ctx->th_local += sent;

                clear_hdr(hdr);
            }
        } // if (APP_DATA)

        // APP_CLOSE
        if (event & APP_CLOSE_REQUESTED) {
            hdr->th_flags = TH_FIN; hdr->th_seq = ctx->th_local;
            ctx->l_fin = true;
            char x[] = "";
            enqueue(&s_queue, hdr, x, 0);
            stcp_network_send(sd, hdr, HEADER_SIZE, NULL);
        } // if (APP_CLOSE_REQUESTED)

        // check for timeouts, retransmit
        int tout = check_timeout(&s_queue);
        if (tout == -2) ctx->done = true;
        else if (tout != -1)
            retransmit(sd, tout, &s_queue);
        if (ctx->l_fin && ctx->r_fin) ctx->done = true;
    }
    printf("\nDONE!\n\n");
    free(hdr);
} // control_loop()

// initializes the out of order receiver linked list
void init_ooorder(ooorder *r_buf) {
    r_buf->head = NULL; r_buf->tail = NULL;
} // init_ooorder()

// insert a segment into the receiver out of order buffer
void insert(ooorder *r_buf, tcphdr *hdr, const char *data, size_t len) {
    // get size of data and read into header and payload
    /* char *packet = (char *) calloc(1, PACKET_SIZE); */
    /* memcpy(packet, hdr, sizeof(tcphdr)); */
    /* memcpy(&packet[HEADER_SIZE], data, PACKET_SIZE-HEADER_SIZE); */

    // construct packet to be stored
    packet_t *pack = (packet_t *) calloc(1, sizeof(packet_t));
    pack->seq = hdr->th_seq;
    pack->len = len;
    pack->payload = (char *) malloc(len);
    memcpy(pack->payload, data, len);
    
    // empty list
    if (r_buf->head == NULL) {
        pack->next = NULL;
        pack->prev = NULL;
        r_buf->head = pack;
        r_buf->tail = pack;
    }
    else {
        pack->next = NULL;
        pack->prev = r_buf->tail;
        pack->prev->next = pack;
        r_buf->tail = pack;
    }
} // insert()

// remove element from receiver out of order linked list
// also removes any duplicates
void remove(ooorder *r_buf, tcp_seq seq) {
    packet_t *start = r_buf->head;
    while (start != NULL) {
        if (start->seq == seq) {
            if (start->prev == NULL) {
                r_buf->head = start->next;
                if (r_buf->head != NULL) r_buf->head->prev = NULL;
            }
            else start->prev->next = start->next;

            if (start->next == NULL) {
                r_buf->tail = start->prev;
                if (r_buf->tail != NULL) r_buf->tail->next = NULL;
            }
            else start->next->prev = start->prev;
        }
        start = start->next;
    }
} // remove()

// check for in order packets past the newest receieved
int topinorder(mysocket_t sd, ooorder *r_buf, tcp_seq seq) {
    // uhhhh........
    int newack = -2;
    packet_t *start;
    do {
        start = r_buf->head;
        while (start != NULL) {
            if (start->seq < seq) 
                remove(r_buf, start->seq);

            else if (start->seq == seq) {
                char data[PACKET_SIZE-HEADER_SIZE] = {0};
                memcpy(data, start->payload, start->len);

                transmitted += start->len;
                print_progress(transmitted);

                stcp_app_send(sd, data, start->len);

                newack = start->seq + start->len;
                remove(r_buf, seq);
                seq += start->len;
            }
            start = start->next;
        }
    } while(start != NULL);

    return newack;
} // topinorder()

// retransmits a segment that timed out. increments their retransmission counts
void retransmit(mysocket_t sd, int top, wqueue *queue) {
    gettimeofday(&(queue->buffer[top].sent), NULL);
    queue->buffer[top].tries += 1;
    stcp_network_send(sd, queue->buffer[top].payload,
                      HEADER_SIZE+queue->buffer[top].len, NULL);
} // retransmit()

// retransmits all packets in the senders buffer less than ack
void retransmit_ack(mysocket_t sd, wqueue *queue, tcp_seq ack) {
    uint i = queue->front;
    for (; i<queue->back; i++)
        if (queue->buffer[i].seq < ack)
            stcp_network_send(sd, queue->buffer[i].payload, PACKET_SIZE, NULL);
} // retransmit_ack()

// print the receiver buffer (DEBUG)
void print_ooorder(ooorder *r_buf) {
    packet_t *start = r_buf->head;
    while (start != NULL) {
        printf("SEQ: %d\n", start->seq);
        start = start->next;
    }

} // print_ooorder()

// resets a header to all 0's
void clear_hdr(tcphdr *hdr) {
    hdr->th_flags = 0;
    hdr->th_ack = 0;
    hdr->th_seq = 0;
    hdr->th_win = 0;
} // clear_hdr()

// find the first segment to have timed out and returns its index
int check_timeout(wqueue *queue) {
    uint32_t i = queue->front;
    struct timeval now;
    gettimeofday(&now, NULL);
    for (; i<queue->back; i++) {
        if (queue->buffer[i].tries == 6) return -2;
        if ((tv2ms(&now) - tv2ms(&queue->buffer[i].sent)) > (TOUT))
            return i;
    }
    return -1;
} // check_timeout()

// sets up the sender queue
void make_queue(wqueue *queue, context_t *ctx) {
    queue->front = ctx->th_local; queue->back = queue->front;
    queue->size = 0; queue->max = WINDOW_SIZE;
    queue->buffer = (packet_t *) calloc(WINDOW_SIZE, sizeof(packet_t));
} // make_queue()

// frees the memory from the sender queue
void destroy_queue(wqueue *queue) {
    free(queue->buffer);
} // destroy_queue()

// constructs and places an element in the sender queue
int enqueue(wqueue *queue, tcphdr *hdr, char *data, size_t length) {
    ssize_t len = length+HEADER_SIZE;

    char *packet = (char *) calloc(1, len);
    memcpy(packet, hdr, sizeof(tcphdr));
    memcpy(&packet[HEADER_SIZE], data, len-HEADER_SIZE);

    packet_t pack;
    pack.seq = hdr->th_seq;
    pack.payload = (char *) malloc(len);
    gettimeofday(&pack.sent, NULL);
    pack.tries = 1;
    pack.len = length;
    memcpy(pack.payload, packet, len);

    queue->buffer[queue->back] = pack;
    queue->back = (queue->back+1) % queue->max;
    queue->size += len-HEADER_SIZE;

    return len;
} // enqueue()

// removes an elements from the sender queue
packet_t *dequeue(wqueue *queue) {
    if (queue->size == 0) return NULL;

    packet_t *p = &(queue->buffer[queue->front]);
    queue->front = (queue->front+1) % queue->max;
    queue->size -= p->len;

    return p;
} // dequeue()

// removes all elements from the sender's queue up to ack
void cumulative_ack(wqueue *queue, tcp_seq ack) {
    uint32_t i = queue->front;
    for (; i<queue->back; i++) {
        if (queue->buffer[i].seq < ack) dequeue(queue);
        else break;
    }        
} // cumulative_ack()


// print the sender queue (DEBUG)
void print_queue(wqueue *queue) {
    printf("QUEUE front: %u size: %u\n", queue->front, queue->size); 
   uint32_t i=queue->front;
    struct timeval now;
    gettimeofday(&now, NULL);
    for (; i<queue->back; i++) {
        packet_t p = queue->buffer[i];
        printf("______index: %d_______\n", i);
        printf("TIME LEFT: %lu SEQ: %d TRIES: %d\n",
               tv2ms(&now)-tv2ms(&p.sent), p.seq, p.tries);
    }
} // print_queue()

// prints a packet (DEBUG)
void print_packet(char *packet) {
    tcp_seq seq, ack;
    uint8_t off, flags;
    uint16_t win;

    tcphdr *hdr;
    hdr = (tcphdr *)calloc(1, sizeof(tcphdr));
    memcpy(hdr, packet, HEADER_SIZE);

    char data[PACKET_SIZE-HEADER_SIZE];
    memcpy(data, packet+HEADER_SIZE, strlen(packet+HEADER_SIZE)+1);
    
    seq=hdr->th_seq;ack=hdr->th_ack;off=hdr->th_off;
    flags=hdr->th_flags;win=hdr->th_win;
    printf("*****************PACKET******************\n");
    printf("SEQ: %u ACK: %u OFF: %d FLAGS: %d WIN: %d\n",
           seq,ack,off,flags,win);
    /* printf("DATA: [%s]", data); */
    printf("\n*****************************************\n");

    free(hdr);
} // print_packet()

/* convert struct timeval to ms(milliseconds) */
/* FROM: http://enl.usc.edu/enl/trunk/peg/testPlayer/timeval.c */
unsigned long int tv2ms(struct timeval *a) {
    return ((a->tv_sec * 1000) + (a->tv_usec / 1000));
} // tv2ms()

void get_fsize(char *line)  {
    char *resp;

    if (NULL == (resp = strrchr(line, ','))) {
        fprintf(stderr, "Malformed response from server.\n");
        length = -1;
    }
    *resp++ = '\0';

    if (NULL == (resp = strrchr(line, ','))) {
        fprintf(stderr, "Malformed response from server.\n");
        length = -1;
    }
    *resp++ = '\0';
    
    sscanf(resp, "%d", &length);}

void print_progress(double transmitted) {
    if ((transmitted - current) >= 2000 || transmitted == length) {
        current = transmitted;
        printf("%.0f bytes out of %d bytes -- %.0f%%\n",
               transmitted, length, transmitted/length*100);
    }
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

