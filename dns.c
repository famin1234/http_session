#include "mem.h"
#include "net.h"
#include "aio.h"
#include "log.h"
#include "dns.h"

#define DNS_BUFFER_MAX 1460
#define DNS_TIMEOUT (1000 * 3)

#define RFC1035_TYPE_A 1
#define RFC1035_TYPE_AAAA 28
#define RFC1035_TYPE_CNAME 5
#define RFC1035_TYPE_PTR 12
#define RFC1035_CLASS_IN 1
#define DNS_EXPIRE_TIME (60 * 1000)

#define RFC1035_MAXHOSTNAMESZ 256
#define RFC1035_MAXLABELSZ 63
#define rfc1035_unpack_error 15

struct dns_cache_table_t {
    struct rb_root rb_root;
    pthread_mutex_t mutex;
    int count;
};

struct dns_client_t {
    struct net_thread_t *net_thread;
    struct conn_t *conn;
    struct dns_cache_t *dns_cache;
    struct list_head_t list;//callback list need mutex
    uint16_t id;
};

struct rfc1035_query_t {
    char name[RFC1035_MAXHOSTNAMESZ];
    unsigned short qtype;
    unsigned short qclass;
};

struct rfc1035_rr_t {
    char name[RFC1035_MAXHOSTNAMESZ];
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rdlength;
    char *rdata;
};

struct rfc1035_message_t {
    unsigned short id;
    unsigned int qr:1;
    unsigned int opcode:4;
    unsigned int aa:1;
    unsigned int tc:1;
    unsigned int rd:1;
    unsigned int ra:1;
    unsigned int rcode:4;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
    struct rfc1035_query_t *query;
    struct rfc1035_rr_t *answer;
};

static struct conn_addr_t dns_addr;
static struct dns_cache_table_t dns_cache_table;

static struct dns_cache_t* dns_cache_alloc(const char *host);
static void dns_cache_free(struct dns_cache_t *dns_cache);
static struct dns_cache_t* dns_cache_table_lookup(const void *host);
static int dns_cache_table_insert(struct dns_cache_t *dns_cache);
static int dns_cache_table_erase(struct dns_cache_t *dns_cache);
static void dns_client_create(struct dns_cache_t *dns_cache, struct net_thread_t *net_thread);
static void dns_client_connect(struct dns_client_t *dns_client);
static void dns_client_read(struct conn_t *conn);
static void dns_client_write(struct conn_t *conn);
static void dns_client_timeout(struct conn_t *conn);
static void dns_client_close(struct dns_client_t *dns_client, int error);
static void dns_client_parse(struct dns_client_t *dns_client, const char *buf, size_t len);
static int rfc1035NamePack(char *buf, size_t sz, const char *name);
static int rfc1035LabelPack(char *buf, size_t sz, const char *label);
static int rfc1035MessageUnpack(const char *buf, size_t sz, struct rfc1035_message_t **answer);
static int rfc1035HeaderUnpack(const char *buf, size_t sz, int *off, struct rfc1035_message_t *h);
static int rfc1035QueryUnpack(const char *buf, size_t sz, int *off, struct rfc1035_query_t *query);
static int rfc1035RRUnpack(const char *buf, size_t sz, int *off, struct rfc1035_rr_t *RR);
static int rfc1035NameUnpack(const char *buf, size_t sz, int *off, unsigned short *rdlength, char *name, size_t ns, int rdepth);
static void rfc1035RRDestroy(struct rfc1035_rr_t * rr, int n);
static void rfc1035MessageDestroy(struct rfc1035_message_t *msg);
//static int rfc1035QueryCompare(const struct rfc1035_query_t *a, const struct rfc1035_query_t *b);
static const char* rfc1035MessageErrno(int rfc1035_errno);

static struct dns_cache_t* dns_cache_alloc(const char *host)
{
    struct dns_cache_t *dns_cache = NULL;

    dns_cache = mem_malloc(sizeof(struct dns_cache_t));
    memset(dns_cache, 0, sizeof(struct dns_cache_t));
    dns_cache->host = mem_strdup(host);
    INIT_LIST_HEAD(&dns_cache->addr_list);
    return dns_cache;
}

static void dns_cache_free(struct dns_cache_t *dns_cache)
{
    struct dns_addr_t *dns_addr;

    mem_free(dns_cache->host);
    while (!list_empty(&dns_cache->addr_list)) {
        dns_addr = d_list_head(&dns_cache->addr_list, struct dns_addr_t, node);
        list_del(&dns_addr->node);
        mem_free(dns_addr);
    }
    mem_free(dns_cache);
}

static struct dns_cache_t* dns_cache_table_lookup(const void *host)
{
    struct rb_node *node = dns_cache_table.rb_root.rb_node;
    struct dns_cache_t *dns_cache;
    int cmp;

    while (node) {
        dns_cache = (struct dns_cache_t *)rb_entry(node, struct dns_cache_t, rb_node);
        cmp = strcmp(host, dns_cache->host);
        if (cmp < 0) {
            node = node->rb_left;
        } else if (cmp > 0) {
            node = node->rb_right;
        } else {
            return dns_cache;
        }
    }
    return NULL;
};

static int dns_cache_table_insert(struct dns_cache_t *dns_cache)
{
    struct rb_node **p = &dns_cache_table.rb_root.rb_node;
    struct rb_node *parent = NULL;
    struct dns_cache_t *tmp;
    int cmp;

    while (*p) {
        parent = *p;
        tmp = rb_entry(parent, struct dns_cache_t, rb_node);
        cmp = strcmp(dns_cache->host, tmp->host);
        if (cmp < 0) {
            p = &(*p)->rb_left;
        } else if (cmp > 0) {
            p = &(*p)->rb_right;
        }  else {
            return -1;
        }
    }
    rb_link_node(&dns_cache->rb_node, parent, p);
    rb_insert_color(&dns_cache->rb_node, &dns_cache_table.rb_root);
    dns_cache_table.count++;
    return 0;
}

static int dns_cache_table_erase(struct dns_cache_t *dns_cache)
{
    rb_erase(&dns_cache->rb_node, &dns_cache_table.rb_root);
    dns_cache_table.count--;
    return 0;
}

static void dns_client_create(struct dns_cache_t *dns_cache, struct net_thread_t *net_thread)
{
    struct dns_client_t *dns_client = NULL;

    dns_cache->dns_client = dns_client = mem_malloc(sizeof(struct dns_client_t));
    memset(dns_client, 0, sizeof(struct dns_client_t));
    dns_client->net_thread = net_thread;
    dns_client->dns_cache = dns_cache;
    INIT_LIST_HEAD(&dns_client->list);
}

static void dns_client_connect(struct dns_client_t *dns_client)
{
    net_socket_t sock;
    struct conn_t *conn = NULL;
    struct dns_cache_t *dns_cache = dns_client->dns_cache;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock > 0) {
        dns_client->conn = conn = conn_alloc();
        conn->sock = sock;
        conn->peer_addr = dns_addr;
        conn->net_thread = dns_client->net_thread;
        conn_nonblock(conn);
        conn->handle_read = dns_client_read;
        conn->handle_write = dns_client_write;
        conn->handle_timeout = dns_client_timeout;
        conn->data = dns_client;
        conn_timer_set(conn, DNS_TIMEOUT);
        conn_ready_set(conn, CONN_WRITE);
        conn_enable(conn, CONN_WRITE);
    } else {
        LOG(LOG_ERROR, "host=%s socket error:%s\n", dns_cache->host, strerror(errno));
        dns_client_close(dns_client, -1);
    }
}

static void dns_client_read(struct conn_t *conn)
{
    struct dns_client_t *dns_client = conn->data;
    struct dns_cache_t *dns_cache = dns_client->dns_cache;
    char *host = dns_cache->host;
    struct conn_addr_t conn_addr;
    conn_addr.addrlen = conn->peer_addr.addrlen;
    char buf[DNS_BUFFER_MAX];
    ssize_t n;

    n = recvfrom(conn->sock, buf, sizeof(buf), 0, &conn_addr.addr, &conn_addr.addrlen);
    if (n > 0) {
        LOG(LOG_DEBUG, "host=%s sock=%d recv=%zd\n", host, conn->sock, n);
        dns_client_parse(dns_client, buf, n);
        dns_client_close(dns_client, 0);
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_ready_unset(conn, CONN_READ);
        conn_enable(conn, CONN_READ);
    } else {
        LOG(LOG_ERROR, "host=%s sock=%d recv=%zd error:%s\n", host, conn->sock, n, strerror(errno));
        dns_client_close(dns_client, -1);
    }
}

static void dns_client_write(struct conn_t *conn)
{
    struct dns_client_t *dns_client = conn->data;
    struct dns_cache_t *dns_cache = dns_client->dns_cache;
    char *host = dns_cache->host;
    char buf[DNS_BUFFER_MAX];
    size_t buf_len = 0;
    ssize_t n;
    uint16_t s;
    uint16_t t;

    dns_client->id = rand() % 65535;
    s = htons(dns_client->id);
    memcpy(buf + buf_len, &s, sizeof(s));
    buf_len += sizeof(s);
    t = 0;
    t |= (0 << 15);//qr
    t |= (0 << 11);//opcode
    t |= (0 << 10);//aa
    t |= (0 << 9);//tc
    t |= (1 << 8);//rd
    t |= (0 << 7);//ra
    t |= 0;//rcode
    s = htons(t);
    memcpy(buf + buf_len, &s, sizeof(s));
    buf_len += sizeof(s);
    s = htons(1);//qdcount
    memcpy(buf + buf_len, &s, sizeof(s));
    buf_len += sizeof(s);
    s = htons(0);//ancount
    memcpy(buf + buf_len, &s, sizeof(s));
    buf_len += sizeof(s);
    s = htons(0);//nscount
    memcpy(buf + buf_len, &s, sizeof(s));
    buf_len += sizeof(s);
    s = htons(0);//arcount
    memcpy(buf + buf_len, &s, sizeof(s));
    buf_len += sizeof(s);
    buf_len += rfc1035NamePack(buf + buf_len, sizeof(buf) - buf_len, host);
    s = htons(RFC1035_TYPE_A);
    memcpy(buf + buf_len, &s, sizeof(s));
    buf_len += sizeof(s);
    s = htons(RFC1035_CLASS_IN);
    memcpy(buf + buf_len, &s, sizeof(s));
    buf_len += sizeof(s);

    n = sendto(conn->sock, buf, buf_len, 0, &conn->peer_addr.addr, conn->peer_addr.addrlen);
    if (n > 0) {
        LOG(LOG_DEBUG, "host=%s sock=%d send=%zd\n", host, conn->sock, n);
        if (n == buf_len) {
            conn_disable(conn, CONN_WRITE);
            conn_enable(conn, CONN_READ);
        } else {
            LOG(LOG_ERROR, "host=%s sock=%d send %zd < %zu\n", host, conn->sock, n, buf_len);
            dns_client_close(dns_client, -1);
        }
    } else if(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_ready_unset(conn, CONN_WRITE);
        conn_enable(conn, CONN_WRITE);
    } else {
        LOG(LOG_ERROR, "host=%s sock=%d send=%zd error:%s\n", host, conn->sock, n, strerror(errno));
        dns_client_close(dns_client, -1);
    }
}

static void dns_client_timeout(struct conn_t *conn)
{
    struct dns_client_t *dns_client = conn->data;
    struct dns_cache_t *dns_cache = dns_client->dns_cache;

    LOG(LOG_ERROR, "host=%s sock=%d timeout\n", dns_cache->host, conn->sock);
    dns_client_close(dns_client, -1);
}

static void dns_client_close(struct dns_client_t *dns_client, int error)
{
    struct net_thread_t *net_thread = dns_client->net_thread;
    struct dns_cache_t *dns_cache = dns_client->dns_cache;
    struct aio_t *aio;

    if (dns_client->conn) {
        conn_close(dns_client->conn);
        dns_client->conn = NULL;
    }
    pthread_mutex_lock(&dns_cache_table.mutex);
    dns_cache->dns_client = NULL;
    if (error) {
        dns_cache_table_erase(dns_cache);
        pthread_mutex_unlock(&dns_cache_table.mutex);
        dns_cache_free(dns_cache);
        dns_cache = NULL;
    } else {
        pthread_mutex_unlock(&dns_cache_table.mutex);
    }
    while (!list_empty(&dns_client->list)) {
        aio = d_list_head(&dns_client->list, struct aio_t, node);
        list_del(&aio->node);
        aio->extra = dns_cache;
        if (net_thread == aio->net_thread) {
            aio_handle_done(aio);
        } else {
            net_thread_aio_add(aio);
        }
    }
    mem_free(dns_client);
}

static void dns_client_parse(struct dns_client_t *dns_client, const char *buf, size_t len)
{
    struct conn_t *conn = dns_client->conn;
    struct dns_cache_t *dns_cache = dns_client->dns_cache;
    char *host = dns_cache->host;
    struct rfc1035_message_t *message = NULL;
    struct rfc1035_rr_t *answers = NULL;
    struct dns_addr_t *dns_addr;
    int i, n;
    //char cname[256];
    int ttl = 0;
    char ip[64];

    n = rfc1035MessageUnpack(buf, len, &message);
    if (n <= 0) {
        LOG(LOG_DEBUG, "host=%s sock=%d tc=%d %s\n", host, conn->sock, message->tc, rfc1035MessageErrno(-n));
    }
    if (message == NULL) {
        return;
    }
    if (dns_client->id != message->id) {
        LOG(LOG_ERROR, "host=%s sock=%d id %d != %d\n", host, conn->sock, dns_client->id, message->id);
        return;
    }
    answers = message->answer;
    for (i = 0; i < n; i++) {
        if (answers[i].class != RFC1035_CLASS_IN) {
            continue;
        }
        if (answers[i].type == RFC1035_TYPE_A) {
            if (answers[i].rdlength != sizeof(struct in_addr)) {
                continue;
            }
            dns_addr = mem_malloc(sizeof(struct dns_addr_t));
            dns_addr->af = AF_INET;
            memcpy(&dns_addr->in_addr, answers[i].rdata, sizeof(struct in_addr));
            inet_ntop(dns_addr->af, &dns_addr->in_addr, ip, sizeof(ip));
            LOG(LOG_DEBUG, "host=%s sock=%d ip=%s\n", dns_cache->host, conn->sock, ip);
            list_add_tail(&dns_addr->node, &dns_cache->addr_list);
        }
        if (answers[i].type == RFC1035_TYPE_AAAA) {
            if (answers[i].rdlength != sizeof(struct in6_addr)) {
                continue;
            }
            dns_addr = mem_malloc(sizeof(struct dns_addr_t));
            dns_addr->af = AF_INET6;
            memcpy(&dns_addr->in6_addr, answers[i].rdata, sizeof(struct in6_addr));
            inet_ntop(dns_addr->af, &dns_addr->in6_addr, ip, sizeof(ip));
            LOG(LOG_DEBUG, "host=%s sock=%d ip=%s\n", dns_cache->host, conn->sock, ip);
            list_add_tail(&dns_addr->node, &dns_cache->addr_list);
        }
        if (answers[i].type == RFC1035_TYPE_CNAME) {
            LOG(LOG_DEBUG, "host=%s sock=%d cname=%.*s\n", dns_cache->host, conn->sock, answers[i].rdlength, answers[i].rdata);
        }
        LOG(LOG_DEBUG, "host=%s sock=%d ttl=%d\n", dns_cache->host, conn->sock, answers[i].ttl);
        if (ttl == 0 || ttl > answers[i].ttl) {
            ttl = answers[i].ttl;
        }
    }
    dns_cache->ttl = ttl;
    rfc1035MessageDestroy(message);
}

static int rfc1035NamePack(char *buf, size_t sz, const char *name)
{
    int off = 0;
    char *copy = mem_strdup(name);
    char *t;
    char *saveptr = NULL;
    /*
     * NOTE: use of strtok here makes names like foo....com valid.
     */
    for (t = strtok_r(copy, ".", &saveptr); t; t = strtok_r(NULL, ".", &saveptr))
        off += rfc1035LabelPack(buf + off, sz - off, t);
    mem_free(copy);
    off += rfc1035LabelPack(buf + off, sz - off, NULL);
    /* never happen */
    //assert(off <= sz);
    return off;
}

static int rfc1035LabelPack(char *buf, size_t sz, const char *label)
{
    int off = 0;
    size_t len = label ? strlen(label) : 0;
    if (label) {
        if (strchr(label, '.')) {
            return 0;
        }
    }
    if (len > RFC1035_MAXLABELSZ)
        len = RFC1035_MAXLABELSZ;
    if (sz < len + 1) {
        return 0;
    }
    *(buf + off) = (char) len;
    off++;
    if (len > 0) {
        memcpy(buf + off, label, len);
    }
    off += len;
    return off;
}

static int rfc1035MessageUnpack(const char *buf, size_t sz, struct rfc1035_message_t **answer)
{
    int off = 0;
    int i;
    int nr = 0;
    struct rfc1035_message_t *msg;
    struct rfc1035_rr_t *recs;
    struct rfc1035_query_t *querys;

    msg = mem_malloc(sizeof(struct rfc1035_message_t));
    memset(msg, 0, sizeof(struct rfc1035_message_t));
    if (rfc1035HeaderUnpack(buf + off, sz - off, &off, msg)) {
        mem_free(msg);
        return -rfc1035_unpack_error;
    }
    i = (int) msg->qdcount;
    if (i != 1) {
        /* This can not be an answer to our queries.. */
        mem_free(msg);
        return -rfc1035_unpack_error;
    }
    querys = msg->query = mem_malloc((int)msg->qdcount * sizeof(struct rfc1035_query_t));
    memset(querys, 0, (int)msg->qdcount * sizeof(struct rfc1035_query_t));
    for (i = 0; i < (int) msg->qdcount; i++) {
        if (rfc1035QueryUnpack(buf, sz, &off, &querys[i])) {
            rfc1035MessageDestroy(msg);
            return -rfc1035_unpack_error;
        }
    }
    *answer = msg;
    if (msg->rcode) {
        return -(int) msg->rcode;
    }
    if (msg->ancount == 0)
        return 0;
    recs = msg->answer = mem_malloc((int)msg->ancount * sizeof(struct rfc1035_rr_t));
    memset(recs, 0, (int)msg->ancount * sizeof(struct rfc1035_rr_t));
    for (i = 0; i < (int) msg->ancount; i++) {
        if (off >= sz) {		/* corrupt packet */
            break;
        }
        if (rfc1035RRUnpack(buf, sz, &off, &recs[i])) {	/* corrupt RR */
            break;
        }
        nr++;
    }
    if (nr == 0) {
        /*
         * we expected to unpack some answers (ancount != 0), but
         * didn't actually get any.
         */
        rfc1035MessageDestroy(msg);
        *answer = NULL;
        return -rfc1035_unpack_error;
    }
    return nr;
}

static int rfc1035HeaderUnpack(const char *buf, size_t sz, int *off, struct rfc1035_message_t *h)
{
    unsigned short s;
    unsigned short t;

    if (*off) {
        return 1;
    }
    /*
     * The header is 12 octets.  This is a bogus message if the size
     * is less than that.
     */
    if (sz < 12)
        return 1;
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->id = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    t = ntohs(s);
    h->qr = (t >> 15) & 0x01;
    h->opcode = (t >> 11) & 0x0F;
    h->aa = (t >> 10) & 0x01;
    h->tc = (t >> 9) & 0x01;
    h->rd = (t >> 8) & 0x01;
    h->ra = (t >> 7) & 0x01;
    /*
     * We might want to check that the reserved 'Z' bits (6-4) are
     * all zero as per RFC 1035.  If not the message should be
     * rejected.
     */
    h->rcode = t & 0x0F;
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->qdcount = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->ancount = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->nscount = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->arcount = ntohs(s);
    return 0;
}

static int rfc1035QueryUnpack(const char *buf, size_t sz, int *off, struct rfc1035_query_t *query)
{
    unsigned short s;

    if (rfc1035NameUnpack(buf, sz, off, NULL, query->name, RFC1035_MAXHOSTNAMESZ, 0)) {
        memset(query, '\0', sizeof(*query));
        return 1;
    }
    if (*off + 4 > sz) {
        memset(query, '\0', sizeof(*query));
        return 1;
    }
    memcpy(&s, buf + *off, 2);
    *off += 2;
    query->qtype = ntohs(s);
    memcpy(&s, buf + *off, 2);
    *off += 2;
    query->qclass = ntohs(s);
    return 0;
}

static int rfc1035RRUnpack(const char *buf, size_t sz, int *off, struct rfc1035_rr_t *RR)
{
    unsigned short s;
    unsigned int i;
    unsigned short rdlength;
    int rdata_off;

    if (rfc1035NameUnpack(buf, sz, off, NULL, RR->name, RFC1035_MAXHOSTNAMESZ, 0)) {
        memset(RR, '\0', sizeof(*RR));
        return 1;
    }
    /*
     * Make sure the remaining message has enough octets for the
     * rest of the RR fields.
     */
    if ((*off) + 10 > sz) {
        memset(RR, '\0', sizeof(*RR));
        return 1;
    }
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    RR->type = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    RR->class = ntohs(s);
    memcpy(&i, buf + (*off), sizeof(i));
    (*off) += sizeof(i);
    RR->ttl = ntohl(i);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    rdlength = ntohs(s);
    if ((*off) + rdlength > sz) {
        /*
         * We got a truncated packet.  'dnscache' truncates UDP
         * replies at 512 octets, as per RFC 1035.
         */
        memset(RR, '\0', sizeof(*RR));
        return 1;
    }
    RR->rdlength = rdlength;
    switch (RR->type) {
        case RFC1035_TYPE_CNAME:
        case RFC1035_TYPE_PTR:
            RR->rdata = mem_malloc(RFC1035_MAXHOSTNAMESZ);
            rdata_off = *off;
            RR->rdlength = 0;		/* Filled in by rfc1035NameUnpack */
            if (rfc1035NameUnpack(buf, sz, &rdata_off, &RR->rdlength, RR->rdata, RFC1035_MAXHOSTNAMESZ, 0))
                return 1;
            if (rdata_off > ((*off) + rdlength)) {
                /*
                 * This probably doesn't happen for valid packets, but
                 * I want to make sure that NameUnpack doesn't go beyond
                 * the RDATA area.
                 */
                mem_free(RR->rdata);
                memset(RR, '\0', sizeof(*RR));
                return 1;
            }
            break;
        case RFC1035_TYPE_A:
        default:
            RR->rdata = mem_malloc(rdlength);
            memcpy(RR->rdata, buf + (*off), rdlength);
            break;
    }
    (*off) += rdlength;
    if ((*off) > sz) {
        return 1;
    }
    return 0;
}

static int rfc1035NameUnpack(const char *buf, size_t sz, int *off, unsigned short *rdlength, char *name, size_t ns, int rdepth)
{
    int no = 0;
    unsigned char c;
    size_t len;

    if (ns <= 0) {
        return 1;
    }
    do {
        if ((*off) >= sz) {
            return 1;
        }
        c = *(buf + (*off));
        if (c > 191) {
            /* blasted compression */
            unsigned short s;
            int ptr;
            if (rdepth > 64)	/* infinite pointer loop */
                return 1;
            memcpy(&s, buf + (*off), sizeof(s));
            s = ntohs(s);
            (*off) += sizeof(s);
            /* Sanity check */
            if ((*off) >= sz)
                return 1;
            ptr = s & 0x3FFF;
            /* Make sure the pointer is inside this message */
            if (ptr >= sz)
                return 1;
            return rfc1035NameUnpack(buf, sz, &ptr, rdlength, name + no, ns - no, rdepth + 1);
        } else if (c > RFC1035_MAXLABELSZ) {
            /*
             * "(The 10 and 01 combinations are reserved for future use.)"
             */
            return 1;
        } else {
            (*off)++;
            len = (size_t) c;
            if (len == 0)
                break;
            if (len > (ns - no - 1))	/* label won't fit */
                return 1;
            if ((*off) + len >= sz)	/* message is too short */
                return 1;
            memcpy(name + no, buf + (*off), len);
            (*off) += len;
            no += len;
            *(name + (no++)) = '.';
            if (rdlength)
                *rdlength += len + 1;
        }
    } while (c > 0 && no < ns);
    if (no)
        *(name + no - 1) = '\0';
    else
        *name = '\0';
    /* make sure we didn't allow someone to overflow the name buffer */
    /* never happen, no has been judged before copy */
    //assert(no <= ns);
    return 0;
}

static void rfc1035RRDestroy(struct rfc1035_rr_t * rr, int n)
{
    if (rr == NULL)
        return;
    if (n > 0) {
        while (n--) {
            if (rr[n].rdata)
                mem_free(rr[n].rdata);
        }
    }
    mem_free(rr);
}

static void rfc1035MessageDestroy(struct rfc1035_message_t *msg)
{
    if (!msg)
        return;
    if (msg->query)
        mem_free(msg->query);
    if (msg->answer)
        rfc1035RRDestroy(msg->answer, msg->ancount);
    mem_free(msg);
}

#if 0
static int rfc1035QueryCompare(const struct rfc1035_query_t *a, const struct rfc1035_query_t *b)
{
    size_t la, lb;

    if (a->qtype != b->qtype)
        return 1;
    if (a->qclass != b->qclass)
        return 1;
    la = strlen(a->name);
    lb = strlen(b->name);
    if (la != lb) {
        /* Trim root label(s) */
        while (la > 0 && a->name[la - 1] == '.')
            la--;
        while (lb > 0 && b->name[lb - 1] == '.')
            lb--;
    }
    if (la != lb)
        return 1;

    return strncasecmp(a->name, b->name, la);
}
#endif

static const char* rfc1035MessageErrno(int rfc1035_errno)
{
    char *rfc1035_error_message = NULL;

    switch (rfc1035_errno) {
        case 0:
            rfc1035_error_message = "No error condition";
            break;
        case 1:
            rfc1035_error_message = "Format Error: The name server was " "unable to interpret the query.";
            break;
        case 2:
            rfc1035_error_message = "Server Failure: The name server was " "unable to process this query.";
            break;
        case 3:
            rfc1035_error_message = "Name Error: The domain name does " "not exist.";
            break;
        case 4:
            rfc1035_error_message = "Not Implemented: The name server does " "not support the requested kind of query.";
            break;
        case 5:
            rfc1035_error_message = "Refused: The name server refuses to " "perform the specified operation.";
            break;
        case rfc1035_unpack_error:
            rfc1035_error_message = "The DNS reply message is corrupt or could " "not be safely parsed.";
            break;
        default:
            rfc1035_error_message = "Unknown Error";
            break;
    }
    return rfc1035_error_message;
}

void dns_init()
{
    srandom(time(NULL));
    memset(&dns_cache_table, 0, sizeof(struct dns_cache_table_t));
    pthread_mutex_init(&dns_cache_table.mutex, NULL);
    dns_cache_table.rb_root = RB_ROOT;
    conn_addr_pton(&dns_addr, "8.8.8.8", 53);
}

void dns_clean()
{
    struct dns_cache_t *dns_cache = NULL;
    struct rb_node *node = NULL;

    while ((node = rb_first(&dns_cache_table.rb_root))) {
        dns_cache = rb_entry(node, struct dns_cache_t, rb_node);
        dns_cache_table_erase(dns_cache);
        dns_cache_free(dns_cache);
    }
    pthread_mutex_destroy(&dns_cache_table.mutex);
    memset(&dns_cache_table, 0, sizeof(struct dns_cache_table_t));
}

void dns_cache_table_query(struct aio_t *aio, const char *host)
{
    struct dns_cache_t *dns_cache;
    struct dns_client_t *dns_client;
    int query = 0;

    pthread_mutex_lock(&dns_cache_table.mutex);
    dns_cache = dns_cache_table_lookup(host);
    if (dns_cache == NULL) {
        dns_cache = dns_cache_alloc(host);
        dns_cache_table_insert(dns_cache);
        dns_client_create(dns_cache, aio->net_thread);
        query = 1;
    }
    dns_client = dns_cache->dns_client;
    if (dns_client) {
        aio->extra = NULL;
        list_add_tail(&aio->node, &dns_client->list);
    } else {
        aio->extra = dns_cache;
    }
    dns_cache->lock++;
    pthread_mutex_unlock(&dns_cache_table.mutex);
    if (aio->extra) {
        aio_handle_done(aio);
    } else {
        LOG(LOG_DEBUG, "dns query %s wait\n", host);
    }
    if (query) {
        dns_client_connect(dns_client);
    }
}

void dns_cache_table_unquery(struct aio_t *aio)
{
    struct dns_cache_t *dns_cache = aio->extra;

    pthread_mutex_lock(&dns_cache_table.mutex);
    dns_cache->lock--;
    if (dns_cache->lock == 0 && dns_cache->del) {
        pthread_mutex_unlock(&dns_cache_table.mutex);
        LOG(LOG_DEBUG, "dns_cache=%s free\n", dns_cache->host);
        dns_cache_free(dns_cache);
    } else {
        pthread_mutex_unlock(&dns_cache_table.mutex);
    }
    aio->extra = NULL;
}
