#ifndef SYSLOGD_H_
#define SYSLOGD_H_
/*
 * hold common data structures and prototypes 
 * for syslogd.c and tls_stuff.c
 * 
 */
 
#include <sys/cdefs.h>
#define MAXLINE         1024            /* maximum line length */
#define MAXSVLINE       120             /* maximum saved line length */
#define DEFUPRI         (LOG_USER|LOG_NOTICE)
#define DEFSPRI         (LOG_KERN|LOG_NOTICE)
#define TIMERINTVL      30              /* interval for checking flush, mark */
#define TTYMSGTIME      1               /* timeout passed to ttymsg */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <sys/event.h>
#include <event.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <locale.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <utmp.h>
#ifdef __NetBSD_Version__
#include <util.h>
#include "utmpentry.h"
#endif /* __NetBSD_Version__ */
#ifdef __FreeBSD_version
#include <libutil.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <limits.h>
#endif /* __FreeBSD_version */

#ifndef DISABLE_TLS
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#endif /* !DISABLE_TLS */

#include <sys/stdint.h>
#include <sys/resource.h>

/* message buffer container used for processing, formatting, and queueing */
struct buf_msg {
        unsigned int refcount;
        int          pri;
        int          flags;
        char        *timestamp;
        char        *recvhost;
        char        *host;
        char        *prog;
        char        *pid;
        char        *msgid;
        char        *sd;        /* structured data */
        char        *msg;       /* message content */
        char        *msgorig;   /* in case we advance *msg beyond header fields
                                   we still want to free() the original ptr  */
        size_t       msglen;    /* strlen(msg) */
        size_t       msgsize;   /* allocated memory size   */
        unsigned int tlsprefixlen; /* bytes for the TLS length prefix */
        unsigned int prilen;       /* bytes for priority and version  */
};

/* queue of messages */
struct buf_queue {
        struct buf_msg* msg;
        TAILQ_ENTRY(buf_queue) entries;
};
TAILQ_HEAD(buf_queue_head, buf_queue);

/* keeps track of UDP sockets and event objects */
struct socketEvent {
        int fd;
        struct event *ev;
};

#include "pathnames.h"
#include <sys/syslog.h>

/* some differences between the BSDs  */
#ifdef __FreeBSD_version
#undef _PATH_UNIX
#define _PATH_UNIX "kernel"
#define HAVE_STRNDUP 0
#endif /* __FreeBSD_version */

#ifdef __NetBSD_version
#define HAVE_STRNDUP 1
#endif /* __NetBSD_version */

#ifndef HAVE_DEHUMANIZE_NUMBER  /* not in my 4.0-STABLE yet */
extern int dehumanize_number(const char *str, int64_t *size);
#endif /* !HAVE_DEHUMANIZE_NUMBER */

#if !HAVE_STRNDUP
char *strndup(const char *str, size_t n);
#endif /* !HAVE_STRNDUP */

#ifdef LIBWRAP
#include <tcpd.h>
#endif

#define FDMASK(fd)      (1 << (fd))

/* debug messages with categories */
#define D_NONE     0
#define D_CALL     1    /* function calls */
#define D_DATA     2    /* syslog message reading/formatting */
#define D_NET      4    /* sockets/network */
#define D_FILE     8    /* local files */
#define D_TLS     16    /* TLS */
#define D_PARSE   32    /* configuration/parsing */
#define D_EVENT   64    /* libevent */
#define D_BUFFER 128    /* message queues */
#define D_MEM    256    /* malloc/free */
#define D_MEM2  1024    /* every single malloc/free */
#define D_SIGN  2048    /* -sign */
#define D_MISC  4096    /* everything else */
#define D_ALL   (D_CALL | D_DATA | D_NET | D_FILE | D_TLS | D_EVENT | D_BUFFER | D_SIGN | D_MISC) 

/* remove first printf for short debug messages */
#define DPRINTF(x, ...) ((Debug & x) \
                         ? (printf("%s:%s:%.4d\t", make_timestamp(NULL, true), \
                                __FILE__, __LINE__), printf(__VA_ARGS__)) \
                         : 0)

/* shortcuts for libevent */
#define EVENT_ADD(x) do { \
                        if (event_add(x, NULL) == -1) \
                                DPRINTF(D_TLS, "Failure in event_add()\n"); \
                        } while (0)
#define RETRYEVENT_ADD(x) do { \
                        if (event_add(x, &((struct timeval){0, TLS_RETRY_EVENT_USEC})) == -1) \
                                DPRINTF(D_TLS, "Failure in event_add()\n"); \
                        } while (0)

#define FREEPTR(x)      if (x)     { DPRINTF(D_MEM2, "free(%s@%p)\n", #x, x); \
                                     free(x);         x = NULL; }
#define FREE_SSL(x)     if (x)     { SSL_free(x);     x = NULL; }
#define FREE_SSL_CTX(x) if (x)     { SSL_CTX_free(x); x = NULL; }

/* generic for all structs with refcount */ 
#define NEWREF(x) ((x) ? (DPRINTF(D_BUFFER, "inc refcount of " #x \
                        " @ %p: %d --> %d\n", (x), (x)->refcount, \
                        (x)->refcount + 1), (x)->refcount++, (x))\
                       : (DPRINTF(D_BUFFER, "inc refcount of NULL!\n"), NULL))
/* only for struct msg_buf() because of buf_msg_free(x) */
#define DELREF(x) ((x) ? (DPRINTF(D_BUFFER, "dec refcount of " #x \
                        " @ %p: %d --> %d\n", (x), (x)->refcount, \
                        (x)->refcount - 1), buf_msg_free(x), NULL) \
                       : (DPRINTF(D_BUFFER, "dec refcount of NULL!\n"), NULL) )

/* assumption: once init() has set up all global variables etc.
 * the bulk of available memory is used for buffer and can be freed
 * if necessary */
#define MALLOC(ptr, size) while(!(ptr = malloc(size))) { \
                                struct filed *f; \
                                DPRINTF(D_MEM, "Unable to allocate memory"); \
                                for (f = Files; f; f = f->f_next) \
                                        message_queue_purge(f, \
                                                f->f_qelements/10, \
                                                PURGE_BY_PRIORITY); \
                          }
#define CALLOC(ptr, size) while(!(ptr = calloc(1, size))) { \
                                struct filed *f; \
                                DPRINTF(D_MEM, "Unable to allocate memory"); \
                                for (f = Files; f; f = f->f_next) \
                                        message_queue_purge(f, \
                                                f->f_qelements/10, \
                                                PURGE_BY_PRIORITY); \
                          }

/* strlen(NULL) does not work? */
#define SAFEstrlen(x) ((x) ? strlen(x) : 0)

#define MAXUNAMES       20      /* maximum number of user names */
#define BSD_TIMESTAMPLEN    14+1
#define MAX_TIMESTAMPLEN    31+1

/* maximum field lengths in syslog-protocol */
#define HOST_MAX    255
#define APPNAME_MAX  48
#define PROCID_MAX  128
#define MSGID_MAX    32

/*
 * Flags to logmsg().
 */

#define IGN_CONS        0x001   /* don't print on console */
#define SYNC_FILE       0x002   /* do fsync on file after printing */
#define ADDDATE         0x004   /* add a date to the message */
#define MARK            0x008   /* this message is a mark */
#define ISKERNEL        0x010   /* kernel generated message */
#define BSDSYSLOG       0x020   /* line in traditional BSD Syslog format */
#define SIGNATURE       0x040   /* syslog-sign data, not signed again */

/* strategies for message_queue_purge() */
#define PURGE_OLDEST            1
#define PURGE_BY_PRIORITY       2

/*
 * This structure represents the files that will have log
 * copies printed.
 * We require f_file to be valid if f_type is F_FILE, F_CONSOLE, F_TTY,
 * or if f_type is F_PIPE and f_pid > 0.
 */

struct filed {
        struct  filed *f_next;          /* next in linked list */
        short   f_type;                 /* entry type, see below */
        short   f_file;                 /* file descriptor */
        time_t  f_time;                 /* time this was last written */
        char    *f_host;                /* host from which to record */
        u_char  f_pmask[LOG_NFACILITIES+1];     /* priority mask */
        u_char  f_pcmp[LOG_NFACILITIES+1];      /* compare priority */
#define PRI_LT  0x1
#define PRI_EQ  0x2
#define PRI_GT  0x4
        char    *f_program;             /* program this applies to */
        union {
                char    f_uname[MAXUNAMES][UT_NAMESIZE+1];
                struct {
                        char    f_hname[MAXHOSTNAMELEN];
                        struct  addrinfo *f_addr;
                } f_forw;               /* UDP forwarding address */
#ifndef DISABLE_TLS
                struct {
                        SSL     *ssl;                   /* SSL object  */
                        struct tls_conn_settings *tls_conn;  /* certificate info */ 
                } f_tls;                /* TLS forwarding address */
#endif /* !DISABLE_TLS */
                char    f_fname[MAXPATHLEN];
                struct {
                        char    f_pname[MAXPATHLEN];
                        pid_t   f_pid;
                } f_pipe;
        } f_un;
#ifndef DISABLE_SIGN
        struct signature_group_t *f_sg;      /* one signature group */
#endif /* !DISABLE_SIGN */
        struct buf_queue_head f_qhead;       /* undelivered msgs queue */
        unsigned int          f_qelements;   /* elements in queue */
        size_t                f_qsize;       /* size of queue in bytes */
        struct buf_msg       *f_prevmsg;     /* last message logged */
        int                   f_prevcount;   /* repetition cnt of prevmsg */
        int                   f_repeatcount; /* number of "repeated" msgs */
        int                   f_lasterror;   /* last error on writev() */
        int                   f_flags;       /* file-specific flags */
#define FFLAG_SYNC      0x01
#define FFLAG_SIGN      0x02
};

#ifndef DISABLE_TLS

/* linked list for allowed peer credentials
 * (one for fingerprint, one for cert-files)
 */
SLIST_HEAD(peer_cred_head, peer_cred);
struct peer_cred {
        SLIST_ENTRY(peer_cred) entries;
        char *data;
};

/* config options for TLS server-side */
struct tls_global_options_t {
        SSL_CTX *global_TLS_CTX;
        struct peer_cred_head fprint_head;  /* trusted client fingerprints */
        struct peer_cred_head cert_head;    /* trusted client cert files   */
        char *keyfile;      /* file with private key     */
        char *certfile;     /* file with own certificate */
        char *CAfile;       /* file with CA certificate  */
        char *CAdir;        /* alternative: path to directory with CA certs */
        char *x509verify;   /* level of peer verification */
        char *bindhost;     /* hostname/IP to bind to     */ 
        char *bindport;     /* port/service to bind to    */
        char *server;       /* if !NULL: do not listen to incoming TLS    */
        char *gen_cert;     /* if !NULL: generate self-signed certificate */
        char *reconnect_giveup_str;
        char *reconnect_interval_str;
        int64_t reconnect_giveup;    /* in seconds or 0 for none */
        int64_t reconnect_interval;  /* in seconds */
};

/* TLS needs three sets of sockets:
 * - listening sockets: a fixed size array TLS_Listen_Set, just like finet for UDP.
 * - outgoing connections: managed as part of struct filed.
 * - incoming connections: variable sized, thus a linked list TLS_Incoming.
 */
/* every connection has its own input buffer with status
 * variables for message reading */
SLIST_HEAD(TLS_Incoming, TLS_Incoming_Conn);
 
struct TLS_Incoming_Conn {
        SLIST_ENTRY(TLS_Incoming_Conn) entries;
        struct tls_conn_settings *tls_conn;
        int socket;
        char *inbuf;                    /* input buffer */
        size_t inbuflen;
        unsigned int cur_msg_len;       /* length of current msg */
        unsigned int cur_msg_start;     /* beginning of current msg */
        unsigned int read_pos;          /* ring buffer position to write to */
        unsigned int errorcount;        /* to close faulty connections */
        bool closenow;                  /* close connection as soon as buffer processed */
        bool dontsave;                  /* for receiving oversized messages w/o saving them */
};

#endif /* !DISABLE_TLS */

#endif /*SYSLOGD_H_*/
