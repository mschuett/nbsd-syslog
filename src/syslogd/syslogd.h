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
#ifndef _NO_NETBSD_USR_SRC_
#include <util.h>
#include "utmpentry.h"
#else
#include <libutil.h>
#include <utmp.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <limits.h>
#endif /* !_NO_NETBSD_USR_SRC_ */

#ifndef DISABLE_TLS
#include <netinet/tcp.h>
#include <sys/stdint.h>
#include <openssl/ssl.h>

#include <sys/resource.h>

/* 
 * question: should the buffer-code be encapsulated by #ifdefs?
 * --> decided against because the changes are rather extensive,
 *     especially in fprintlog()
 */

/* message buffer container used for queueing
 * 
 * many different fields because fprintlog
 * uses the different parts for formatting
 */
struct buf_msg {
        char        *timestamp;
        char        *host;
        char        *line;
        size_t       linelen;
        int          pri;
        int          flags;
        unsigned int refcount;
        char        *tlsline;
        size_t       tlslength;
};

/* queue of messages */
struct buf_queue {
        struct buf_msg* msg;
        TAILQ_ENTRY(buf_queue) entries;
};
TAILQ_HEAD(buf_queue_head, buf_queue);
#endif /* !DISABLE_TLS */


/* argumunt struct for tls_send() 
 * TODO: merge with simplified struct buf_msg
 */
struct tls_send_msg {
        struct filed   *f;
        struct buf_msg *buffer;
        char           *line; 
        size_t          linelen;
        unsigned int    offset;    /* in case of partial writes */
        unsigned int    refcount;
};

/* keeps track of UDP sockets and event objects */
struct socketEvent {
        int fd;
        struct event *ev;
};

#include "pathnames.h"
#include <sys/syslog.h>

#ifdef _NO_NETBSD_USR_SRC_
#undef _PATH_UNIX
#define _PATH_UNIX "kernel"
#endif /* _NO_NETBSD_USR_SRC_ */

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
#define D_MISC   256    /* everything else */
#define D_ALL    511
/* remove first printf for short debug messages */
#define DPRINTF(x, ...)    if (Debug & x) { \
                                printf("%s:%s:%.4d\t", make_timestamp(true), __FILE__, __LINE__); \
                                printf(__VA_ARGS__); }


#define EVENT_ADD(x) do { \
                        if (event_add(x, NULL) == -1) \
                                DPRINTF(D_TLS, "Failure in event_add()\n"); \
                        } while (0)


#define FREEPTR(x)      if (x)     { free(x);         x = NULL; }
#define FREE_SSL_CTX(x) if (x)     { SSL_CTX_free(x); x = NULL; }

#define MAXUNAMES       20      /* maximum number of user names */
#define TIMESTAMPLEN    15

/*
 * Flags to logmsg().
 */

#define IGN_CONS        0x001   /* don't print on console */
#define SYNC_FILE       0x002   /* do fsync on file after printing */
#define ADDDATE         0x004   /* add a date to the message */
#define MARK            0x008   /* this message is a mark */
#define ISKERNEL        0x010   /* kernel generated message */

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
        struct buf_queue_head f_qhead;          /* undelivered msgs queue */
        unsigned int f_qelements;               /* elements in queue */
        size_t  f_qsize;                        /* size of queue in bytes */
        char    f_prevline[MAXSVLINE];          /* last message logged */
        char    f_lasttime[16];                 /* time of last occurrence */
        char    f_prevhost[MAXHOSTNAMELEN];     /* host from which recd. */
        int     f_prevpri;                      /* pri of f_prevline */
        int     f_prevlen;                      /* length of f_prevline */
        int     f_prevcount;                    /* repetition cnt of prevline */
        int     f_repeatcount;                  /* number of "repeated" msgs */
        int     f_lasterror;                    /* last error on writev() */
        int     f_flags;                        /* file-specific flags */
#define FFLAG_SYNC      0x01
};

#ifndef DISABLE_TLS

/* linked list for allowed peer credentials
 * (one for fingerprint, one for cert-files)
 * 
 * Question: should I keep the certificates in memory so they do not
 * have to be read again or every incoming connection? 
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
        struct peer_cred_head cert_head;    /* trusted client cert files */
        char *keyfile;      /* file with private key */
        char *certfile;     /* file with own certificate */
        char *CAfile;       /* file with CA certificate */
        char *CAdir;        /* alternative: path to directory with CA certs */
        char *x509verify;   /* level of peer verification */
        char *bindhost;     /* hostname/IP to bind to */ 
        char *bindport;     /* port/service to bind to */
        char *client_only;  /* if !NULL: do not listen to incoming TLS */
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
        /* char inbuf[2*MAXLINE]; */
        char *inbuf;                    /* input buffer */
        size_t inbuflen;
        SLIST_ENTRY(TLS_Incoming_Conn) entries;
        struct tls_conn_settings *tls_conn;
        SSL *ssl;
        int socket;
        unsigned int cur_msg_len;       /* length of current msg */
        unsigned int cur_msg_start;     /* beginning of current msg */
        unsigned int read_pos;          /* ring buffer position to write to */
        unsigned int errorcount;        /* to close faulty connections */
        bool closenow;                  /* close connection as soon as buffer processed */
        bool dontsave;                  /* for receiving oversized messages w/o saving them */
};

#endif /* !DISABLE_TLS */

#endif /*SYSLOGD_H_*/
