/*      $NetBSD: syslogd.c,v 1.84 2006/11/13 20:24:00 christos Exp $    */

/*
 * Copyright (c) 1983, 1988, 1993, 1994
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#ifndef lint
__COPYRIGHT("@(#) Copyright (c) 1983, 1988, 1993, 1994\n\
        The Regents of the University of California.  All rights reserved.\n");
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)syslogd.c   8.3 (Berkeley) 4/4/94";
#else
__RCSID("$NetBSD: syslogd.c,v 1.84 2006/11/13 20:24:00 christos Exp $");
#endif
#endif /* not lint */

/*
 *  syslogd -- log system messages
 *
 * This program implements a system log. It takes a series of lines.
 * Each line may have a priority, signified as "<n>" as
 * the first characters of the line.  If this is
 * not present, a default priority is used.
 *
 * To kill syslogd, send a signal 15 (terminate).  A signal 1 (hup) will
 * cause it to reread its configuration file.
 *
 * Defined Constants:
 *
 * MAXLINE -- the maximimum line length that can be handled.
 * DEFUPRI -- the default priority for user messages
 * DEFSPRI -- the default priority for kernel messages
 *
 * Author: Eric Allman
 * extensive changes by Ralph Campbell
 * more extensive changes by Eric Allman (again)
 * Extension to log by program name as well as facility and priority
 *   by Peter da Silva.
 * -U and -v by Harlan Stenn.
 * Priority comparison code by Harlan Stenn.
 */

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
#include <sys/event.h>
#include <netinet/in.h>

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
#include "tls_stuff.h"
#endif /* !DISABLE_TLS */

#include "pathnames.h"

#define SYSLOG_NAMES
#include <sys/syslog.h>

#ifdef LIBWRAP
#include <tcpd.h>

int allow_severity = LOG_AUTH|LOG_INFO;
int deny_severity = LOG_AUTH|LOG_WARNING;
#endif

char    *ConfFile = _PATH_LOGCONF;
char    ctty[] = _PATH_CONSOLE;

#define FDMASK(fd)      (1 << (fd))

#define dprintf         if (Debug) printf

#define MAXUNAMES       20      /* maximum number of user names */

/*
 * Flags to logmsg().
 */

#define IGN_CONS        0x001   /* don't print on console */
#define SYNC_FILE       0x002   /* do fsync on file after printing */
#define ADDDATE         0x004   /* add a date to the message */
#define MARK            0x008   /* this message is a mark */
#define ISKERNEL        0x010   /* kernel generated message */

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

/*
 * Queue of about-to-be-dead processes we should watch out for.
 */
TAILQ_HEAD(, deadq_entry) deadq_head = TAILQ_HEAD_INITIALIZER(deadq_head);

typedef struct deadq_entry {
        pid_t                           dq_pid;
        int                             dq_timeout;
        TAILQ_ENTRY(deadq_entry)        dq_entries;
} *dq_t;

/*
 * The timeout to apply to processes waiting on the dead queue.  Unit
 * of measure is "mark intervals", i.e. 20 minutes by default.
 * Processes on the dead queue will be terminated after that time.
 */
#define DQ_TIMO_INIT    2

/*
 * Intervals at which we flush out "message repeated" messages,
 * in seconds after previous message is logged.  After each flush,
 * we move to the next interval until we reach the largest.
 */
int     repeatinterval[] = { 30, 120, 600 };    /* # of secs before flush */
#define MAXREPEAT ((sizeof(repeatinterval) / sizeof(repeatinterval[0])) - 1)
#define REPEATTIME(f)   ((f)->f_time + repeatinterval[(f)->f_repeatcount])
#define BACKOFF(f)      { if (++(f)->f_repeatcount > MAXREPEAT) \
                                 (f)->f_repeatcount = MAXREPEAT; \
                        }

/* values for f_type */
#define F_UNUSED        0               /* unused entry */
#define F_FILE          1               /* regular file */
#define F_TTY           2               /* terminal */
#define F_CONSOLE       3               /* console terminal */
#define F_FORW          4               /* remote machine */
#define F_USERS         5               /* list of users */
#define F_WALL          6               /* everyone logged on */
#define F_PIPE          7               /* pipe to program */
/* FIXME: should this also be wrapped in an #ifndef DISABLE_TLS ?
 * it does not result in additionally compiled code  */
#define F_TLS       8 

char    *TypeNames[9] = {
        "UNUSED",       "FILE",         "TTY",          "CONSOLE",
        "FORW",         "USERS",        "WALL",         "PIPE",
        "TLS"
};

struct  filed *Files;
struct  filed consfile;

int     Debug;                  /* debug flag */
int     daemonized = 0;         /* we are not daemonized yet */
char    LocalHostName[MAXHOSTNAMELEN];  /* our hostname */
char    oldLocalHostName[MAXHOSTNAMELEN];/* previous hostname */
char    *LocalDomain;           /* our local domain name */
size_t  LocalDomainLen;         /* length of LocalDomain */
int     *finet = NULL;          /* Internet datagram sockets */
int     Initialized;            /* set when we have initialized ourselves */
int     ShuttingDown;           /* set when we die() */
int     MarkInterval = 20 * 60; /* interval between marks in seconds */
int     MarkSeq = 0;            /* mark sequence number */
int     SecureMode = 0;         /* listen only on unix domain socks */
int     UseNameService = 1;     /* make domain name queries */
int     NumForwards = 0;        /* number of forwarding actions in conf file */
char    **LogPaths;             /* array of pathnames to read messages from */
int     NoRepeat = 0;           /* disable "repeated"; log always */
int     RemoteAddDate = 0;      /* always add date to messages from network */
int     SyncKernel = 0;         /* write kernel messages synchronously */
int     UniquePriority = 0;     /* only log specified priority */
int     LogFacPri = 0;          /* put facility and priority in log messages: */
                                /* 0=no, 1=numeric, 2=names */
void    cfline(char *, struct filed *, char *, char *);
char   *cvthname(struct sockaddr_storage *);
void    deadq_enter(pid_t, const char *);
int     deadq_remove(pid_t);
int     decode(const char *, CODE *);
void    die(struct kevent *);   /* SIGTERM kevent dispatch routine */
void    domark(struct kevent *);/* timer kevent dispatch routine */
void    fprintlog(struct filed *, int, char *);
int     getmsgbufsize(void);
int*    socksetup(int, const char *);
void    init(struct kevent *);  /* SIGHUP kevent dispatch routine */
void    logerror(const char *, ...);
void    logmsg(int, char *, char *, int);
void    log_deadchild(pid_t, int, const char *);
int     matches_spec(const char *, const char *,
                     char *(*)(const char *, const char *));
void    printline(char *, char *, int);
void    printsys(char *);
int     p_open(char *, pid_t *);
void    trim_localdomain(char *);
void    reapchild(struct kevent *); /* SIGCHLD kevent dispatch routine */
void    usage(void);
void    wallmsg(struct filed *, struct iovec *, size_t);
int     main(int, char *[]);
void    logpath_add(char ***, int *, int *, char *);
void    logpath_fileadd(char ***, int *, int *, char *);

static int fkq;

struct kevent *allocevchange(void);
static int wait_for_events(struct kevent *, size_t);

static void dispatch_read_klog(struct kevent *);
static void dispatch_read_finet(struct kevent *);
static void dispatch_read_funix(struct kevent *);

/*
 * Global line buffer.  Since we only process one event at a time,
 * a global one will do.
 */
static char *linebuf;
static size_t linebufsize;
static const char *bindhostname = NULL;

#define A_CNT(x)        (sizeof((x)) / sizeof((x)[0]))

#ifndef DISABLE_TLS
/* TLS needs three sets of sockets:
 * - listening sockets: a fixed size array TLS_Listen_Set, just like finet for UDP.
 * - outgoing connections: managed as part of struct filed.
 * - incoming connections: variable sized, thus a linked list TLS_Incoming.
 */
int *TLS_Listen_Set;

SLIST_HEAD(TLS_Incoming, TLS_Incoming_Conn) TLS_Incoming_Head
        = SLIST_HEAD_INITIALIZER(TLS_Incoming_Head);

/* every connection has its own input buffer with status
 * variables for message reading */
struct TLS_Incoming_Conn {
        char inbuf[2*MAXLINE];           /* input buffer */
        SLIST_ENTRY(TLS_Incoming_Conn) entries;
        struct tls_conn_settings *tls_conn;
        SSL *ssl;
        int socket;
        uint_fast16_t cur_msg_len;       /* length of current msg */
        uint_fast16_t cur_msg_start;     /* beginning of current msg */
        uint_fast16_t read_pos;          /* ring buffer position to write to */
        uint_fast8_t errorcount;         /* to close faulty connections */
        bool closenow;                   /* close connection as soon as buffer processed */
};

/* buffersize to process file length prefixes in TLS messages */
#define PREFIXLENGTH 10
extern char *SSL_ERRCODE[];
SSL_CTX *global_TLS_CTX;
bool TLSClientOnly = 0;

/* forward declarations */
bool copy_config_value(char **mem, char *p, char *q);
bool copy_config_value_quoted(char *keyword, char **mem, char **p, char **q);
bool parse_tls_destination(char *line, struct filed *f);
void tls_split_messages(struct TLS_Incoming_Conn *c);

void dispatch_accept_tls(struct kevent *ev);
void dispatch_read_tls(struct kevent *ev);
void tls_reconnect(struct filed *f);

void tls_reconnect(struct filed *f) { /* TODO */ return; };

/* auxillary code to allocate memory and copy a string */
bool
copy_config_value(/*@out@*/ char **mem, char *p, char *q)
{
        if (!(*mem = malloc(1 + q - p))) {
                printf("Couldn't allocate memory for TLS config\n");
                return false;
        }
        strncpy(*mem, p, q - p);
        (*mem)[q - p] = '\0';
        return true;
}

bool
copy_config_value_quoted(char *keyword, char **mem, /*@null@*/char **p, /*@null@*/char **q)
{
        if (strncmp(*p, keyword, strlen(keyword)))
                return false;
        *q = *p += strlen(keyword);
        if (!(*q = strchr(*p, '"'))) {
                printf("unterminated \"\n");
                return false;
        }
        if (!(copy_config_value(mem, *p, *q)))
                return false;
        *p = ++(*q);
        return true;
}

bool
parse_tls_destination(char *line, struct filed *f)
{
        char *p, *q;
        
        p = line;
        if ((*p++ != '@') || *p++ != '[') {
                logerror("parse_tls_destination() on non-TLS action\n");
                return false; 
        }
        
        if (!(q = strchr(p, ']'))) {
                logerror("Unterminated [ in configuration\n");
                return false;
        }

        if (!(f->f_un.f_tls.tls_conn = malloc(sizeof(struct tls_conn_settings)))) {
                logerror("Couldn't allocate memory for TLS config\n");
                return false;
        }
        /* default values */
        bzero(f->f_un.f_tls.tls_conn, sizeof(struct tls_conn_settings));
        f->f_un.f_tls.tls_conn->x509verify = X509VERIFY_NONE;
        
        if (!(copy_config_value(&(f->f_un.f_tls.tls_conn->hostname), p, q)))
                return false;
        p = ++q;
        
        if (*p == ':') {
                p++; q++;
                while (isalnum((unsigned char)*q))
                        q++;
                if (!(copy_config_value(&(f->f_un.f_tls.tls_conn->port), p, q)))
                        return false;
                p = q;
        }
        /* allow whitespace for readability? */
        while (isblank(*p))
                p++;
        if (*p == '(') {
                p++;
                while (*p != ')') {
                        if (copy_config_value_quoted("subject=\"", &(f->f_un.f_tls.tls_conn->subject), &p, &q)
                            || copy_config_value_quoted("fingerprint=\"", &(f->f_un.f_tls.tls_conn->fingerprint), &p, &q)
                            || copy_config_value_quoted("cert=\"", &(f->f_un.f_tls.tls_conn->certfile), &p, &q)) {
                        /* nothing */
                        }
                        else if (!strncmp(p, "verify=", strlen("verify="))) {
                                q = p += strlen("verify=");
                                if (*p == '\"') { p++; q++; }  /* "" are optional */
                                while (isalpha((unsigned char)*q)) q++;
                                if ((q-p > 1) && !strncasecmp("off", p, q-p))
                                        f->f_un.f_tls.tls_conn->x509verify = X509VERIFY_NONE;
                                else if ((q-p > 1) && !strncasecmp("opt", p, q-p))
                                        f->f_un.f_tls.tls_conn->x509verify = X509VERIFY_IFPRESENT;
                                else if ((q-p > 1) && !strncasecmp("on", p, q-p))
                                        f->f_un.f_tls.tls_conn->x509verify = X509VERIFY_ALWAYS;
                                else {
                                        logerror("unknown verify value %.*s\n", q-p, p);
                                }
                                if (*q == '\"') q++;  /* "" are optional */
                                p = q;
                        }
                        else {
                                logerror("unknown keyword %s \n", p);
                                return false;        
                        }
                        while (*p == ',' || isblank(*p))
                                p++;
                        if (*p == '\0') {
                                logerror("unterminated (\n");
                                return false;
                        }
                }
        }
        dprintf("got TLS config: host %s, port %s, subject: %s\n",
                f->f_un.f_tls.tls_conn->hostname,
                f->f_un.f_tls.tls_conn->port,
                f->f_un.f_tls.tls_conn->subject);
        return true;
}

#endif /* !DISABLE_TLS */


int
main(int argc, char *argv[])
{
        int ch, *funix, j, fklog;
        int funixsize = 0, funixmaxsize = 0;
        struct kevent events[16];
        struct sockaddr_un sunx;
        char **pp;
        struct kevent *ev;
        uid_t uid = 0;
        gid_t gid = 0;
        char *user = NULL;
        char *group = NULL;
        char *root = "/";
        char *endp;
        struct group   *gr;
        struct passwd  *pw;
        unsigned long l;

        (void)setlocale(LC_ALL, "");

        /* TODO: introduce TLS related options if needed */
        while ((ch = getopt(argc, argv, "b:dnsSf:m:p:P:ru:g:t:TUv")) != -1)
                switch(ch) {
                case 'b':
                        bindhostname = optarg;
                        break;
                case 'd':               /* debug */
                        Debug++;
                        break;
                case 'f':               /* configuration file */
                        ConfFile = optarg;
                        break;
                case 'g':
                        group = optarg;
                        if (*group == '\0')
                                usage();
                        break;
                case 'm':               /* mark interval */
                        MarkInterval = atoi(optarg) * 60;
                        break;
                case 'n':               /* turn off DNS queries */
                        UseNameService = 0;
                        break;
                case 'p':               /* path */
                        logpath_add(&LogPaths, &funixsize, 
                            &funixmaxsize, optarg);
                        break;
                case 'P':               /* file of paths */
                        logpath_fileadd(&LogPaths, &funixsize, 
                            &funixmaxsize, optarg);
                        break;
                case 'r':               /* disable "repeated" compression */
                        NoRepeat++;
                        break;
                case 's':               /* no network listen mode */
                        SecureMode++;
                        break;
                case 'S':
                        SyncKernel = 1;
                        break;
                case 't':
                        root = optarg;
                        if (*root == '\0')
                                usage();
                        break;
                case 'T':
                        RemoteAddDate = 1;
                        break;
                case 'u':
                        user = optarg;
                        if (*user == '\0')
                                usage();
                        break;
                case 'U':               /* only log specified priority */
                        UniquePriority = 1;
                        break;
                case 'v':               /* log facility and priority */
                        if (LogFacPri < 2)
                                LogFacPri++;
                        break;
                default:
                        usage();
                }
        if ((argc -= optind) != 0)
                usage();

        setlinebuf(stdout);

        if (user != NULL) {
                if (isdigit((unsigned char)*user)) {
                        errno = 0;
                        endp = NULL;
                        l = strtoul(user, &endp, 0);
                        if (errno || *endp != '\0')
                                goto getuser;
                        uid = (uid_t)l;
                        if (uid != l) {
                                errno = 0;
                                logerror("UID out of range");
                                die(NULL);
                        }
                } else {
getuser:
                        if ((pw = getpwnam(user)) != NULL) {
                                uid = pw->pw_uid;
                        } else {
                                errno = 0;  
                                logerror("Cannot find user `%s'", user);
                                die(NULL);
                        }
                }
        }

        if (group != NULL) {
                if (isdigit((unsigned char)*group)) {
                        errno = 0;
                        endp = NULL;
                        l = strtoul(group, &endp, 0);
                        if (errno || *endp != '\0')
                                goto getgroup;
                        gid = (gid_t)l;
                        if (gid != l) {
                                errno = 0;
                                logerror("GID out of range");
                                die(NULL);
                        }
                } else {
getgroup:
                        if ((gr = getgrnam(group)) != NULL) {
                                gid = gr->gr_gid;
                        } else {
                                errno = 0;
                                logerror("Cannot find group `%s'", group);
                                die(NULL);
                        }
                }
        }

        if (access(root, F_OK | R_OK)) {
                logerror("Cannot access `%s'", root);
                die(NULL);
        }

        consfile.f_type = F_CONSOLE;
        (void)strlcpy(consfile.f_un.f_fname, ctty,
            sizeof(consfile.f_un.f_fname));
        linebufsize = getmsgbufsize();
        if (linebufsize < MAXLINE)
                linebufsize = MAXLINE;
        linebufsize++;
        linebuf = malloc(linebufsize);
        if (linebuf == NULL) {
                logerror("Couldn't allocate line buffer");
                die(NULL);
        }

#ifndef SUN_LEN
#define SUN_LEN(unp) (strlen((unp)->sun_path) + 2)
#endif
        if (funixsize == 0)
                logpath_add(&LogPaths, &funixsize, 
                    &funixmaxsize, _PATH_LOG);
        funix = (int *)malloc(sizeof(int) * funixsize);
        if (funix == NULL) {
                logerror("Couldn't allocate funix descriptors");
                die(NULL);
        }
        for (j = 0, pp = LogPaths; *pp; pp++, j++) {
                dprintf("Making unix dgram socket `%s'\n", *pp);
                unlink(*pp);
                memset(&sunx, 0, sizeof(sunx));
                sunx.sun_family = AF_LOCAL;
                (void)strncpy(sunx.sun_path, *pp, sizeof(sunx.sun_path));
                funix[j] = socket(AF_LOCAL, SOCK_DGRAM, 0);
                if (funix[j] < 0 || bind(funix[j],
                    (struct sockaddr *)&sunx, SUN_LEN(&sunx)) < 0 ||
                    chmod(*pp, 0666) < 0) {
                        logerror("Cannot create `%s'", *pp);
                        die(NULL);
                }
                dprintf("Listening on unix dgram socket `%s'\n", *pp);
        }

        if ((fklog = open(_PATH_KLOG, O_RDONLY, 0)) < 0) {
                dprintf("Can't open `%s' (%d)\n", _PATH_KLOG, errno);
        } else {
                dprintf("Listening on kernel log `%s'\n", _PATH_KLOG);
        }

#ifndef DISABLE_TLS
        /* OpenSSL PRNG needs /dev/urandom, thus initialize before chroot() */
        if (!RAND_status())
                logerror("Unable to initialize OpenSSL PRNG\n");
        else {
                dprintf("Initializing PRNG\n");
        }
        SLIST_INIT(&TLS_Incoming_Head);
#endif /* !DISABLE_TLS */
        /* 
         * All files are open, we can drop privileges and chroot
         */
        dprintf("Attempt to chroot to `%s'\n", root);  
        if (chroot(root)) {
                logerror("Failed to chroot to `%s'", root);
                die(NULL);
        }
        dprintf("Attempt to set GID/EGID to `%d'\n", gid);  
        if (setgid(gid) || setegid(gid)) {
                logerror("Failed to set gid to `%d'", gid);
                die(NULL);
        }
        dprintf("Attempt to set UID/EUID to `%d'\n", uid);  
        if (setuid(uid) || seteuid(uid)) {
                logerror("Failed to set uid to `%d'", uid);
                die(NULL);
        }

        /* 
         * We cannot detach from the terminal before we are sure we won't 
         * have a fatal error, because error message would not go to the
         * terminal and would not be logged because syslogd dies. 
         * All die() calls are behind us, we can call daemon()
         */
        if (!Debug) {
                (void)daemon(0, 0);
                daemonized = 1;
                /* tuck my process id away, if i'm not in debug mode */
#ifndef _NO_NETBSD_USR_SRC_
                pidfile(NULL);
#endif /* !_NO_NETBSD_USR_SRC_ */
        }

        /*
         * Create the global kernel event descriptor.
         *
         * NOTE: We MUST do this after daemon(), bacause the kqueue()
         * API dictates that kqueue descriptors are not inherited
         * across forks (lame!).
         */
        if ((fkq = kqueue()) < 0) {
                logerror("Cannot create event queue");
                die(NULL);      /* XXX This error is lost! */
        }

        /*
         * We must read the configuration file for the first time
         * after the kqueue descriptor is created, because we install
         * events during this process.
         */
        init(NULL);

        /*
         * Always exit on SIGTERM.  Also exit on SIGINT and SIGQUIT
         * if we're debugging.
         */
        (void)signal(SIGTERM, SIG_IGN);
        (void)signal(SIGINT, SIG_IGN);
        (void)signal(SIGQUIT, SIG_IGN);
        ev = allocevchange();
        EV_SET(ev, SIGTERM, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0,
            KEVENT_UDATA_CAST die);
        if (Debug) {
                ev = allocevchange();
                EV_SET(ev, SIGINT, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0,
                    KEVENT_UDATA_CAST die);

                ev = allocevchange();
                EV_SET(ev, SIGQUIT, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0,
                    KEVENT_UDATA_CAST die);
        }

        ev = allocevchange();
        EV_SET(ev, SIGCHLD, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0,
            KEVENT_UDATA_CAST reapchild);

        ev = allocevchange();
        EV_SET(ev, 0, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0,
            TIMERINTVL * 1000 /* seconds -> ms */, KEVENT_UDATA_CAST domark);

        (void)signal(SIGPIPE, SIG_IGN); /* We'll catch EPIPE instead. */

        /* Re-read configuration on SIGHUP. */
        (void) signal(SIGHUP, SIG_IGN);
        ev = allocevchange();
        EV_SET(ev, SIGHUP, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0,
            KEVENT_UDATA_CAST init);

        if (fklog >= 0) {
                ev = allocevchange();
                EV_SET(ev, fklog, EVFILT_READ, EV_ADD | EV_ENABLE,
                    0, 0, KEVENT_UDATA_CAST dispatch_read_klog);
        }
        for (j = 0, pp = LogPaths; *pp; pp++, j++) {
                ev = allocevchange();
                EV_SET(ev, funix[j], EVFILT_READ, EV_ADD | EV_ENABLE,
                    0, 0, KEVENT_UDATA_CAST dispatch_read_funix);
        }

        dprintf("Off & running....\n");

        for (;;) {
                void (*handler)(struct kevent *);
                int i, rv;

                rv = wait_for_events(events, A_CNT(events));
                if (rv == 0)
                        continue;
                if (rv < 0) {
                        if (errno != EINTR)
                                logerror("kevent() failed");
                        continue;
                }
                dprintf("Got an event (%d)\n", rv);
                for (i = 0; i < rv; i++) {
                        handler = (void *) events[i].udata;
                        (*handler)(&events[i]);
                }
        }
}

void
usage(void)
{

        (void)fprintf(stderr,
            "usage: %s [-dnrSsTUv] [-b bind_address] [-f config_file] [-g group]\n"
            "\t[-m mark_interval] [-P file_list] [-p log_socket\n"
            "\t[-p log_socket2 ...]] [-t chroot_dir] [-u user]\n",
            getprogname());
        exit(1);
}

/*
 * Dispatch routine for reading /dev/klog
 */
static void
dispatch_read_klog(struct kevent *ev)
{
        ssize_t rv;
        int fd = ev->ident;

        dprintf("Kernel log active\n");

        rv = read(fd, linebuf, linebufsize - 1);
        if (rv > 0) {
                linebuf[rv] = '\0';
                printsys(linebuf);
        } else if (rv < 0 && errno != EINTR) {
                /*
                 * /dev/klog has croaked.  Disable the event
                 * so it won't bother us again.
                 */
                struct kevent *cev = allocevchange();
                logerror("klog failed");
                EV_SET(cev, fd, EVFILT_READ, EV_DISABLE,
                    0, 0, KEVENT_UDATA_CAST dispatch_read_klog);
        }
}

/*
 * Dispatch routine for reading Unix domain sockets.
 */
static void
dispatch_read_funix(struct kevent *ev)
{
        struct sockaddr_un myname, fromunix;
        ssize_t rv;
        socklen_t sunlen;
        int fd = ev->ident;

        sunlen = sizeof(myname);
        if (getsockname(fd, (struct sockaddr *)&myname, &sunlen) != 0) {
                /*
                 * This should never happen, so ensure that it doesn't
                 * happen again.
                 */
                struct kevent *cev = allocevchange();
                logerror("getsockname() unix failed");
                EV_SET(cev, fd, EVFILT_READ, EV_DISABLE,
                    0, 0, KEVENT_UDATA_CAST dispatch_read_funix);
                return;
        }

        dprintf("Unix socket (%.*s) active\n", (myname.sun_len-sizeof(myname.sun_len)-sizeof(myname.sun_family)), myname.sun_path);

        sunlen = sizeof(fromunix);
        rv = recvfrom(fd, linebuf, MAXLINE, 0,
            (struct sockaddr *)&fromunix, &sunlen);
        if (rv > 0) {
                linebuf[rv] = '\0';
                printline(LocalHostName, linebuf, 0);
        } else if (rv < 0 && errno != EINTR) {
                logerror("recvfrom() unix `%.*s'", myname.sun_len, myname.sun_path);
        }
}

/*
 * Dispatch routine for reading Internet sockets.
 */
static void
dispatch_read_finet(struct kevent *ev)
{
#ifdef LIBWRAP
        struct request_info req;
#endif
        struct sockaddr_storage frominet;
        ssize_t rv;
        socklen_t len;
        int fd = ev->ident;
        int reject = 0;

        dprintf("inet socket active\n");

#ifdef LIBWRAP
        request_init(&req, RQ_DAEMON, "syslogd", RQ_FILE, fd, NULL);
        fromhost(&req);
        reject = !hosts_access(&req);
        if (reject)
                dprintf("access denied\n");
#endif

        len = sizeof(frominet);
        rv = recvfrom(fd, linebuf, MAXLINE, 0,
            (struct sockaddr *)&frominet, &len);
        if (rv == 0 || (rv < 0 && errno == EINTR))
                return;
        else if (rv < 0) {
                logerror("recvfrom inet");
                return;
        }

        linebuf[rv] = '\0';
        if (!reject)
                printline(cvthname(&frominet), linebuf,
                          RemoteAddDate ? ADDDATE : 0);
}

#ifndef DISABLE_TLS
/*
 * Dispatch routine for accepting TCP/TLS sockets.
 * TODO: check correct LIBWRAP usage for TCP connections
 * TODO: how do we handle fingerprint auth for incoming?
 *       set up a list of tls_conn_settings and pick one matching the hostname?
 */
void
dispatch_accept_tls(struct kevent *ev)
{
#ifdef LIBWRAP
        struct request_info req;
#endif
        struct sockaddr_storage frominet;
        socklen_t addrlen;
        int fd = ev->ident;
        int reject = 0;
        int tries = 0;
        int newsock, rc, error;
        SSL *ssl;
        struct tls_conn_settings *conn_info;
        struct TLS_Incoming_Conn *tls_in;
        struct kevent *newev;
        char hbuf[NI_MAXHOST];
        char *peername;

        dprintf("incoming TLS connection\n");
        if (!global_TLS_CTX) {
                logerror("global_TLS_CTX not initialized!\n");
                return;
        }

#ifdef LIBWRAP
        request_init(&req, RQ_DAEMON, "syslogd", RQ_FILE, fd, NULL);
        fromhost(&req);
        reject = !hosts_access(&req);
#endif
        addrlen = sizeof(frominet);
        if (!(conn_info = malloc(sizeof(struct tls_conn_settings)))
         || !(tls_in = malloc(sizeof(struct TLS_Incoming_Conn)))) {
                logerror("cannot allocate memory");
                return;
        }
          
        if (-1 == (newsock = accept(fd, (struct sockaddr *)&frominet, &addrlen))) {
                logerror("Error in accept(): %s", strerror(errno));
                return;
        }
        if ((rc = getnameinfo((struct sockaddr *)&frominet, addrlen, hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST|NI_NUMERICSERV))) {
                dprintf("could not get peername: %s", gai_strerror(rc));
                peername = NULL;
        }
        else {
                if (!(peername = malloc(strlen(hbuf)+1))) {
                        dprintf("cannot allocate %d bytes memory\n", strlen(hbuf)+1);
                        return;
                }
                (void)strlcpy(peername, hbuf, strlen(hbuf)+1);
        }
#ifdef LIBWRAP
        if (reject) {
                logerror("access from %s denied by hosts_access", peername);
                return;
        }
#endif
        if (-1 == (fcntl(newsock, F_SETFL, O_NONBLOCK))) {
                dprintf("Unable to fcntl(sock, O_NONBLOCK): %s\n", strerror(errno));
        }
        
        if (!(ssl = SSL_new(global_TLS_CTX))) {
                dprintf("Unable to establish TLS: %s\n", ERR_error_string(ERR_get_error(), NULL));
                close(newsock);
                return;                                
        }
        if (!SSL_set_fd(ssl, newsock)) {
                dprintf("Unable to connect TLS to socket %d: %s\n", newsock, ERR_error_string(ERR_get_error(), NULL));
                SSL_free(ssl);
                close(newsock);
                return;
        }
        dprintf("connection from %s accept()ed, and connected SSL*@%p with fd %d...\n",
                peername, ssl, newsock);

        /* store connection details inside ssl object, used to verify
         * cert and immediately match against hostname */
        bzero(conn_info, sizeof(*conn_info));
        conn_info->hostname = peername;
        conn_info->x509verify = X509VERIFY_NONE;
        conn_info->sslptr = ssl;
        SSL_set_app_data(ssl, conn_info);
        SSL_set_accept_state(ssl);
        
        /* non-blocking might require several calls? */
try_SSL_accept:        
        rc = SSL_accept(ssl);
        if (0 >= rc) {
                error = tls_examine_error("SSL_accept()", ssl, NULL, rc);
                switch (error) {
                        case TLS_RETRY:
                                if (++tries < TLS_SLEEP_TRIES) {
                                        usleep(TLS_SLEEP_USEC);
                                        goto try_SSL_accept;
                                }
                                break;
                        default:break;
                }
        } else {
                bzero(tls_in, sizeof(tls_in));
                tls_in->tls_conn = conn_info;
                tls_in->socket = newsock;
                tls_in->ssl = ssl;
                tls_in->inbuf[0] = '\0';
                tls_in->read_pos = tls_in->cur_msg_start = \
                        tls_in->cur_msg_len = tls_in->closenow = 0;
                SLIST_INSERT_HEAD(&TLS_Incoming_Head, tls_in, entries);
    
                newev = allocevchange();
                EV_SET(newev, newsock, EVFILT_READ, EV_ADD | EV_ENABLE,
                    0, 0, KEVENT_UDATA_CAST dispatch_read_tls);
                dprintf("established TLS connection from %s\n", peername);
                
                /*
                 * We could also listen to EOF kevents -- but I do not think
                 * that would be useful, because we still had to read() the buffer
                 * before closing the socket.
                 */
        }
}

/*
 * Dispatch routine to read from TCP/TLS sockets.
 * NB: This gets called when the TCP socket has data available, thus
 *     we can call SSL_read() on it. But that does not mean the SSL buffer
 *     holds a complete record and SSL_read() lets us read any data now.
 * Question: we get the socket fd and have to look up the tls_conn object.
 *     IMHO we always have <100 connections and a list traversal is
 *     fast enough. A possible optimization would be keeping track of
 *     message counts and moving busy sources to the front of the list.
 */
void
dispatch_read_tls(struct kevent *ev)
{
        int fd = ev->ident;
        int error, tries;
        int_fast16_t rc;
        struct TLS_Incoming_Conn *c;

        dprintf("active TLS socket %d\n", fd);
        
        SLIST_FOREACH(c, &TLS_Incoming_Head, entries) {
                dprintf("look at tls_in@%p with fd %d\n", c, c->socket);
                if (c->socket == fd)
                        break;
        }
        if (!c) {
                logerror("lost TLS socket fd %d, closing", fd);
                close(fd);
                return;
        }

/* according to draft-ietf-syslog-transport-tls-12 "It is ... possible
 * that a syslog message be transferred in multiple TLS records."
 * So we have to buffer it just like with TCP with a seperate incoming buffer.
 * 
 * Example: If a msg is sent in two TLS records 
 * then we might read the beginning (from the 1st record),
 * but wait some time for the end (in the 2nd record).
 * In that waiting time we must not block.
 */
        
        tries = 0;
try_SSL_read:
        dprintf("incoming status is msg_start %d, msg_len %d, pos %d\n",
                c->cur_msg_start, c->cur_msg_len, c->read_pos);
        dprintf("calling SSL_read(%p, %p, %d)\n", c->ssl,
        	&(c->inbuf[c->read_pos]), sizeof(c->inbuf) - c->read_pos);
        rc = SSL_read(c->ssl, &(c->inbuf[c->read_pos]), sizeof(c->inbuf) - c->read_pos);
        if (rc <= 0) {
                error = tls_examine_error("SSL_read()", c->ssl, c->tls_conn, rc);
                switch (error) {
                        case TLS_RETRY:
                                if (++tries < TLS_SLEEP_TRIES) {
                                        usleep(TLS_SLEEP_USEC);
                                        goto try_SSL_read;
                                }
                                break;
                        case TLS_TEMP_ERROR:
                                if (c->tls_conn->errorcount < TLS_MAXERRORCOUNT)
                                        break;
                                /* else fallthrough */
                        case TLS_PERM_ERROR:
                                /* there might be data in the inbuf, so only
                                 * mark for closing after message retrieval */
                                c->closenow = 1;
                                break;
                        default:break;
                }
        } else {
                dprintf("SSL_read() returned %d\n", rc);
                c->errorcount = 0;
                c->read_pos += rc;
        }
        tls_split_messages(c);
}

/* moved message splitting out of dispatching function.
 * now we can call it recursively.
 */
void
tls_split_messages(struct TLS_Incoming_Conn *c)
{
/* define only to make it better readable */
#define MSG_END_OFFSET (c->cur_msg_start + c->cur_msg_len)
        uint_fast16_t offset;
        char numbuf[PREFIXLENGTH+1];
        
        dprintf("tls_split_messages() -- incoming status is " \
                "msg_start %d, msg_len %d, pos %d\n",
                c->cur_msg_start, c->cur_msg_len, c->read_pos);

        if(c->closenow && !c->read_pos) {
                /* close socket */
                free_tls_conn(c->tls_conn);
                SLIST_REMOVE(&TLS_Incoming_Head, c, TLS_Incoming_Conn, entries);
                free(c);
        }
        if (!c->read_pos)
                return;
        if (c->read_pos < MSG_END_OFFSET)
                return;
                
        /* read length prefix, always at start of buffer */
        offset = 0;
        while (isdigit((int)c->inbuf[offset])
                && offset < c->read_pos
                && offset < PREFIXLENGTH) {
                numbuf[offset] = c->inbuf[offset];
                numbuf[++offset] = '\0';
        }
        if (offset == c->read_pos) {
                return;
        }
        if (((c->inbuf[offset] != ' ') && !isdigit((int)c->inbuf[offset]))
                || offset == PREFIXLENGTH) {
                /* found non-digit in prefix or filled buffer */
                /* Question: would it be useful to skip this message and
                 * try to find next message by looking for its beginning?
                 * IMHO not.   
                 */
                logerror("Unable to handle TLS length prefix. " \
                        "Protocol error? Closing connection now.");
                free_tls_conn(c->tls_conn);
                SLIST_REMOVE(&TLS_Incoming_Head, c, TLS_Incoming_Conn, entries);
                free(c);
                return;
        } else if (c->inbuf[offset] == ' ') {
                c->cur_msg_len = strtol(numbuf, NULL, 10);
                c->cur_msg_start = offset + 1;
                if (c->cur_msg_len > linebufsize) {
                        /* TODO: handle messages too large for our buffer
                         *  --> either receive and truncate or malloc()
                         */
                        logerror("c->cur_msg_len > linebufsize");
                        die(NULL);
                }
        }
        /* read one syslog message */        
        if (c->read_pos >= MSG_END_OFFSET) {
                /* process complete msg */
                (void)memcpy(linebuf, &c->inbuf[c->cur_msg_start], c->cur_msg_len);
                linebuf[c->cur_msg_len] = '\0';
                printline(c->tls_conn->hostname, linebuf, RemoteAddDate ? ADDDATE : 0);

                /* 
                 * silently ignore whitespace after messages.
                 * this allows debugging with socat  :-)
                 */
                if (Debug)
                        while (isspace(c->inbuf[c->read_pos-1])) {
                                c->read_pos--;
                                dprintf("skip\n"); 
                        }

                if (MSG_END_OFFSET == c->read_pos) {
                        /* no unprocessed data in buffer --> reset to empty */
                        c->cur_msg_start = c->cur_msg_len = c->read_pos = 0;
                } else {
                        /* move remaining input to start of buffer */
                        dprintf("move inbuf of length %d by %d chars\n",
                                c->read_pos - (MSG_END_OFFSET),
                                MSG_END_OFFSET);
                        memmove(&c->inbuf[0],
                                &c->inbuf[MSG_END_OFFSET],
                                c->read_pos - (MSG_END_OFFSET));
                        c->read_pos -= (MSG_END_OFFSET);
                        c->cur_msg_start = c->cur_msg_len = 0;
                }
        }
        dprintf("return with status: msg_start %d, msg_len %d, pos %d\n",
                 c->cur_msg_start, c->cur_msg_len, c->read_pos);

        /* try to read another message */
        if (c->read_pos > 10)
                tls_split_messages(c);
        return;
}
#endif /* !DISABLE_TLS */

/*
 * given a pointer to an array of char *'s, a pointer to its current
 * size and current allocated max size, and a new char * to add, add
 * it, update everything as necessary, possibly allocating a new array
 */
void
logpath_add(char ***lp, int *szp, int *maxszp, char *new)
{
        char **nlp;
        int newmaxsz;

        dprintf("Adding `%s' to the %p logpath list\n", new, *lp);
        if (*szp == *maxszp) {
                if (*maxszp == 0) {
                        newmaxsz = 4;   /* start of with enough for now */
                        *lp = NULL;
                } else
                        newmaxsz = *maxszp * 2;
                nlp = realloc(*lp, sizeof(char *) * (newmaxsz + 1));
                if (nlp == NULL) {
                        logerror("Couldn't allocate line buffer");
                        die(NULL);
                }
                *lp = nlp;
                *maxszp = newmaxsz;
        }
        if (((*lp)[(*szp)++] = strdup(new)) == NULL) {
                logerror("Couldn't allocate logpath");
                die(NULL);
        }
        (*lp)[(*szp)] = NULL;           /* always keep it NULL terminated */
}

/* do a file of log sockets */
void
logpath_fileadd(char ***lp, int *szp, int *maxszp, char *file)
{
        FILE *fp;
        char *line;
        size_t len;

        fp = fopen(file, "r");
        if (fp == NULL) {
                logerror("Could not open socket file list `%s'", file);
                die(NULL);
        }

        while ((line = fgetln(fp, &len))) {
                line[len - 1] = 0;
                logpath_add(lp, szp, maxszp, line);
        }
        fclose(fp);
}

/*
 * Take a raw input line, decode the message, and print the message
 * on the appropriate log files.
 */
void
printline(char *hname, char *msg, int flags)
{
        int c, pri;
        char *p, *q, line[MAXLINE + 1];
        long n;

        /* test for special codes */
        pri = DEFUPRI;
        p = msg;
        if (*p == '<') {
                errno = 0;
                n = strtol(p + 1, &q, 10);
                if (*q == '>' && n >= 0 && n < INT_MAX && errno == 0) {
                        p = q + 1;
                        pri = (int)n;
                }
        }
        if (pri &~ (LOG_FACMASK|LOG_PRIMASK))
                pri = DEFUPRI;

        /*
         * Don't allow users to log kernel messages.
         * NOTE: Since LOG_KERN == 0, this will also match
         *       messages with no facility specified.
         */
        if ((pri & LOG_FACMASK) == LOG_KERN)
                pri = LOG_MAKEPRI(LOG_USER, LOG_PRI(pri));

        q = line;

        while ((c = *p++) != '\0' &&
            q < &line[sizeof(line) - 2]) {
                c &= 0177;
                if (iscntrl(c))
                        if (c == '\n')
                                *q++ = ' ';
                        else if (c == '\t')
                                *q++ = '\t';
                        else {
                                *q++ = '^';
                                *q++ = c ^ 0100;
                        }
                else
                        *q++ = c;
        }
        *q = '\0';

        logmsg(pri, line, hname, flags);
}

/*
 * Take a raw input line from /dev/klog, split and format similar to syslog().
 */
void
printsys(char *msg)
{
        int n, pri, flags, is_printf;
        char *p, *q;

        for (p = msg; *p != '\0'; ) {
                flags = ISKERNEL | ADDDATE;
                if (SyncKernel)
                        flags |= SYNC_FILE;
                pri = DEFSPRI;
                is_printf = 1;
                if (*p == '<') {
                        errno = 0;
                        n = (int)strtol(p + 1, &q, 10);
                        if (*q == '>' && n >= 0 && n < INT_MAX && errno == 0) {
                                p = q + 1;
                                pri = n;
                                is_printf = 0;
                        }
                }
                if (is_printf) {
                        /* kernel printf's come out on console */
                        flags |= IGN_CONS;
                }
                if (pri &~ (LOG_FACMASK|LOG_PRIMASK))
                        pri = DEFSPRI;
                for (q = p; *q != '\0' && *q != '\n'; q++)
                        /* look for end of line */;
                if (*q != '\0')
                        *q++ = '\0';
                logmsg(pri, p, LocalHostName, flags);
                p = q;
        }
}

time_t  now;

/*
 * Check to see if `name' matches the provided specification, using the
 * specified strstr function.
 */
int
matches_spec(const char *name, const char *spec,
    char *(*check)(const char *, const char *))
{
        const char *s;
        const char *cursor;
        char prev, next;
        size_t len;

        if (name[0] == '\0')
                return (0);

        if (strchr(name, ',')) /* sanity */
                return (0);

        len = strlen(name);
        cursor = spec;
        while ((s = (*check)(cursor, name)) != NULL) {
                prev = s == spec ? ',' : *(s - 1);
                cursor = s + len;
                next = *cursor;

                if (prev == ',' && (next == '\0' || next == ','))
                        return (1);
        }

        return (0);
}

/*
 * Log a message to the appropriate log files, users, etc. based on
 * the priority.
 */
void
logmsg(int pri, char *msg, char *from, int flags)
{
        struct filed *f;
        int fac, msglen, omask, prilev, i;
        char *timestamp;
        char prog[NAME_MAX + 1];
        char buf[MAXLINE + 1];

        dprintf("logmsg: pri 0%o, flags 0x%x, from %s, msg %s\n",
            pri, flags, from, msg);

        omask = sigblock(sigmask(SIGHUP)|sigmask(SIGALRM));

        /*
         * Check to see if msg looks non-standard.
         */
        msglen = strlen(msg);
        if (msglen < 16 || msg[3] != ' ' || msg[6] != ' ' ||
            msg[9] != ':' || msg[12] != ':' || msg[15] != ' ')
                flags |= ADDDATE;

        (void)time(&now);
        if (flags & ADDDATE)
                timestamp = ctime(&now) + 4;
        else {
                timestamp = msg;
                msg += 16;
                msglen -= 16;
        }

        /* skip leading whitespace */
        while (isspace((unsigned char)*msg)) {
                msg++;
                msglen--;
        }

        /* extract facility and priority level */
        if (flags & MARK)
                fac = LOG_NFACILITIES;
        else
                fac = LOG_FAC(pri);
        prilev = LOG_PRI(pri);

        /* extract program name */
        for (i = 0; i < NAME_MAX; i++) {
                if (!isprint((unsigned char)msg[i]) ||
                    msg[i] == ':' || msg[i] == '[')
                        break;
                prog[i] = msg[i];
        }
        prog[i] = '\0';

        /* add kernel prefix for kernel messages */
        if (flags & ISKERNEL) {
                snprintf(buf, sizeof(buf), "%s: %s",
                    _PATH_UNIX, msg);
                msg = buf;
                msglen = strlen(buf);
        }

        /* log the message to the particular outputs */
        if (!Initialized) {
                f = &consfile;
                f->f_file = open(ctty, O_WRONLY, 0);

                if (f->f_file >= 0) {
                        (void)strncpy(f->f_lasttime, timestamp, 15);
                        fprintlog(f, flags, msg);
                        (void)close(f->f_file);
                }
                (void)sigsetmask(omask);
                return;
        }
        for (f = Files; f; f = f->f_next) {
                /* skip messages that are incorrect priority */
                if (!(((f->f_pcmp[fac] & PRI_EQ) && (f->f_pmask[fac] == prilev))
                     ||((f->f_pcmp[fac] & PRI_LT) && (f->f_pmask[fac] < prilev))
                     ||((f->f_pcmp[fac] & PRI_GT) && (f->f_pmask[fac] > prilev))
                     )
                    || f->f_pmask[fac] == INTERNAL_NOPRI)
                        continue;

                /* skip messages with the incorrect host name */
                if (f->f_host != NULL) {
                        switch (f->f_host[0]) {
                        case '+':
                                if (! matches_spec(from, f->f_host + 1,
                                                   strcasestr))
                                        continue;
                                break;
                        case '-':
                                if (matches_spec(from, f->f_host + 1,
                                                 strcasestr))
                                        continue;
                                break;
                        }
                }

                /* skip messages with the incorrect program name */
                if (f->f_program != NULL) {
                        switch (f->f_program[0]) {
                        case '+':
                                if (! matches_spec(prog, f->f_program + 1,
                                                   strstr))
                                        continue;
                                break;
                        case '-':
                                if (matches_spec(prog, f->f_program + 1,
                                                 strstr))
                                        continue;
                                break;
                        default:
                                if (! matches_spec(prog, f->f_program,
                                                   strstr))
                                        continue;
                                break;
                        }
                }

                if (f->f_type == F_CONSOLE && (flags & IGN_CONS))
                        continue;

                /* don't output marks to recently written files */
                if ((flags & MARK) && (now - f->f_time) < MarkInterval / 2)
                        continue;

                /*
                 * suppress duplicate lines to this file unless NoRepeat
                 */
                if ((flags & MARK) == 0 && msglen == f->f_prevlen &&
                    !NoRepeat &&
                    !strcmp(msg, f->f_prevline) &&
                    !strcasecmp(from, f->f_prevhost)) {
                        (void)strncpy(f->f_lasttime, timestamp, 15);
                        f->f_prevcount++;
                        dprintf("Msg repeated %d times, %ld sec of %d\n",
                            f->f_prevcount, (long)(now - f->f_time),
                            repeatinterval[f->f_repeatcount]);
                        /*
                         * If domark would have logged this by now,
                         * flush it now (so we don't hold isolated messages),
                         * but back off so we'll flush less often
                         * in the future.
                         */
                        if (now > REPEATTIME(f)) {
                                fprintlog(f, flags, (char *)NULL);
                                BACKOFF(f);
                        }
                } else {
                        /* new line, save it */
                        if (f->f_prevcount)
                                fprintlog(f, 0, (char *)NULL);
                        f->f_repeatcount = 0;
                        f->f_prevpri = pri;
                        (void)strncpy(f->f_lasttime, timestamp, 15);
                        (void)strncpy(f->f_prevhost, from,
                                        sizeof(f->f_prevhost));
                        if (msglen < MAXSVLINE) {
                                f->f_prevlen = msglen;
                                (void)strlcpy(f->f_prevline, msg,
                                    sizeof(f->f_prevline));
                                fprintlog(f, flags, (char *)NULL);
                        } else {
                                f->f_prevline[0] = 0;
                                f->f_prevlen = 0;
                                fprintlog(f, flags, msg);
                        }
                }
        }
        (void)sigsetmask(omask);
}

void
fprintlog(struct filed *f, int flags, char *msg)
{
        struct iovec iov[10];
        struct iovec *v;
        struct addrinfo *r;
        int j, lsent, fail, retry, l = 0;
        char line[MAXLINE + 1], repbuf[80], greetings[200];
#define ADDEV() assert(++v - iov < A_CNT(iov))
#ifndef DISABLE_TLS
        char tlsline[MAXLINE + 1 + PREFIXLENGTH + 1]; /* line + space + decimal length + null */
        char *tlslineptr;
        int error, rc;
#endif /* !DISABLE_TLS */

        v = iov;
        if (f->f_type == F_WALL) {
                v->iov_base = greetings;
                v->iov_len = snprintf(greetings, sizeof greetings,
                    "\r\n\7Message from syslogd@%s at %.24s ...\r\n",
                    f->f_prevhost, ctime(&now));
                ADDEV();
                v->iov_base = "";
                v->iov_len = 0;
                ADDEV();
        } else {
                v->iov_base = f->f_lasttime;
                v->iov_len = 15;
                ADDEV();
                v->iov_base = " ";
                v->iov_len = 1;
                ADDEV();
        }

        if (LogFacPri) {
                static char fp_buf[30];
                const char *f_s = NULL, *p_s = NULL;
                int fac = f->f_prevpri & LOG_FACMASK;
                int pri = LOG_PRI(f->f_prevpri);
                char f_n[5], p_n[5];

                if (LogFacPri > 1) {
                        CODE *c;

                        for (c = facilitynames; c->c_name != NULL; c++) {
                                if (c->c_val == fac) {
                                        f_s = c->c_name;
                                        break;
                                }
                        }
                        for (c = prioritynames; c->c_name != NULL; c++) {
                                if (c->c_val == pri) {
                                        p_s = c->c_name;
                                        break;
                                }
                        }
                }
                if (f_s == NULL) {
                        snprintf(f_n, sizeof(f_n), "%d", LOG_FAC(fac));
                        f_s = f_n;
                }
                if (p_s == NULL) {
                        snprintf(p_n, sizeof(p_n), "%d", pri);
                        p_s = p_n;
                }
                snprintf(fp_buf, sizeof(fp_buf), "<%s.%s>", f_s, p_s);
                v->iov_base = fp_buf;
                v->iov_len = strlen(fp_buf);
        } else {
                v->iov_base = "";
                v->iov_len = 0;
        }
        ADDEV();

        v->iov_base = f->f_prevhost;
        v->iov_len = strlen(v->iov_base);
        ADDEV();
        v->iov_base = " ";
        v->iov_len = 1;
        ADDEV();

        if (msg) {
                v->iov_base = msg;
                v->iov_len = strlen(msg);
        } else if (f->f_prevcount > 1) {
                v->iov_base = repbuf;
                v->iov_len = snprintf(repbuf, sizeof repbuf,
                    "last message repeated %d times", f->f_prevcount);
        } else {
                v->iov_base = f->f_prevline;
                v->iov_len = f->f_prevlen;
        }
        ADDEV();

        dprintf("Logging to %s", TypeNames[f->f_type]);
        f->f_time = now;

        if ((f->f_type == F_FORW)
#ifndef DISABLE_TLS
         || (f->f_type == F_TLS)
#endif /* !DISABLE_TLS */
        ) {
                        /*
                         * check for local vs remote messages
                         * (from FreeBSD PR#bin/7055)
                         */
                if (strcasecmp(f->f_prevhost, LocalHostName)) {
                        l = snprintf(line, sizeof(line) - 1,
                                     "<%d>%.15s [%s]: %s",
                                     f->f_prevpri, (char *) iov[0].iov_base,
                                     f->f_prevhost, (char *) iov[5].iov_base);
                } else {
                        l = snprintf(line, sizeof(line) - 1, "<%d>%.15s %s",
                                     f->f_prevpri, (char *) iov[0].iov_base,
                                     (char *) iov[5].iov_base);
                }
                if (l > MAXLINE)
                        l = MAXLINE;
        }                
        
        switch (f->f_type) {
        case F_UNUSED:
                dprintf("\n");
                break;

        case F_FORW:
                dprintf(" %s\n", f->f_un.f_forw.f_hname);
                if (finet) {
                        lsent = -1;
                        fail = 0;
                        for (r = f->f_un.f_forw.f_addr; r; r = r->ai_next) {
                                retry = 0;
                                for (j = 0; j < *finet; j++) {
#if 0 
                                        /*
                                         * should we check AF first, or just
                                         * trial and error? FWD
                                         */
                                        if (r->ai_family ==
                                            address_family_of(finet[j+1])) 
#endif
sendagain:
                                        lsent = sendto(finet[j+1], line, l, 0,
                                            r->ai_addr, r->ai_addrlen);
                                        if (lsent == -1) {
                                                switch (errno) {
                                                case ENOBUFS:
                                                        /* wait/retry/drop */
                                                        if (++retry < 5) {
                                                                usleep(1000);
                                                                goto sendagain;
                                                        }
                                                        break;
                                                case EHOSTDOWN:
                                                case EHOSTUNREACH:
                                                case ENETDOWN:
                                                        /* drop */
                                                        break;
                                                default:
                                                        /* busted */
                                                        fail++;
                                                        break;
                                                }
                                        } else if (lsent == l) 
                                                break;
                                }
                        }
                        if (lsent != l && fail) {
                                f->f_type = F_UNUSED;
                                logerror("sendto() failed");
                        }
                }
                break;

#ifndef DISABLE_TLS
        case F_TLS:
                printf("[%s]\n", f->f_un.f_tls.tls_conn->hostname);

                /* 
                 * At least on machines with enough memory using a new out buffer
                 * and making a copy is probably faster than using a second buffer
                 * just for the length prefix and calling SSL_write() twice.
                 */
                j = snprintf(tlsline, sizeof(tlsline)-1, "%d %s", l, line);
                tlslineptr = tlsline;
                retry = 0;
try_SSL_write:
                rc = SSL_write(f->f_un.f_tls.tls_conn->sslptr, tlslineptr, j);
                if (0 >= rc) {
                        error = tls_examine_error("SSL_write()",
                                        f->f_un.f_tls.tls_conn->sslptr,
                                        f->f_un.f_tls.tls_conn, rc);
                        switch (error) {
                                case TLS_RETRY:
                                        if (++retry < TLS_SLEEP_TRIES) {
                                                usleep(TLS_SLEEP_USEC);
                                                goto try_SSL_write;
                                        }
                                        break;
                                case TLS_TEMP_ERROR:
                                        if ((f->f_un.f_tls.tls_conn->errorcount)++ < TLS_MAXERRORCOUNT)
                                                break;
                                        /* else fallthrough */
                                case TLS_PERM_ERROR:
                                        /* TODO: Reconnect after x seconds  */
                                        tls_reconnect(f);
                                        break;
                                default:break;
                        }
                }
                else if (rc < j) {
                        dprintf("TLS: SSL_write() wrote %d out of %d bytes\n",
                                rc, j);
                        tlslineptr += rc;
                        j -= rc;
                        goto try_SSL_write;
                }
                f->f_un.f_tls.tls_conn->errorcount = 0;
                break;
#endif /* !DISABLE_TLS */

        case F_PIPE:
                dprintf(" %s\n", f->f_un.f_pipe.f_pname);
                v->iov_base = "\n";
                v->iov_len = 1;
                ADDEV();
                if (f->f_un.f_pipe.f_pid == 0) {
                        if ((f->f_file = p_open(f->f_un.f_pipe.f_pname,
                                                &f->f_un.f_pipe.f_pid)) < 0) {
                                f->f_type = F_UNUSED;
                                logerror(f->f_un.f_pipe.f_pname);
                                break;
                        }
                }
                if (writev(f->f_file, iov, v - iov) < 0) {
                        int e = errno;
                        if (f->f_un.f_pipe.f_pid > 0) {
                                (void) close(f->f_file);
                                deadq_enter(f->f_un.f_pipe.f_pid,
                                            f->f_un.f_pipe.f_pname);
                        }
                        f->f_un.f_pipe.f_pid = 0;
                        /*
                         * If the error was EPIPE, then what is likely
                         * has happened is we have a command that is
                         * designed to take a single message line and
                         * then exit, but we tried to feed it another
                         * one before we reaped the child and thus
                         * reset our state.
                         *
                         * Well, now we've reset our state, so try opening
                         * the pipe and sending the message again if EPIPE
                         * was the error.
                         */
                        if (e == EPIPE) {
                                if ((f->f_file = p_open(f->f_un.f_pipe.f_pname,
                                     &f->f_un.f_pipe.f_pid)) < 0) {
                                        f->f_type = F_UNUSED;
                                        logerror(f->f_un.f_pipe.f_pname);
                                        break;
                                }
                                if (writev(f->f_file, iov, v - iov) < 0) {
                                        e = errno;
                                        if (f->f_un.f_pipe.f_pid > 0) {
                                            (void) close(f->f_file);
                                            deadq_enter(f->f_un.f_pipe.f_pid,
                                                        f->f_un.f_pipe.f_pname);
                                        }
                                        f->f_un.f_pipe.f_pid = 0;
                                } else
                                        e = 0;
                        }
                        if (e != 0) {
                                errno = e;
                                logerror(f->f_un.f_pipe.f_pname);
                        }
                }
                break;

        case F_CONSOLE:
                if (flags & IGN_CONS) {
                        dprintf(" (ignored)\n");
                        break;
                }
                /* FALLTHROUGH */

        case F_TTY:
        case F_FILE:
                dprintf(" %s\n", f->f_un.f_fname);
                if (f->f_type != F_FILE) {
                        v->iov_base = "\r\n";
                        v->iov_len = 2;
                } else {
                        v->iov_base = "\n";
                        v->iov_len = 1;
                }
                ADDEV();
        again:
                if (writev(f->f_file, iov, v - iov) < 0) {
                        int e = errno;
                        if (f->f_type == F_FILE && e == ENOSPC) {
                                int lasterror = f->f_lasterror;
                                f->f_lasterror = e;
                                if (lasterror != e)
                                        logerror(f->f_un.f_fname);
                                break;
                        }
                        (void)close(f->f_file);
                        /*
                         * Check for errors on TTY's due to loss of tty
                         */
                        if ((e == EIO || e == EBADF) && f->f_type != F_FILE) {
                                f->f_file = open(f->f_un.f_fname,
                                    O_WRONLY|O_APPEND, 0);
                                if (f->f_file < 0) {
                                        f->f_type = F_UNUSED;
                                        logerror(f->f_un.f_fname);
                                } else
                                        goto again;
                        } else {
                                f->f_type = F_UNUSED;
                                errno = e;
                                f->f_lasterror = e;
                                logerror(f->f_un.f_fname);
                        }
                } else {
                        f->f_lasterror = 0;
                        if ((flags & SYNC_FILE) && (f->f_flags & FFLAG_SYNC))
                                (void)fsync(f->f_file);
                }
                break;

        case F_USERS:
        case F_WALL:
                dprintf("\n");
                v->iov_base = "\r\n";
                v->iov_len = 2;
                ADDEV();
                wallmsg(f, iov, v - iov);
                break;
        }
        f->f_prevcount = 0;
}

/*
 *  WALLMSG -- Write a message to the world at large
 *
 *      Write the specified message to either the entire
 *      world, or a list of approved users.
 */
void
wallmsg(struct filed *f, struct iovec *iov, size_t iovcnt)
{
#ifndef _NO_NETBSD_USR_SRC_
        static int reenter;                     /* avoid calling ourselves */
        int i;
        char *p;
        static struct utmpentry *ohead = NULL;
        struct utmpentry *ep;

        if (reenter++)
                return;

        (void)getutentries(NULL, &ep);
        if (ep != ohead) {
                freeutentries(ohead);
                ohead = ep;
        }
        /* NOSTRICT */
        for (; ep; ep = ep->next) {
                if (f->f_type == F_WALL) {
                        if ((p = ttymsg(iov, iovcnt, ep->line, TTYMSGTIME))
                            != NULL) {
                                errno = 0;      /* already in msg */
                                logerror(p);
                        }
                        continue;
                }
                /* should we send the message to this user? */
                for (i = 0; i < MAXUNAMES; i++) {
                        if (!f->f_un.f_uname[i][0])
                                break;
                        if (strcmp(f->f_un.f_uname[i], ep->name) == 0) {
                                if ((p = ttymsg(iov, iovcnt, ep->line,
                                    TTYMSGTIME)) != NULL) {
                                        errno = 0;      /* already in msg */
                                        logerror(p);
                                }
                                break;
                        }
                }
        }
        reenter = 0;
#endif /* !_NO_NETBSD_USR_SRC_ */
}

void
reapchild(struct kevent *ev)
{
        int status;
        pid_t pid;
        struct filed *f;

        while ((pid = wait3(&status, WNOHANG, NULL)) > 0) {
                if (!Initialized || ShuttingDown) {
                        /*
                         * Be silent while we are initializing or
                         * shutting down.
                         */
                        continue;
                }

                if (deadq_remove(pid))
                        continue;

                /* Now, look in the list of active processes. */
                for (f = Files; f != NULL; f = f->f_next) {
                        if (f->f_type == F_PIPE &&
                            f->f_un.f_pipe.f_pid == pid) {
                                (void) close(f->f_file);
                                f->f_un.f_pipe.f_pid = 0;
                                log_deadchild(pid, status,
                                              f->f_un.f_pipe.f_pname);
                                break;
                        }
                }
        }
}

/*
 * Return a printable representation of a host address.
 */
char *
cvthname(struct sockaddr_storage *f)
{
        int error;
        const int niflag = NI_DGRAM;
        static char host[NI_MAXHOST], ip[NI_MAXHOST];

        error = getnameinfo((struct sockaddr*)f, ((struct sockaddr*)f)->sa_len,
                        ip, sizeof ip, NULL, 0, NI_NUMERICHOST|niflag);

        dprintf("cvthname(%s)\n", ip);

        if (error) {
                dprintf("Malformed from address %s\n", gai_strerror(error));
                return ("???");
        }

        if (!UseNameService)
                return (ip);

        error = getnameinfo((struct sockaddr*)f, ((struct sockaddr*)f)->sa_len,
                        host, sizeof host, NULL, 0, niflag);
        if (error) {
                dprintf("Host name for your address (%s) unknown\n", ip);
                return (ip);
        }

        trim_localdomain(host);

        return (host);
}

void
trim_localdomain(char *host)
{
        size_t hl;

        hl = strlen(host);
        if (hl > 0 && host[hl - 1] == '.')
                host[--hl] = '\0';

        if (hl > LocalDomainLen && host[hl - LocalDomainLen - 1] == '.' &&
            strcasecmp(&host[hl - LocalDomainLen], LocalDomain) == 0)
                host[hl - LocalDomainLen - 1] = '\0';
}

void
domark(struct kevent *ev)
{
        struct filed *f;
        dq_t q, nextq;

        /*
         * XXX Should we bother to adjust for the # of times the timer
         * has expired (i.e. in case we miss one?).  This information is
         * returned to us in ev->data.
         */

        now = time((time_t *)NULL);
        MarkSeq += TIMERINTVL;
        if (MarkSeq >= MarkInterval) {
                logmsg(LOG_INFO, "-- MARK --", LocalHostName, ADDDATE|MARK);
                MarkSeq = 0;
        }

        for (f = Files; f; f = f->f_next) {
                if (f->f_prevcount && now >= REPEATTIME(f)) {
                        dprintf("Flush %s: repeated %d times, %d sec.\n",
                            TypeNames[f->f_type], f->f_prevcount,
                            repeatinterval[f->f_repeatcount]);
                        fprintlog(f, 0, (char *)NULL);
                        BACKOFF(f);
                }
        }

        /* Walk the dead queue, and see if we should signal somebody. */
        for (q = TAILQ_FIRST(&deadq_head); q != NULL; q = nextq) {
                nextq = TAILQ_NEXT(q, dq_entries);
                switch (q->dq_timeout) {
                case 0:
                        /* Already signalled once, try harder now. */
                        if (kill(q->dq_pid, SIGKILL) != 0)
                                (void) deadq_remove(q->dq_pid);
                        break;

                case 1:
                        /*
                         * Timed out on the dead queue, send terminate
                         * signal.  Note that we leave the removal from
                         * the dead queue to reapchild(), which will
                         * also log the event (unless the process
                         * didn't even really exist, in case we simply
                         * drop it from the dead queue).
                         */
                        if (kill(q->dq_pid, SIGTERM) != 0) {
                                (void) deadq_remove(q->dq_pid);
                                break;
                        }
                        /* FALLTHROUGH */

                default:
                        q->dq_timeout--;
                }
        }
}

/*
 * Print syslogd errors some place.
 */
void
logerror(const char *fmt, ...)
{
        static int logerror_running;
        va_list ap;
        char tmpbuf[BUFSIZ];
        char buf[BUFSIZ];

        /* If there's an error while trying to log an error, give up. */
        if (logerror_running)
                return;
        logerror_running = 1;

        va_start(ap, fmt);

        (void)vsnprintf(tmpbuf, sizeof(tmpbuf), fmt, ap);

        va_end(ap);

        if (errno)
                (void)snprintf(buf, sizeof(buf), "syslogd: %s: %s", 
                    tmpbuf, strerror(errno));
        else
                (void)snprintf(buf, sizeof(buf), "syslogd: %s", tmpbuf);

        if (daemonized) 
                logmsg(LOG_SYSLOG|LOG_ERR, buf, LocalHostName, ADDDATE);
        if (!daemonized && Debug)
                dprintf("%s\n", buf);
        if (!daemonized && !Debug)
                printf("%s\n", buf);

        logerror_running = 0;
}

void
die(struct kevent *ev)
{
        struct filed *f;
        char **p;

        ShuttingDown = 1;       /* Don't log SIGCHLDs. */
        for (f = Files; f != NULL; f = f->f_next) {
                /* flush any pending output */
                if (f->f_prevcount)
                        fprintlog(f, 0, (char *)NULL);
                if (f->f_type == F_PIPE && f->f_un.f_pipe.f_pid > 0) {
                        (void) close(f->f_file);
                        f->f_un.f_pipe.f_pid = 0;
                }
        }
        errno = 0;
        if (ev != NULL)
                logerror("Exiting on signal %d", (int) ev->ident);
        else
                logerror("Fatal error, exiting");
        for (p = LogPaths; p && *p; p++)
                unlink(*p);
        exit(0);
}

/*
 *  INIT -- Initialize syslogd from configuration table
 */
void
init(struct kevent *ev)
{
        size_t i;
        FILE *cf;
        struct filed *f, *next, **nextp;
        char *p;
        char cline[LINE_MAX];
        char prog[NAME_MAX + 1];
        char host[MAXHOSTNAMELEN];
        char hostMsg[2*MAXHOSTNAMELEN + 40];
#ifndef DISABLE_TLS
        struct TLS_Incoming_Conn *tls_in;
#endif /* !DISABLE_TLS */

        dprintf("init\n");

        (void)strlcpy(oldLocalHostName, LocalHostName,
                      sizeof(oldLocalHostName));
        (void)gethostname(LocalHostName, sizeof(LocalHostName));
        if ((p = strchr(LocalHostName, '.')) != NULL) {
                *p++ = '\0';
                LocalDomain = p;
        } else
                LocalDomain = "";
        LocalDomainLen = strlen(LocalDomain);

#ifndef DISABLE_TLS
        /* 
         * close all listening and connected TLS sockets
         */
        if (TLS_Listen_Set)
                for (i = 0; i < *TLS_Listen_Set; i++)
                        if (close(TLS_Listen_Set[i+1]) < 0)
                                logerror("close() failed");
        /* close incoming TLS connections */
        SLIST_FOREACH(tls_in, &TLS_Incoming_Head, entries) {
                free_tls_conn(tls_in->tls_conn);
                free(tls_in);
        }
        /* no effect: SLIST_EMPTY(&TLS_Incoming_Head); */

        /* TODO: I wonder whether TLS connections should
         * use a multi-step shutdown:
         * 1. send close notify to incoming connections
         * 2. receive outstanding messages/buffer
         * 3. receive close notify and close TLS socket
         * 4. close outgoing connections & files
         * 
         * Since init() is called after kevent, this would
         * probably require splitting it into hangup() for closing
         * and newinit() for opening, so that messages can still
         * be received between these two function calls.
         * 
         * Or we check inside init() if new kevents arrive
         * for the incoming sockets...
         */
#endif /* !DISABLE_TLS */

        /*
         *  Close all open log files.
         */
        Initialized = 0;
        for (f = Files; f != NULL; f = next) {
                /* flush any pending output */
                if (f->f_prevcount)
                        fprintlog(f, 0, (char *)NULL);

                switch (f->f_type) {
                case F_FILE:
                case F_TTY:
                case F_CONSOLE:
                        (void)close(f->f_file);
                        break;
                case F_PIPE:
                        if (f->f_un.f_pipe.f_pid > 0) {
                                (void)close(f->f_file);
                                deadq_enter(f->f_un.f_pipe.f_pid,
                                            f->f_un.f_pipe.f_pname);
                        }
                        f->f_un.f_pipe.f_pid = 0;
                        break;
                case F_FORW:
                        if (f->f_un.f_forw.f_addr)
                                freeaddrinfo(f->f_un.f_forw.f_addr);
                        break;
#ifndef DISABLE_TLS
                case F_TLS:
                        free_tls_conn(f->f_un.f_tls.tls_conn);
                        break;
#endif /* !DISABLE_TLS */
                }
                next = f->f_next;
                if (f->f_program != NULL)
                        free(f->f_program);
                if (f->f_host != NULL)
                        free(f->f_host);
                free((char *)f);
        }
        Files = NULL;
        nextp = &Files;

        /*
         *  Close all open UDP sockets
         */

        if (finet) {
                for (i = 0; i < *finet; i++) {
                        if (close(finet[i+1]) < 0) {
                                logerror("close() failed");
                                die(NULL);
                        }
                }
        }

        /*
         *  Reset counter of forwarding actions
         */

        NumForwards=0;

        /* open the configuration file */
        if ((cf = fopen(ConfFile, "r")) == NULL) {
                dprintf("Cannot open `%s'\n", ConfFile);
                *nextp = (struct filed *)calloc(1, sizeof(*f));
                cfline("*.ERR\t/dev/console", *nextp, "*", "*");
                (*nextp)->f_next = (struct filed *)calloc(1, sizeof(*f));
                cfline("*.PANIC\t*", (*nextp)->f_next, "*", "*");
                Initialized = 1;
                return;
        }

        /*
         *  Foreach line in the conf table, open that file.
         */
        f = NULL;
        strcpy(prog, "*");
        strcpy(host, "*");
        while (fgets(cline, sizeof(cline), cf) != NULL) {
                /*
                 * check for end-of-section, comments, strip off trailing
                 * spaces and newline character.  #!prog is treated specially:
                 * following lines apply only to that program.
                 */
                for (p = cline; isspace((unsigned char)*p); ++p)
                        continue;
                if (*p == '\0')
                        continue;
                if (*p == '#') {
                        p++;
                        if (*p != '!' && *p != '+' && *p != '-')
                                continue;
                }
                if (*p == '+' || *p == '-') {
                        host[0] = *p++;
                        while (isspace((unsigned char)*p))
                                p++;
                        if (*p == '\0' || *p == '*') {
                                strcpy(host, "*");
                                continue;
                        }
                        for (i = 1; i < MAXHOSTNAMELEN - 1; i++) {
                                if (*p == '@') {
                                        (void)strncpy(&host[i], LocalHostName,
                                            sizeof(host) - 1 - i);
                                        host[sizeof(host) - 1] = '\0';
                                        i = strlen(host) - 1;
                                        p++;
                                        continue;
                                }
                                if (!isalnum((unsigned char)*p) &&
                                    *p != '.' && *p != '-' && *p != ',')
                                        break;
                                host[i] = *p++;
                        }
                        host[i] = '\0';
                        continue;
                }
                if (*p == '!') {
                        p++;
                        while (isspace((unsigned char)*p))
                                p++;
                        if (*p == '\0' || *p == '*') {
                                strcpy(prog, "*");
                                continue;
                        }
                        for (i = 0; i < NAME_MAX; i++) {
                                if (!isprint((unsigned char)p[i]))
                                        break;
                                prog[i] = p[i];
                        }
                        prog[i] = '\0';
                        continue;
                }
                for (p = strchr(cline, '\0'); isspace((unsigned char)*--p);)
                        continue;
                *++p = '\0';
                f = (struct filed *)calloc(1, sizeof(*f));
                *nextp = f;
                nextp = &f->f_next;
                cfline(cline, f, prog, host);
        }

        /* close the configuration file */
        (void)fclose(cf);

        Initialized = 1;

        if (Debug) {
                for (f = Files; f; f = f->f_next) {
                        for (i = 0; i <= LOG_NFACILITIES; i++)
                                if (f->f_pmask[i] == INTERNAL_NOPRI)
                                        printf("X ");
                                else
                                        printf("%d ", f->f_pmask[i]);
                        printf("%s: ", TypeNames[f->f_type]);
                        switch (f->f_type) {
                        case F_FILE:
                        case F_TTY:
                        case F_CONSOLE:
                                printf("%s", f->f_un.f_fname);
                                break;

                        case F_FORW:
                                printf("%s", f->f_un.f_forw.f_hname);
                                break;
#ifndef DISABLE_TLS
                        case F_TLS:
                                printf("[%s]", f->f_un.f_tls.tls_conn->hostname);
                                break;
#endif /* !DISABLE_TLS */
                        case F_PIPE:
                                printf("%s", f->f_un.f_pipe.f_pname);
                                break;

                        case F_USERS:
                                for (i = 0;
                                    i < MAXUNAMES && *f->f_un.f_uname[i]; i++)
                                        printf("%s, ", f->f_un.f_uname[i]);
                                break;
                        }
                        if (f->f_program != NULL)
                                printf(" (%s)", f->f_program);
                        printf("\n");
                }
        }

        finet = socksetup(PF_UNSPEC, bindhostname);
        if (finet) {
                if (SecureMode) {
                        for (i = 0; i < *finet; i++) {
                                if (shutdown(finet[i+1], SHUT_RD) < 0) {
                                        logerror("shutdown() failed");
                                        die(NULL);
                                }
                        }
                } else
                        dprintf("Listening on inet and/or inet6 socket\n");
                dprintf("Sending on inet and/or inet6 socket\n");
        }

#ifndef DISABLE_TLS
        /* TODO: get TLS settings from the config file
         *  (CA certs, fingerprints, maybe hostname/port to bind to, ...)
         */
        dprintf("Preparing sockets for TLS\n");
        TLS_Listen_Set = socksetup_tls(PF_UNSPEC, bindhostname, SERVICENAME);
        /* init with new TLS_CTX
         * TODO: keep the old one and only change the X.509 settings on config change
         */
        if (global_TLS_CTX) {
                SSL_CTX_free(global_TLS_CTX);
        }
        global_TLS_CTX = init_global_TLS_CTX(MYKEY, MYCERT, MYCA, MYCAPATH, X509VERIFY);
#endif /* !DISABLE_TLS */

        logmsg(LOG_SYSLOG|LOG_INFO, "syslogd: restart", LocalHostName, ADDDATE);
        dprintf("syslogd: restarted\n");
        /*
         * Log a change in hostname, but only on a restart (we detect this
         * by checking to see if we're passed a kevent).
         */
        if (ev != NULL && strcmp(oldLocalHostName, LocalHostName) != 0) {
                (void)snprintf(hostMsg, sizeof(hostMsg),
                    "syslogd: host name changed, \"%s\" to \"%s\"",
                    oldLocalHostName, LocalHostName);
                logmsg(LOG_SYSLOG|LOG_INFO, hostMsg, LocalHostName, ADDDATE);
                dprintf("%s\n", hostMsg);
        }
}

/*
 * Crack a configuration file line
 */
void
cfline(char *line, struct filed *f, char *prog, char *host)
{
        struct addrinfo hints, *res;
        int    error, i, pri, syncfile;
        char   *bp, *p, *q;
        char   buf[MAXLINE];

        dprintf("cfline(\"%s\", f, \"%s\", \"%s\")\n", line, prog, host);

        errno = 0;      /* keep strerror() stuff out of logerror messages */

        /* clear out file entry */
        memset(f, 0, sizeof(*f));
        for (i = 0; i <= LOG_NFACILITIES; i++)
                f->f_pmask[i] = INTERNAL_NOPRI;
        
        /* 
         * There should not be any space before the log facility.
         * Check this is okay, complain and fix if it is not.
         */
        q = line;
        if (isblank((unsigned char)*line)) {
                errno = 0;
                logerror(
                    "Warning: `%s' space or tab before the log facility",
                    line);
                /* Fix: strip all spaces/tabs before the log facility */
                while (*q++ && isblank((unsigned char)*q))
                        /* skip blanks */;
                line = q; 
        }

        /* 
         * q is now at the first char of the log facility
         * There should be at least one tab after the log facility 
         * Check this is okay, and complain and fix if it is not.
         */
        q = line + strlen(line);
        while (!isblank((unsigned char)*q) && (q != line))
                q--;
        if ((q == line) && strlen(line)) { 
                /* No tabs or space in a non empty line: complain */
                errno = 0;
                logerror(
                    "Error: `%s' log facility or log target missing",
                    line);
                return;
        }
        
        /* save host name, if any */
        if (*host == '*')
                f->f_host = NULL;
        else {
                f->f_host = strdup(host);
                trim_localdomain(f->f_host);
        }

        /* save program name, if any */
        if (*prog == '*')
                f->f_program = NULL;
        else
                f->f_program = strdup(prog);

        /* scan through the list of selectors */
        for (p = line; *p && !isblank((unsigned char)*p);) {
                int pri_done, pri_cmp, pri_invert;

                /* find the end of this facility name list */
                for (q = p; *q && !isblank((unsigned char)*q) && *q++ != '.'; )
                        continue;

                /* get the priority comparison */
                pri_cmp = 0;
                pri_done = 0;
                pri_invert = 0;
                if (*q == '!') {
                        pri_invert = 1;
                        q++;
                }
                while (! pri_done) {
                        switch (*q) {
                        case '<':
                                pri_cmp = PRI_LT;
                                q++;
                                break;
                        case '=':
                                pri_cmp = PRI_EQ;
                                q++;
                                break;
                        case '>':
                                pri_cmp = PRI_GT;
                                q++;
                                break;
                        default:
                                pri_done = 1;
                                break;
                        }
                }

                /* collect priority name */
                for (bp = buf; *q && !strchr("\t ,;", *q); )
                        *bp++ = *q++;
                *bp = '\0';

                /* skip cruft */
                while (strchr(",;", *q))
                        q++;

                /* decode priority name */
                if (*buf == '*') {
                        pri = LOG_PRIMASK + 1;
                        pri_cmp = PRI_LT | PRI_EQ | PRI_GT;
                } else {
                        pri = decode(buf, prioritynames);
                        if (pri < 0) {
                                errno = 0;
                                logerror("Unknown priority name `%s'", buf);
                                return;
                        }
                }
                if (pri_cmp == 0)
                        pri_cmp = UniquePriority ? PRI_EQ
                                                 : PRI_EQ | PRI_GT;
                if (pri_invert)
                        pri_cmp ^= PRI_LT | PRI_EQ | PRI_GT;

                /* scan facilities */
                while (*p && !strchr("\t .;", *p)) {
                        for (bp = buf; *p && !strchr("\t ,;.", *p); )
                                *bp++ = *p++;
                        *bp = '\0';
                        if (*buf == '*')
                                for (i = 0; i < LOG_NFACILITIES; i++) {
                                        f->f_pmask[i] = pri;
                                        f->f_pcmp[i] = pri_cmp;
                                }
                        else {
                                i = decode(buf, facilitynames);
                                if (i < 0) {
                                        errno = 0;
                                        logerror("Unknown facility name `%s'",
                                            buf);
                                        return;
                                }
                                f->f_pmask[i >> 3] = pri;
                                f->f_pcmp[i >> 3] = pri_cmp;
                        }
                        while (*p == ',' || *p == ' ')
                                p++;
                }

                p = q;
        }

        /* skip to action part */
        while (isblank((unsigned char)*p))
                p++;

        if (*p == '-') {
                syncfile = 0;
                p++;
        } else
                syncfile = 1;

        switch (*p) {
        case '@':
#ifndef DISABLE_TLS
                if (*(p+1) == '[') {
                        /* TLS destination */
                        if (!parse_tls_destination(p, f)) {
                                logerror("Unable to parse action %s\n", p);
                                break;
                        }
                        if (!tls_connect(&global_TLS_CTX, f->f_un.f_tls.tls_conn)) {
                                logerror("Unable to connect to TLS server %s\n", f->f_un.f_tls.tls_conn->hostname);
                                break;
                        }
                        else {
                                /* successful setup */
                                f->f_type = F_TLS;
                        }
                        break;
                }
#endif /* !DISABLE_TLS */
                (void)strlcpy(f->f_un.f_forw.f_hname, ++p,
                    sizeof(f->f_un.f_forw.f_hname));
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_protocol = 0;
                error = getaddrinfo(f->f_un.f_forw.f_hname, SERVICENAME, &hints,
                    &res);
                if (error) {
                        logerror(gai_strerror(error));
                        break;
                }
                f->f_un.f_forw.f_addr = res;
                f->f_type = F_FORW;
                NumForwards++;
                break;

        case '/':
                (void)strlcpy(f->f_un.f_fname, p, sizeof(f->f_un.f_fname));
                if ((f->f_file = open(p, O_WRONLY|O_APPEND, 0)) < 0) {
                        f->f_type = F_UNUSED;
                        logerror(p);
                        break;
                }
                if (syncfile)
                        f->f_flags |= FFLAG_SYNC;
                if (isatty(f->f_file))
                        f->f_type = F_TTY;
                else
                        f->f_type = F_FILE;
                if (strcmp(p, ctty) == 0)
                        f->f_type = F_CONSOLE;
                break;

        case '|':
                f->f_un.f_pipe.f_pid = 0;
                (void) strlcpy(f->f_un.f_pipe.f_pname, p + 1,
                    sizeof(f->f_un.f_pipe.f_pname));
                f->f_type = F_PIPE;
                break;

        case '*':
                f->f_type = F_WALL;
                break;

        default:
                for (i = 0; i < MAXUNAMES && *p; i++) {
                        for (q = p; *q && *q != ','; )
                                q++;
                        (void)strncpy(f->f_un.f_uname[i], p, UT_NAMESIZE);
                        if ((q - p) > UT_NAMESIZE)
                                f->f_un.f_uname[i][UT_NAMESIZE] = '\0';
                        else
                                f->f_un.f_uname[i][q - p] = '\0';
                        while (*q == ',' || *q == ' ')
                                q++;
                        p = q;
                }
                f->f_type = F_USERS;
                break;
        }
}


/*
 *  Decode a symbolic name to a numeric value
 */
int
decode(const char *name, CODE *codetab)
{
        CODE *c;
        char *p, buf[40];

        if (isdigit((unsigned char)*name))
                return (atoi(name));

        for (p = buf; *name && p < &buf[sizeof(buf) - 1]; p++, name++) {
                if (isupper((unsigned char)*name))
                        *p = tolower((unsigned char)*name);
                else
                        *p = *name;
        }
        *p = '\0';
        for (c = codetab; c->c_name; c++)
                if (!strcmp(buf, c->c_name))
                        return (c->c_val);

        return (-1);
}

/*
 * Retrieve the size of the kernel message buffer, via sysctl.
 */
int
getmsgbufsize(void)
{
#ifndef _NO_NETBSD_USR_SRC_
        int msgbufsize, mib[2];
        size_t size;

        mib[0] = CTL_KERN;
        mib[1] = KERN_MSGBUFSIZE;
        size = sizeof msgbufsize;
        if (sysctl(mib, 2, &msgbufsize, &size, NULL, 0) == -1) {
                dprintf("Couldn't get kern.msgbufsize\n");
                return (0);
        }
        return (msgbufsize);
#else
        return 1024;
#endif /* !_NO_NETBSD_USR_SRC_ */
}

int *
socksetup(int af, const char *hostname)
{
        struct addrinfo hints, *res, *r;
        struct kevent *ev;
        int error, maxs, *s, *socks;
        const int on = 1;

        if(SecureMode && !NumForwards)
                return(NULL);

        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_PASSIVE;
        hints.ai_family = af;
        hints.ai_socktype = SOCK_DGRAM;
        error = getaddrinfo(hostname, SERVICENAME, &hints, &res);
        if (error) {
                logerror(gai_strerror(error));
                errno = 0;
                die(NULL);
        }

        /* Count max number of sockets we may open */
        for (maxs = 0, r = res; r; r = r->ai_next, maxs++)
                continue;
        socks = malloc((maxs+1) * sizeof(int));
        if (!socks) {
                logerror("Couldn't allocate memory for sockets");
                die(NULL);
        }

        *socks = 0;   /* num of sockets counter at start of array */
        s = socks + 1;
        for (r = res; r; r = r->ai_next) {
                *s = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
                if (*s < 0) {
                        logerror("socket() failed");
                        continue;
                }
                if (r->ai_family == AF_INET6 && setsockopt(*s, IPPROTO_IPV6,
                    IPV6_V6ONLY, &on, sizeof(on)) < 0) {
                        logerror("setsockopt(IPV6_V6ONLY) failed");
                        close(*s);
                        continue;
                }

                if (!SecureMode) {
                        if (bind(*s, r->ai_addr, r->ai_addrlen) < 0) {
                                logerror("bind() failed");
                                close(*s);
                                continue;
                        }
                        ev = allocevchange();
                        EV_SET(ev, *s, EVFILT_READ, EV_ADD | EV_ENABLE,
                            0, 0, KEVENT_UDATA_CAST dispatch_read_finet);
                }

                *socks = *socks + 1;
                s++;
        }

        if (*socks == 0) {
                free (socks);
                if(Debug)
                        return(NULL);
                else
                        die(NULL);
        }
        if (res)
                freeaddrinfo(res);

        return(socks);
}

/*
 * Fairly similar to popen(3), but returns an open descriptor, as opposed
 * to a FILE *.
 */
int
p_open(char *prog, pid_t *rpid)
{
        int pfd[2], nulldesc, i;
        pid_t pid;
        char *argv[4];  /* sh -c cmd NULL */
        char errmsg[200];

        if (pipe(pfd) == -1)
                return (-1);
        if ((nulldesc = open(_PATH_DEVNULL, O_RDWR)) == -1) {
                /* We are royally screwed anyway. */
                return (-1);
        }

        switch ((pid = fork())) {
        case -1:
                (void) close(nulldesc);
                return (-1);

        case 0:
                argv[0] = "sh";
                argv[1] = "-c";
                argv[2] = prog;
                argv[3] = NULL;

                (void) setsid();        /* avoid catching SIGHUPs. */

                /*
                 * Reset ignored signals to their default behavior.
                 */
                (void)signal(SIGTERM, SIG_DFL);
                (void)signal(SIGINT, SIG_DFL);
                (void)signal(SIGQUIT, SIG_DFL);
                (void)signal(SIGPIPE, SIG_DFL);
                (void)signal(SIGHUP, SIG_DFL);

                dup2(pfd[0], STDIN_FILENO);
                dup2(nulldesc, STDOUT_FILENO);
                dup2(nulldesc, STDERR_FILENO);
                for (i = getdtablesize(); i > 2; i--)
                        (void) close(i);

                (void) execvp(_PATH_BSHELL, argv);
                _exit(255);
        }

        (void) close(nulldesc);
        (void) close(pfd[0]);

        /*
         * Avoid blocking on a hung pipe.  With O_NONBLOCK, we are
         * supposed to get an EWOULDBLOCK on writev(2), which is
         * caught by the logic above anyway, which will in turn
         * close the pipe, and fork a new logging subprocess if
         * necessary.  The stale subprocess will be killed some
         * time later unless it terminated itself due to closing
         * its input pipe.
         */
        if (fcntl(pfd[1], F_SETFL, O_NONBLOCK) == -1) {
                /* This is bad. */
                (void) snprintf(errmsg, sizeof(errmsg),
                    "Warning: cannot change pipe to pid %d to "
                    "non-blocking.", (int) pid);
                logerror(errmsg);
        }
        *rpid = pid;
        return (pfd[1]);
}

void
deadq_enter(pid_t pid, const char *name)
{
        dq_t p;
        int status;

        /*
         * Be paranoid: if we can't signal the process, don't enter it
         * into the dead queue (perhaps it's already dead).  If possible,
         * we try to fetch and log the child's status.
         */
        if (kill(pid, 0) != 0) {
                if (waitpid(pid, &status, WNOHANG) > 0)
                        log_deadchild(pid, status, name);
                return;
        }

        p = malloc(sizeof(*p));
        if (p == NULL) {
                errno = 0;
                logerror("panic: out of memory!");
                exit(1);
        }

        p->dq_pid = pid;
        p->dq_timeout = DQ_TIMO_INIT;
        TAILQ_INSERT_TAIL(&deadq_head, p, dq_entries);
}

int
deadq_remove(pid_t pid)
{
        dq_t q;

        for (q = TAILQ_FIRST(&deadq_head); q != NULL;
             q = TAILQ_NEXT(q, dq_entries)) {
                if (q->dq_pid == pid) {
                        TAILQ_REMOVE(&deadq_head, q, dq_entries);
                        free(q);
                        return (1);
                }
        }
        return (0);
}

void
log_deadchild(pid_t pid, int status, const char *name)
{
        int code;
        char buf[256];
        const char *reason;

        /* Keep strerror() struff out of logerror messages. */
        errno = 0;
        if (WIFSIGNALED(status)) {
                reason = "due to signal";
                code = WTERMSIG(status);
        } else {
                reason = "with status";
                code = WEXITSTATUS(status);
                if (code == 0)
                        return;
        }
        (void) snprintf(buf, sizeof(buf),
            "Logging subprocess %d (%s) exited %s %d.",
            pid, name, reason, code);
        logerror(buf);
}

static struct kevent changebuf[8];
static int nchanges;

struct kevent *
allocevchange(void)
{

        if (nchanges == A_CNT(changebuf)) {
                /* XXX Error handling could be improved. */
                (void) wait_for_events(NULL, 0);
        }

        return (&changebuf[nchanges++]);
}

static int
wait_for_events(struct kevent *events, size_t nevents)
{
        int rv;

        rv = kevent(fkq, nchanges ? changebuf : NULL, nchanges,
                    events, nevents, NULL);
        nchanges = 0;
        return (rv);
}
