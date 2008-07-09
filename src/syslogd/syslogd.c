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
#define SYSLOG_NAMES
#include "syslogd.h"
#ifndef DISABLE_TLS
#include "tls_stuff.h"
#endif /* !DISABLE_TLS */

#ifdef LIBWRAP
int allow_severity = LOG_AUTH|LOG_INFO;
int deny_severity = LOG_AUTH|LOG_WARNING;
#endif

char    *ConfFile = _PATH_LOGCONF;
char    ctty[] = _PATH_CONSOLE;

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


struct TypeInfo {
        char *name;
        char *queue_length_string;
        char *default_length_string;
        char *queue_size_string;
        char *default_size_string;
        int64_t queue_length;
        int64_t queue_size;
        int   max_msg_length;
} TypeInfo[] = {
        /* values are set in init() 
         * -1 in length/size or max_msg_length means infinite */
        {"UNUSED",  NULL,    "0", NULL,   "0", 0, 0,     0}, 
        {"FILE",    NULL, "1024", NULL,  "1M", 0, 0, 16384}, 
        {"TTY",     NULL,    "0", NULL,   "0", 0, 0,  1024}, 
        {"CONSOLE", NULL,    "0", NULL,   "0", 0, 0,  1024}, 
        {"FORW",    NULL,    "0", NULL,  "1M", 0, 0, 16384}, 
        {"USERS",   NULL,    "0", NULL,   "0", 0, 0,  1024}, 
        {"WALL",    NULL,    "0", NULL,   "0", 0, 0,  1024}, 
        {"PIPE",    NULL, "1024", NULL,  "1M", 0, 0, 16384},
#ifndef DISABLE_TLS
        {"TLS",     NULL,   "-1", NULL, "16M", 0, 0, 16384}
#endif /* !DISABLE_TLS */
};

/* hard limit on memory usage */
struct global_memory_limit {
        char *configstring;
        rlim_t numeric;
} global_memory_limit = {NULL, 0};

struct  filed *Files = NULL;
struct  filed consfile;

int     Debug = D_NONE;         /* debug flag */
int     daemonized = 0;         /* we are not daemonized yet */
char    *LocalFQDN;             /* our FQDN */
char    LocalHostName[MAXHOSTNAMELEN];  /* our hostname */
char    oldLocalHostName[MAXHOSTNAMELEN];/* previous hostname */
char    *LocalDomain;           /* our local domain name */
size_t  LocalDomainLen;         /* length of LocalDomain */
struct socketEvent *finet;      /* Internet datagram sockets and events */
#ifndef DISABLE_TLS
struct socketEvent *TLS_Listen_Set; /* TLS/TCP sockets and events */
#endif /* !DISABLE_TLS */
int     Initialized = 0;        /* set when we have initialized ourselves */
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
bool    BSDOutputFormat = false;/* if true emit traditional BSD Syslog lines,
                                   otherwise new syslog-protocol lines */
bool    ChainRelays = false;    /* preserves the names of all relays
                                 * --> compatible with old syslogd behaviour
                                 * as introduced after FreeBSD PR#bin/7055,
                                 * but incompatible with RFC3164 and
                                 * syslog-protocol
                                 * 
                                 * TODO: implement
                                 */

void    cfline(const unsigned int, char *, struct filed *, char *, char *);
char   *cvthname(struct sockaddr_storage *);
void    deadq_enter(pid_t, const char *);
int     deadq_remove(pid_t);
int     decode(const char *, CODE *);
void    die(int fd, short event, void *ev);   /* SIGTERM kevent dispatch routine */
void    domark(int fd, short event, void *ev);/* timer kevent dispatch routine */
void    fprintlog(struct filed *, struct buf_msg *, struct buf_queue *);
int     getmsgbufsize(void);
char   *getLocalFQDN(void);
struct socketEvent* socksetup(int, const char *);
void    init(int fd, short event, void *ev);  /* SIGHUP kevent dispatch routine */
void    logerror(const char *, ...);
void    loginfo(const char *, ...);
void    logmsg_async(const int, const char *, const int);
void    logmsg(struct buf_msg *);
void    log_deadchild(pid_t, int, const char *);
int     matches_spec(const char *, const char *,
                     char *(*)(const char *, const char *));
void    printline(char *, char *, int);
void    printsys(char *);
int     p_open(char *, pid_t *);
void    trim_localdomain(char *);
void    trim_anydomain(char *);
void    reapchild(int fd, short event, void *ev); /* SIGCHLD kevent dispatch routine */
void    usage(void);
void    wallmsg(struct filed *, struct iovec *, size_t);
int     main(int, char *[]);
void    logpath_add(char ***, int *, int *, char *);
void    logpath_fileadd(char ***, int *, int *, char *);
char *make_timestamp(time_t *, bool);
unsigned check_timestamp(char *, char **, const bool, const bool);
static inline bool valid_utf8(const char *);
static inline void free_incoming_tls_sockets(void);

struct event *allocev(void);
void schedule_event(struct event **, struct timeval *, void (*)(int, short, void *), void *);
static void dispatch_read_klog(int fd, short event, void *ev);
static void dispatch_read_finet(int fd, short event, void *ev);
static void dispatch_read_funix(int fd, short event, void *ev);

unsigned int message_queue_purge(struct filed *f, const unsigned int, const int);
void send_queue(struct filed *);
void free_cred_SLIST(struct peer_cred_head *);
static struct buf_queue *find_qentry_to_delete(const struct buf_queue_head *, const int, const bool);
struct buf_msg *buf_msg_new(const size_t);
void buf_msg_free(struct buf_msg *msg);

bool message_queue_remove(struct filed *, struct buf_queue *);
bool message_queue_add(struct filed *, struct buf_msg *);
void message_queue_freeall(struct filed *);

/* for make_timestamp() */
#define TIMESTAMPBUFSIZE 35
char timestamp[TIMESTAMPBUFSIZE];

/*
 * Global line buffer.  Since we only process one event at a time,
 * a global one will do.
 */
char *linebuf;
size_t linebufsize;

/*
 * New line buffer:
 * In normal operation this struct exists only once and is
 * reused for every new message.
 * If a received message is too large then a second buffer
 * can be allocated for that message.
 * If a message cannot be delivered, then its linebuf can be
 * queued and a new one has to be allocated
 */ 
struct buf_msg *msgbuf;

static const char *bindhostname = NULL;

#define A_CNT(x)        (sizeof((x)) / sizeof((x)[0]))

#ifndef DISABLE_TLS
struct TLS_Incoming TLS_Incoming_Head = \
        SLIST_HEAD_INITIALIZER(TLS_Incoming_Head);
extern char *SSL_ERRCODE[];
struct tls_global_options_t tls_opt;

struct filed *get_f_by_conninfo(struct tls_conn_settings *conn_info);
#endif /* !DISABLE_TLS */

int
main(int argc, char *argv[])
{
        int ch, *funix, j, fklog;
        int funixsize = 0, funixmaxsize = 0;
        struct sockaddr_un sunx;
        char **pp;
        struct event *ev;
        uid_t uid = 0;
        gid_t gid = 0;
        char *user = NULL;
        char *group = NULL;
        char *root = "/";
        char *endp;
        struct group   *gr;
        struct passwd  *pw;
        unsigned long l;

	/* should we set LC_TIME="C" to ensure correct timestamps&parsing? */
        (void)setlocale(LC_ALL, "");

        while ((ch = getopt(argc, argv, "b:dnsSf:m:op:P:ru:g:t:TUv")) != -1)
                switch(ch) {
                case 'b':
                        bindhostname = optarg;
                        break;
                case 'c':               /* chain relay hostnames */
                        ChainRelays = true;
                        break;
                case 'd':               /* debug */
                        Debug = D_ALL;  /* TODO: read bitmap as integer */
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
                case 'o':               /* old-style BSD Syslog format */
                        BSDOutputFormat = true;
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
                                die(0, 0, NULL);
                        }
                } else {
getuser:
                        if ((pw = getpwnam(user)) != NULL) {
                                uid = pw->pw_uid;
                        } else {
                                errno = 0;  
                                logerror("Cannot find user `%s'", user);
                                die(0, 0, NULL);
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
                                die(0, 0, NULL);
                        }
                } else {
getgroup:
                        if ((gr = getgrnam(group)) != NULL) {
                                gid = gr->gr_gid;
                        } else {
                                errno = 0;
                                logerror("Cannot find group `%s'", group);
                                die(0, 0, NULL);
                        }
                }
        }

        if (access(root, F_OK | R_OK)) {
                logerror("Cannot access `%s'", root);
                die(0, 0, NULL);
        }

        consfile.f_type = F_CONSOLE;
        (void)strlcpy(consfile.f_un.f_fname, ctty,
            sizeof(consfile.f_un.f_fname));
        linebufsize = getmsgbufsize();
        if (linebufsize < MAXLINE)
                linebufsize = MAXLINE;
        linebufsize++;
        
        if (!(linebuf = malloc(linebufsize))) {
                logerror("Couldn't allocate buffer");
                die(0, 0, NULL);
        }
	/* TODO: remove global buffer? */
        msgbuf = buf_msg_new(linebufsize);

#ifndef SUN_LEN
#define SUN_LEN(unp) (strlen((unp)->sun_path) + 2)
#endif
        if (funixsize == 0)
                logpath_add(&LogPaths, &funixsize, 
                    &funixmaxsize, _PATH_LOG);
        funix = (int *)malloc(sizeof(int) * funixsize);
        if (funix == NULL) {
                logerror("Couldn't allocate funix descriptors");
                die(0, 0, NULL);
        }
        for (j = 0, pp = LogPaths; *pp; pp++, j++) {
                DPRINTF(D_NET, "Making unix dgram socket `%s'\n", *pp);
                unlink(*pp);
                memset(&sunx, 0, sizeof(sunx));
                sunx.sun_family = AF_LOCAL;
                (void)strncpy(sunx.sun_path, *pp, sizeof(sunx.sun_path));
                funix[j] = socket(AF_LOCAL, SOCK_DGRAM, 0);
                if (funix[j] < 0 || bind(funix[j],
                    (struct sockaddr *)&sunx, SUN_LEN(&sunx)) < 0 ||
                    chmod(*pp, 0666) < 0) {
                        logerror("Cannot create `%s'", *pp);
                        die(0, 0, NULL);
                }
                DPRINTF(D_NET, "Listening on unix dgram socket `%s'\n", *pp);
        }

#ifndef _NO_NETBSD_USR_SRC_ 
        /* I am having problems with /dev/klog on FreeBSD.
         * will look at that later..., currently I just ignore
         * it since it works on NetBSD  */
        if ((fklog = open(_PATH_KLOG, O_RDONLY, 0)) < 0) {
                DPRINTF(D_FILE, "Can't open `%s' (%d)\n", _PATH_KLOG, errno);
        } else {
                DPRINTF(D_FILE, "Listening on kernel log `%s' with fd %d\n", _PATH_KLOG, fklog);
        }
#else
        fklog = -1;
#endif /* !_NO_NETBSD_USR_SRC_ */

#ifndef DISABLE_TLS
        /* OpenSSL PRNG needs /dev/urandom, thus initialize before chroot() */
        if (!RAND_status())
                logerror("Unable to initialize OpenSSL PRNG");
        else {
                DPRINTF(D_TLS, "Initializing PRNG\n");
        }
        SLIST_INIT(&TLS_Incoming_Head);
#endif /* !DISABLE_TLS */
        /* 
         * All files are open, we can drop privileges and chroot
         */
        DPRINTF(D_MISC, "Attempt to chroot to `%s'\n", root);  
        if (chroot(root)) {
                logerror("Failed to chroot to `%s'", root);
                die(0, 0, NULL);
        }
        DPRINTF(D_MISC, "Attempt to set GID/EGID to `%d'\n", gid);  
        if (setgid(gid) || setegid(gid)) {
                logerror("Failed to set gid to `%d'", gid);
                die(0, 0, NULL);
        }
        DPRINTF(D_MISC, "Attempt to set UID/EUID to `%d'\n", uid);  
        if (setuid(uid) || seteuid(uid)) {
                logerror("Failed to set uid to `%d'", uid);
                die(0, 0, NULL);
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
        (void)event_init();
        
        /*
         * We must read the configuration file for the first time
         * after the kqueue descriptor is created, because we install
         * events during this process.
         */
        init(0, 0, NULL);

        /*
         * Always exit on SIGTERM.  Also exit on SIGINT and SIGQUIT
         * if we're debugging.
         */
        (void)signal(SIGTERM, SIG_IGN);
        (void)signal(SIGINT, SIG_IGN);
        (void)signal(SIGQUIT, SIG_IGN);
        
        ev = allocev();
        signal_set(ev, SIGTERM, die, ev);
        EVENT_ADD(ev);
        
        if (Debug) {
                ev = allocev();
                signal_set(ev, SIGINT, die, ev);
                EVENT_ADD(ev);
                ev = allocev();
                signal_set(ev, SIGQUIT, die, ev);
                EVENT_ADD(ev);
        }

        ev = allocev();
        signal_set(ev, SIGCHLD, reapchild, ev);
        EVENT_ADD(ev);

        ev = allocev();
        schedule_event(&ev,
                &((struct timeval){TIMERINTVL, 0}),
                domark, ev);
                
        (void)signal(SIGPIPE, SIG_IGN); /* We'll catch EPIPE instead. */

        /* Re-read configuration on SIGHUP. */
        (void) signal(SIGHUP, SIG_IGN);
        ev = allocev();
        signal_set(ev, SIGHUP, init, ev);
        EVENT_ADD(ev);

        if (fklog >= 0) {
                ev = allocev();
                DPRINTF(D_EVENT, "register klog for fd %d with ev@%p\n", fklog, ev);
                event_set(ev, fklog, EV_READ | EV_PERSIST, dispatch_read_klog, ev);
                EVENT_ADD(ev);
        }
        for (j = 0, pp = LogPaths; *pp; pp++, j++) {
                ev = allocev();
                event_set(ev, funix[j], EV_READ | EV_PERSIST, dispatch_read_funix, ev);
                EVENT_ADD(ev);
        }

        DPRINTF(D_MISC, "Off & running....\n");
        
        j = event_dispatch();
        /* normal termination via die(), reaching this is an error */
        DPRINTF(D_MISC, "event_dispatch() returned %d\n", j);
        return j;
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
 * 
 * Note: slightly different semantic in dispatch_read functions:
 *       - read_klog() might give multiple messages in linebuf and
 *         leaves the task of splitting them to printsys()
 *       - all other read functions receive one message and
 *         then call printline() with one buffer.
 */
static void
dispatch_read_klog(int fd, short event, void *ev)
{
        ssize_t rv;

        DPRINTF((D_CALL|D_EVENT), "Kernel log active (%d, %d, %p)"
                " with linebuf@%p, length %d)\n", fd, event, ev,
                linebuf, linebufsize);

        rv = read(fd, linebuf, linebufsize - 1);
        if (rv > 0) {
                linebuf[rv] = '\0';
                printsys(linebuf);
        } else if (rv < 0 && errno != EINTR) {
                /*
                 * /dev/klog has croaked.  Disable the event
                 * so it won't bother us again.
                 */
                logerror("klog failed");
                event_del(ev);
        }
}

/*
 * Dispatch routine for reading Unix domain sockets.
 */
static void
dispatch_read_funix(int fd, short event, void *ev)
{
        struct sockaddr_un myname, fromunix;
        ssize_t rv;
        socklen_t sunlen;

        sunlen = sizeof(myname);
        if (getsockname(fd, (struct sockaddr *)&myname, &sunlen) != 0) {
                /*
                 * This should never happen, so ensure that it doesn't
                 * happen again.
                 */
                logerror("getsockname() unix failed");
                event_del(ev);
                return;
        }

        DPRINTF((D_CALL|D_EVENT|D_NET), "Unix socket (%.*s) active (%d, %d %p)"
                " with linebuf@%p, size %d)\n", (myname.sun_len
                - sizeof(myname.sun_len) - sizeof(myname.sun_family)),
                myname.sun_path, fd, event, ev, linebuf, linebufsize-1);

        sunlen = sizeof(fromunix);
        rv = recvfrom(fd, linebuf, linebufsize-1, 0,
            (struct sockaddr *)&fromunix, &sunlen);
        if (rv > 0) {
                linebuf[rv] = '\0';
                printline(LocalFQDN, linebuf, 0);
        } else if (rv < 0 && errno != EINTR) {
                logerror("recvfrom() unix `%.*s'",
                        myname.sun_len, myname.sun_path);
        }
}

/*
 * Dispatch routine for reading Internet sockets.
 */
static void
dispatch_read_finet(int fd, short event, void *ev)
{
#ifdef LIBWRAP
        struct request_info req;
#endif
        struct sockaddr_storage frominet;
        ssize_t rv;
        socklen_t len;
        int reject = 0;

        DPRINTF((D_CALL|D_EVENT|D_NET), "inet socket active (%d, %d %p) "
                " with linebuf@%p, size %d)\n",
                fd, event, ev, linebuf, linebufsize-1);

#ifdef LIBWRAP
        request_init(&req, RQ_DAEMON, "syslogd", RQ_FILE, fd, NULL);
        fromhost(&req);
        reject = !hosts_access(&req);
        if (reject)
                DPRINTF(D_NET, "access denied\n");
#endif

        len = sizeof(frominet);
        rv = recvfrom(fd, linebuf, linebufsize-1, 0,
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

        DPRINTF(D_FILE, "Adding `%s' to the %p logpath list\n", new, *lp);
        if (*szp == *maxszp) {
                if (*maxszp == 0) {
                        newmaxsz = 4;   /* start of with enough for now */
                        *lp = NULL;
                } else
                        newmaxsz = *maxszp * 2;
                nlp = realloc(*lp, sizeof(char *) * (newmaxsz + 1));
                if (nlp == NULL) {
                        logerror("Couldn't allocate line buffer");
                        die(0, 0, NULL);
                }
                *lp = nlp;
                *maxszp = newmaxsz;
        }
        if (((*lp)[(*szp)++] = strdup(new)) == NULL) {
                logerror("Couldn't allocate logpath");
                die(0, 0, NULL);
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
                die(0, 0, NULL);
        }

        while ((line = fgetln(fp, &len))) {
                line[len - 1] = 0;
                logpath_add(lp, szp, maxszp, line);
        }
        fclose(fp);
}

/* 
 * checks UTF-8 codepoint
 * returns either its length in bytes or 0 if *input is invalid
 */
static inline bool
valid_utf8(const char *c) {
    int nb, rc;

    if (!(*c & 0x80)) nb = 1;
    else if ((*c & 0xc0) == 0x80) return 0;
    else if ((*c & 0xe0) == 0xc0) nb = 2;
    else if ((*c & 0xf0) == 0xe0) nb = 3;
    else if ((*c & 0xf8) == 0xf0) nb = 4;
    else if ((*c & 0xfc) == 0xf8) nb = 5;
    else if ((*c & 0xfe) == 0xfc) nb = 6;

    rc = nb;
    while (nb-- > 1)
      if ((*(c + nb-1) & 0xc0) != 0x80) return 0;

    return rc;
}

/* note previous versions transscribe
 * control characters, e.g. \007 --> "^G"
 * did anyone rely on that?
 * 
 * this new version works on only one buffer and
 * replaces control characters with a space
 */ 
#define REPL_CNTRL(c) do { if (iscntrl(c)) { \
                                if ((c) == '\t') {/* no change */} \
                                else (c) = ' '; \
                      } } while (0)
/*
 * Take a raw input line, split header fields,
 * check encoding, prepare struct buffer
 * and call logmsg()
 */
void
printline(char *hname, char *msg, int flags)
{
	struct buf_msg *buffer;
        int pri, i;
        char *p, *q, *start;
        long n;
        bool bsdsyslog = true;

        DPRINTF((D_CALL|D_BUFFER|D_DATA), "printline(\"%s\", \"%s\", %d)\n", hname, msg, flags);
        
        /* test for special codes */
        pri = DEFUPRI;
        p = msg;
        if (*p == '<') {
                errno = 0;
                n = strtol(p + 1, &q, 10);
                if (*q == '>' && n >= 0 && n < INT_MAX && errno == 0) {
                        p = q + 1;
                        pri = (int)n;
                        if (*p == '1') { /* syslog-protocol version */
                                p += 2;  /* skip version and space */
                                bsdsyslog = false;
                        }
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

        buffer = buf_msg_new(0);
        start = p += check_timestamp(p, &buffer->timestamp, !bsdsyslog, !BSDOutputFormat);
        DPRINTF(D_DATA, "Got timestamp \"%s\"\n", buffer->timestamp);
        
        if (bsdsyslog) {
                if (*p == ' ') p++; /* SP */
                else goto all_bsd_msg;
                /* in any error case we skip header parsing and
                 * treat all following data as message content */ 

                /* extract host */
                for (start = p; *p; p++) {
                        if (*p == ' ') {
                                buffer->host = strndup(start, p - start);
                                break;
                        } else if (*p == '[' || (*p == ':' && *(p+1) == ' ')) {
                                /* no host in message */
                                buffer->host = LocalHostName;
                                buffer->prog = strndup(start, p - start);
                                break;
                        } else {
                                REPL_CNTRL(*p);
                                *p &= 0177;
                        }
                }
                DPRINTF(D_DATA, "Got host \"%s\"\n", buffer->host);
                /* p @ SP after host, or @ :/[ after prog */

                /* extract program */
                if (!buffer->prog) {
                        if (*p == ' ') p++; /* SP */
                        else goto all_bsd_msg;
                        
                        for (start = p; *p; p++) {
                                if (*p == ' ') { /* error */
                                        goto all_bsd_msg;
                                        break;
                                } else if (*p == '[' || (*p == ':' && *(p+1) == ' ')) {
                                        buffer->prog = strndup(start, p - start);
                                        break;
                                } else {
                                        REPL_CNTRL(*p);
                                        *p &= 0177;
                                }
                        }
                }
                DPRINTF(D_DATA, "Got prog \"%s\"\n", buffer->prog);
                start = p;

                /* p @ :/[ after prog */
                if (*p == '[') {
                        p++;
                        if (*p == ' ') p++; /* SP */
                        for (start = p; *p; p++) {
                                if (*p == ' ') { /* error */
                                        goto all_bsd_msg;
                                        break;
                                } else if (*p == ']') {
                                        buffer->pid = strndup(start, p - start);
                                        break;
                                } else {
                                        REPL_CNTRL(*p);
                                        *p &= 0177;
                                }
                        }
                }
                DPRINTF(D_DATA, "Got pid \"%s\"\n", buffer->pid);

                if (*p == ']') p++;
                if (*p == ':') p++;
                if (*p == ' ') p++;
                
                /* p @ opening [ of SD or first byte of message */
                /* special case: if message starts with [
                 * then try to treat like structured data,
                 * only without UTF-8 support */
                if (*p == '[') {
                        for (start = p++; *p; p++) {
                                /* 2nd bracket must be escaped
                                 * or start a new element */
                                if ((*(p-1) != '\\' && *p == '[')
                                 || (*(p-2) != '\\' && *(p-1) != ']' && *p == '[')) {
                                        goto all_bsd_msg;
                                        break;
                                } else if (*(p-2) != '\\' && *(p-1) == ']' && *p == ' ') {
                                        buffer->sd = strndup(start, p - start);
                                        start = p+1;
                                        break;
                                } else if (*p == '\0') {
                                        /* no structured data but normal message */
                                        buffer->msg = strndup(start, p - start);
                                        break;
                                } else {
                                        REPL_CNTRL(*p);
                                        *p &= 0177;
                                }
                        }
                }
                DPRINTF(D_DATA, "Got SD \"%s\"\n", buffer->sd);
                if (*p == ' ') p++;
                start = p;
                /* and now the message itself 
                 * note: do not reset start, because we might have found a [
                 * and be inside an invalid SD field --> that is part of msg
                 */
all_bsd_msg:
                for (;; p++) {
                        if (*p == '\0') {
                                buffer->msg = strndup(start, p - start);
                                break;
                        } else {
                                REPL_CNTRL(*p);
                                *p &= 0177;
                        }
                }
                DPRINTF(D_DATA, "Got msg \"%s\"\n", buffer->msg);
        } else /* syslog-protocol */ {
                bool utf8allowed = false; /* for some fields */
                
                if (*p == ' ') p++; /* SP */
                else goto all_syslog_msg;
                
                /* extract host */
                for (start = p; *p; p++) {
                        if (*p == ' ' && start == p-1 && *(p-1) == '-') {
                                /* NILVALUE */ 
                                break;
                        } else if (*p == ' ' && (start != p-1 || *(p-1) != '-')) {
                                buffer->host = strndup(start, p - start);
                                break;
                        } else {
                                REPL_CNTRL(*p);
                                *p &= 0177;
                        }
                }
                /* p @ SP after host */
                DPRINTF(D_DATA, "Got host \"%s\"\n", buffer->host);

                /* extract app-name */
                if (*p == ' ') p++; /* SP */
                else goto all_syslog_msg;                
                for (start = p; *p; p++) {
                        if (*p == ' ' && start == p-1 && *(p-1) == '-') {
                                /* NILVALUE */ 
                                break;
                        } else if (*p == ' ' && (start != p-1 || *(p-1) != '-')) {
                                buffer->prog = strndup(start, p - start);
                                break;
                        } else {
                                REPL_CNTRL(*p);
                                *p &= 0177;
                        }
                }
                DPRINTF(D_DATA, "Got prog \"%s\"\n", buffer->prog);

                /* extract procid */
                if (*p == ' ') p++; /* SP */
                else goto all_syslog_msg;                
                for (start = p; *p; p++) {
                        if (*p == ' ' && start == p-1 && *(p-1) == '-') {
                                /* NILVALUE */ 
                                break;
                        } else if (*p == ' ' && (start != p-1 || *(p-1) != '-')) {
                                buffer->pid = strndup(start, p - start);
                                start = p;
                                break;
                        } else {
                                REPL_CNTRL(*p);
                                *p &= 0177;
                        }
                }
                DPRINTF(D_DATA, "Got pid \"%s\"\n", buffer->pid);

                /* extract msgid */
                if (*p == ' ') p++; /* SP */
                else goto all_syslog_msg;                
                for (start = p; *p; p++) {
                        if (*p == ' ' && start == p-1 && *(p-1) == '-') {
                                /* NILVALUE */ 
                                start = p+1;
                                break;
                        } else if (*p == ' ' && (start != p-1 || *(p-1) != '-')) {
                                buffer->msgid = strndup(start, p - start);
                                start = p+1;
                                break;
                        } else {
                                REPL_CNTRL(*p);
                                *p &= 0177;
                        }
                }
                DPRINTF(D_DATA, "Got msgid \"%s\"\n", buffer->msgid);

                /* extract SD */
                if (*p == ' ') p++; /* SP */
                else goto all_syslog_msg;
                if (*p == '[') {
                        /* TODO: check correct SD format */
                        for (start = p++,utf8allowed=false; *p; p++) {
                                /* 2nd bracket must be escaped
                                 * or start a new element else invalid */
                                if ((*(p-1) != '\\' && *p == '[')
                                 || (*(p-2) != '\\' && *(p-1) != ']' && *p == '[')) {
                                        goto all_bsd_msg;
                                        break;
                                } else if (*(p-2) != '\\' && *(p-1) == ']' && *p == ' ') {
                                        buffer->sd = strndup(start, p - start);
                                        start = p+1;
                                        break;
                                } else if (*(p-1) != '\\' && *p == '"') {
                                        utf8allowed = !utf8allowed;
                                } else if (*p == '\0') {
                                        /* no structured data but normal message */
                                        buffer->msg = strndup(start, p - start);
                                        break;
                                } else if (utf8allowed) {
                                        i = valid_utf8(p);
                                        if (i == 0)
                                                *p++ = '?';
                                        if (i > 1) { /* multi byte char */
                                                while(i) {
                                                        p++;
                                                        i--;
                                                }
                                                continue;
                                        }
                                        /* else i == 1 --> c \in ASCII */
                                } else {
                                        REPL_CNTRL(*p);
                                        *p &= 0177;
                                }
                        }
                } else if (*p == '-') { /* empty SD */
                        start = ++p;
                        if (*p == ' ')
                                start = ++p; /* SP */
                } else { /* SD missing! */
                }
                DPRINTF(D_DATA, "Got SD \"%s\"\n", buffer->sd);

                /* and now the message itself 
                 * note: move back to last start to check for BOM
                 */
all_syslog_msg:
                p = start;
                /* check for UTF-8-BOM */
                if (*p == 0xEF && *(p+1) == 0xBB && *(p+2) == 0xBF) {
                        utf8allowed = true;
                        start = p = p+3;
                }
                /* enter for loop only if bytes are left */
                if (*p != '\0') for (;; p++) {
                        if (*p == '\0') {
                                buffer->msg = strndup(start, p - start);
                                break;
                        } else if (utf8allowed) {
                                i = valid_utf8(p);
                                if (i == 0)
                                        *p++ = '?';
                                if (i > 1) { /* multi byte char */
                                        while(i) {
                                                p++;
                                                i--;
                                        }
                                        continue;
                                }
                                /* else i == 1 --> *p \in ASCII */
                        } else {
                                REPL_CNTRL(*p);
                                *p &= 0177;
                        }
                }
                DPRINTF(D_DATA, "Got msg \"%s\"\n", buffer->msg);
        }

        buffer->recvhost = strdup(hname);
        buffer->msglen = buffer->msgsize = 1 + p - start;
        buffer->msgorig = buffer->msg;
        buffer->pri = pri;
        if (bsdsyslog)
                buffer->flags = flags |= BSDSYSLOG;
        else
                buffer->flags = flags;

        DPRINTF(D_DATA, "Got msg \"%s\" with strlen+1=%d and msglen=%d\n",
                buffer->msg, strlen(buffer->msg)+1, buffer->msglen);

        logmsg(buffer);
        DELREF(buffer);
}

/*
 * Take a raw input line from /dev/klog, split and format similar to syslog().
 */
void
printsys(char *msg)
{
        int n, is_printf;
        char *p, *q;
        struct buf_msg *buffer;

        for (p = msg; *p != '\0'; ) {
                buffer = buf_msg_new(0);
                /* always assume BSDSYSLOG.
                 * even _if_ the kernel would output syslog-protocol
                 * then this whole loop could be changed and would not
                 * have to check every single line for its version byte */
                buffer->flags = ISKERNEL | ADDDATE | BSDSYSLOG;
                if (SyncKernel)
                        buffer->flags |= SYNC_FILE;

                buffer->pri = DEFSPRI;
                is_printf = 1;
                if (*p == '<') {
                        errno = 0;
                        n = (int)strtol(p + 1, &q, 10);
                        if (*q == '>' && n >= 0 && n < INT_MAX && errno == 0) {
                                p = q + 1;
                                buffer->pri = n;
                                is_printf = 0;
                        }
                }
                if (is_printf) {
                        /* kernel printf's come out on console */
                        buffer->flags |= IGN_CONS;
                }
                if (buffer->pri &~ (LOG_FACMASK|LOG_PRIMASK))
                        buffer->pri = DEFSPRI;

                for (q = p; *q != '\0' && *q != '\n'; q++)
                        /* look for end of line; no further checks.
                         * trust the kernel to send ASCII only */;
                if (*q != '\0')
                        *q++ = '\0';

                buffer->msg = strndup(p, q - p);
                buffer->msglen = buffer->msgsize = q - p;
                buffer->timestamp = strdup(make_timestamp(NULL, false));
                buffer->recvhost = buffer->host = LocalFQDN;
                buffer->prog = strdup(_PATH_UNIX);
                
                logmsg(buffer);
                DELREF(buffer);
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
 * wrapper with old function signature,
 * keeps calling code shorter and hides buffer allocation
 */
void
logmsg_async(const int pri, const char *msg, const int flags)
{
        struct buf_msg *buffer;
        size_t msglen;
        
        msglen = strlen(msg)+1;
        buffer = buf_msg_new(msglen);
        
        buffer->pri = pri;
        buffer->msglen = strlcpy(buffer->msg, msg, msglen) + 1;
        buffer->timestamp = strdup(make_timestamp(NULL, false));
        buffer->recvhost = buffer->host = LocalHostName;
        buffer->flags = flags;
        buffer->prog = strdup("syslogd");
        logmsg(buffer);
        DELREF(buffer);
}

/* read timestamp in from_buf, convert into a timestamp in to_buf
 *
 * returns length of timestamp found in from_buf (= number of bytes consumed)
 */
unsigned
check_timestamp(char *from_buf, char **to_buf, const bool from_iso, const bool to_iso)
{
        char *q;
        int p;
        bool found_ts = false;
        
        DPRINTF((D_CALL|D_DATA), "check_timestamp(%p = \"%s\", from_iso=%d, "
                "to_iso=%d)\n", from_buf, from_buf, from_iso, to_iso);
        
        if (!from_buf) return 0;
        /*
         * Check to see if msg looks non-standard.
         * looks at every char because we do not have a msg length yet
         */
        /* detailed checking adapted from Albert Mietus' sl_timestamp.c */
        if (from_iso) {
                if (from_buf[4] == '-' && from_buf[7] == '-'
                 && from_buf[10] == 'T' && from_buf[13] == ':'
                 && from_buf[16] == ':'
                 && isdigit(from_buf[0]) && isdigit(from_buf[1]) 
                 && isdigit(from_buf[2]) && isdigit(from_buf[3])   /* YYYY */
                 && isdigit(from_buf[5]) && isdigit(from_buf[6])
                 && isdigit(from_buf[8]) && isdigit(from_buf[9])   /* mm dd */
                 && isdigit(from_buf[11]) && isdigit(from_buf[12]) /* HH */
                 && isdigit(from_buf[14]) && isdigit(from_buf[15]) /* MM */
                 && isdigit(from_buf[17]) && isdigit(from_buf[18]) /* SS */
                 )  {
                        /* time-secfrac */
                        if (from_buf[19] == '.')
                                for (p=20; isdigit(from_buf[p]); p++) /* NOP*/ ;
                        else
                                p = 19;
                        /* time-offset */
                        if (from_buf[p] == 'Z'
                         || ((from_buf[p] == '+' || from_buf[p] == '-')
                            && from_buf[p+3] == ':'
                            && isdigit(from_buf[p+1]) && isdigit(from_buf[p+2])
                            && isdigit(from_buf[p+4]) && isdigit(from_buf[p+5])
                         ))
                                found_ts = true;
                }
        } else {
                if (from_buf[3] == ' ' && from_buf[6] == ' '
                 && from_buf[9] == ':' && from_buf[12] == ':'
                 && (from_buf[4] == ' ' || isdigit(from_buf[4]))
                 && isdigit(from_buf[5]) /* dd */
                 && isdigit(from_buf[7])  && isdigit(from_buf[8])   /* HH */
                 && isdigit(from_buf[10]) && isdigit(from_buf[11])  /* MM */
                 && isdigit(from_buf[13]) && isdigit(from_buf[14])  /* SS */
                 && isupper(from_buf[0]) && islower(from_buf[1]) /* month */
                 && islower(from_buf[2]))
                        found_ts = true;
        }
        if (!found_ts) {
                *to_buf = strdup(make_timestamp(NULL, to_iso));
                return 0;
        }
                
        if (!from_iso && !to_iso) {
                /* copy BSD timestamp */
                DPRINTF(D_CALL, "check_timestamp(): copy BSD timestamp\n");
                *to_buf = strndup(from_buf, BSD_TIMESTAMPLEN-1);
                return BSD_TIMESTAMPLEN-1;
        } else if (from_iso && to_iso) {
                /* copy ISO timestamp */
                DPRINTF(D_CALL, "check_timestamp(): copy ISO timestamp\n");
                if (!(q = strchr(from_buf, ' ')))
                        q = from_buf + strlen(from_buf);
                *to_buf = strndup(from_buf, q - from_buf);
                return q - from_buf;
        } else if (from_iso && !to_iso) {
                /* convert ISO->BSD */
                struct tm parsed;
                time_t p;
                char tsbuf[MAX_TIMESTAMPLEN];
                int i;

                DPRINTF(D_CALL, "check_timestamp(): convert ISO->BSD\n");
                for(i = 0; i < MAX_TIMESTAMPLEN && from_buf[i] != '\0'
                    && from_buf[i] != '.' && from_buf[i] != ' '; i++)
                        tsbuf[i] = from_buf[i]; /* copy date & time */
                for(; i < MAX_TIMESTAMPLEN && from_buf[i] != '\0'
                    && from_buf[i] != '+' && from_buf[i] != '-'
                    && from_buf[i] != 'Z' && from_buf[i] != ' '; i++)
                        ;                          /* skip fraction digits */
                for(; i < MAX_TIMESTAMPLEN && from_buf[i] != '\0'
                    && from_buf[i] != ':' && from_buf[i] != ' ' ; i++)
                        tsbuf[i] = from_buf[i]; /* copy TZ */
                if (from_buf[i] == ':') i++;    /* skip colon */
                for(; i < MAX_TIMESTAMPLEN && from_buf[i] != '\0'
                    && from_buf[i] != ' ' ; i++)
                        tsbuf[i] = from_buf[i]; /* copy TZ */

                (void)strptime(tsbuf, "%FT%T%z", &parsed);
                p = mktime(&parsed);

                *to_buf = strndup(make_timestamp(&p, false), BSD_TIMESTAMPLEN);
                return i;
        } else if (!from_iso && to_iso) {
                /* convert BSD->ISO */
                struct tm parsed;
                struct tm *current;
                time_t p;
                char *rc;

                DPRINTF(D_CALL, "check_timestamp(): convert BSD->ISO\n");
                rc = strptime(from_buf, "%b %d %T", &parsed);
                current = gmtime(&now);

                /* use current year and timezone */
                parsed.tm_isdst = current->tm_isdst;
                parsed.tm_gmtoff = current->tm_gmtoff;
                parsed.tm_year = current->tm_year;
                if (current->tm_mon == 0 && parsed.tm_mon == 11)
                        parsed.tm_year--;

                p = mktime(&parsed);
                rc = make_timestamp(&p, true);
                *to_buf = strndup(rc, MAX_TIMESTAMPLEN-1);

                return BSD_TIMESTAMPLEN;
        } else {
                DPRINTF(D_MISC, "Executing unreachable code in check_timestamp()\n");
                return 0;
        }
}

/*
 * Log a message to the appropriate log files, users, etc. based on
 * the priority.
 */
void
logmsg(struct buf_msg *buffer)
{
        struct filed *f;
        int fac, omask, prilev;

        DPRINTF((D_CALL|D_BUFFER), "logmsg: buffer@%p, pri 0%o, flags 0x%x, "
                "timestamp \"%s\", from \"%s\", msg \"%s\"\n",
                buffer, buffer->pri, buffer->flags, buffer->timestamp,
                buffer->recvhost, buffer->msg);

        omask = sigblock(sigmask(SIGHUP)|sigmask(SIGALRM));

        /* sanity check */
        if (Debug) {
                if (buffer->refcount != 1)
                        DPRINTF(D_BUFFER,
                                "buffer->refcount != 1 -- memory leak?\n");
                if (buffer->msglen != strlen(buffer->msg)+1)
                        DPRINTF((D_BUFFER|D_DATA),
                                "buffer->msglen = %d != %d = "
                                "strlen(buffer->msg)+1\n",
                                buffer->msglen, strlen(buffer->msg)+1);
                /* struct elements assumed to be present */
                assert(buffer->msg);
                assert(buffer->msglen);
                assert(buffer->msgorig);
                assert(buffer->msgsize);
                /* basic invariants */
                assert(buffer->msglen <= buffer->msgsize);
                assert(buffer->msgorig <= buffer->msg);
        }

        /* extract facility and priority level */
        if (buffer->flags & MARK)
                fac = LOG_NFACILITIES;
        else
                fac = LOG_FAC(buffer->pri);
        prilev = LOG_PRI(buffer->pri);

        /* log the message to the particular outputs */
        if (!Initialized) {
                f = &consfile;
                f->f_file = open(ctty, O_WRONLY, 0);

                if (f->f_file >= 0) {
                        DELREF(f->f_prevmsg);
                        f->f_prevmsg = NEWREF(buffer);
                        fprintlog(f, NEWREF(buffer), NULL);
                        DELREF(buffer);
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
                /* do we compare with host (IMHO correct) or recvhost (compatible)? */
                if (f->f_host != NULL && buffer->host != NULL) {
                        switch (f->f_host[0]) {
                        case '+':
                                if (! matches_spec(buffer->host, f->f_host + 1,
                                                   strcasestr))
                                        continue;
                                break;
                        case '-':
                                if (matches_spec(buffer->host, f->f_host + 1,
                                                 strcasestr))
                                        continue;
                                break;
                        }
                }

                /* skip messages with the incorrect program name */
                if (f->f_program != NULL && buffer->prog != NULL) {
                        switch (f->f_program[0]) {
                        case '+':
                                if (! matches_spec(buffer->prog, f->f_program + 1,
                                                   strstr))
                                        continue;
                                break;
                        case '-':
                                if (matches_spec(buffer->prog, f->f_program + 1,
                                                 strstr))
                                        continue;
                                break;
                        default:
                                if (! matches_spec(buffer->prog, f->f_program,
                                                   strstr))
                                        continue;
                                break;
                        }
                }

                if (f->f_type == F_CONSOLE && (buffer->flags & IGN_CONS))
                        continue;

                /* don't output marks to recently written files */
                if ((buffer->flags & MARK) && (now - f->f_time) < MarkInterval / 2)
                        continue;

                /*
                 * suppress duplicate lines to this file unless NoRepeat
                 */
                if ((buffer->flags & MARK) == 0 &&
                     f->f_prevmsg &&
                     buffer->msglen == f->f_prevmsg->msglen &&
                    !NoRepeat &&
                    !strcmp(buffer->msg, f->f_prevmsg->msg) &&
                    buffer->host && f->f_prevmsg->host &&
                    !strcasecmp(buffer->host, f->f_prevmsg->host)) {
                        f->f_prevcount++;
                        DPRINTF(D_DATA, "Msg repeated %d times, %ld sec of %d\n",
                            f->f_prevcount, (long)(now - f->f_time),
                            repeatinterval[f->f_repeatcount]);
                        /*
                         * If domark would have logged this by now,
                         * flush it now (so we don't hold isolated messages),
                         * but back off so we'll flush less often
                         * in the future.
                         */
                        if (now > REPEATTIME(f)) {
                                fprintlog(f, NEWREF(buffer), NULL);
                                DELREF(buffer);
                                BACKOFF(f);
                        }
                } else {
                        /* new line, save it */
                        if (f->f_prevcount)
                                fprintlog(f, NULL, NULL);
                        f->f_repeatcount = 0;
                        DELREF(f->f_prevmsg);
                        f->f_prevmsg = NEWREF(buffer);
                        fprintlog(f, NEWREF(buffer), NULL);
                        DELREF(buffer);
                }
        }
        (void)sigsetmask(omask);
}

/* 
 * Added parameter struct buf_msg *buffer
 * If present (!= NULL) then a destination that is unable to send the
 * message can queue the message for later delivery.
 */
/*
 * if qentry == NULL: new message, if temporarily undeliverable it will be enqueued
 * if qentry != NULL: a temporarily undeliverable message will not be enqueued,
 *                  but after delivery be removed from the queue
 */
#define OUT(x) ((x)?(x):"-")
void
fprintlog(struct filed *f, struct buf_msg *passedbuffer, struct buf_queue *qentry)
{
        struct buf_msg *buffer = passedbuffer;
        struct iovec iov[4];
        struct iovec *v = iov;
        struct addrinfo *r;
        int j, lsent, fail, retry, len = 0;
        size_t msglen;
        char *line = NULL;
        char *q, *p;
#define REPBUFSIZE 80
#define FPBUFSIZE 30
        char greetings[200];
        char fp_buf[FPBUFSIZE] = "\0";
#define ADDEV() assert(++v - iov < A_CNT(iov))

        DPRINTF(D_CALL, "fprintlog(%p, %p, %p)\n", f, buffer, qentry);

        f->f_time = now;

        /* increase refcount here and lower again at return.
         * this enables the buffer in the else branch to be freed
         * --> every branch needs one NEWREF() or buf_msg_new()! */ 
        if (buffer) {
                NEWREF(buffer);
        } else {
                /* ad-hoc buffer to format repeat message,
                 * problem: when is this freed? */
                if (f->f_prevcount > 1) {
                        buffer = buf_msg_new(REPBUFSIZE);
                        buffer->msglen = snprintf(buffer->msg, REPBUFSIZE,
                            "last message repeated %d times", f->f_prevcount);
                        buffer->timestamp =
                                make_timestamp(NULL, !BSDOutputFormat);
                        buffer->pri = f->f_prevmsg->pri;
                        buffer->host = LocalHostName;
                        buffer->prog = strdup("syslogd");
                } else {
                        buffer = NEWREF(f->f_prevmsg);
                }
        }

        if (LogFacPri) {
                const char *f_s = NULL, *p_s = NULL;
                int fac = buffer->pri & LOG_FACMASK;
                int pri = LOG_PRI(buffer->pri);
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
        }

        /* new message formatting:
         * instead of using iov always assemble one complete TLS-ready line
         * with length and priority (depending on BSDOutputFormat either in
         * BSD Syslog or syslog-protocol format)
         * 
         * additionally save the length of the prefixes,
         * so UDP destinations can skip the length prefix and
         * file/pipe/wall destinations can omit length and priority
         */
        if (buffer->line && buffer->linelen) {
                /* already formatted */
        } else {
                /* get required message length */
                if (BSDOutputFormat)
                        msglen = snprintf(NULL, 0, "<%d>%s%.15s %s %s%s%s%s: %s%s%s",
                                     buffer->pri, fp_buf, buffer->timestamp,
                                     (buffer->host ? buffer->host : buffer->recvhost),
                                     buffer->prog, buffer->pid ? "[" : "", 
                                     buffer->pid ? buffer->pid : "", 
                                     buffer->pid ? "]" : "", buffer->sd,
                                     (buffer->sd && buffer->msg ? " ": ""),
                                     buffer->msg);
                else
                        msglen = snprintf(NULL, 0, "<%d>1 %s%s %s %s %s %s %s%s%s",
                                     buffer->pri, fp_buf, buffer->timestamp,
                                     (buffer->host ? buffer->host : buffer->recvhost),
                                     OUT(buffer->prog), OUT(buffer->pid),
                                     OUT(buffer->msgid), OUT(buffer->sd),
                                     (buffer->msg ? " ": ""), buffer->msg);
                /* add space for length prefix */
                for (buffer->tlsprefixlen = 0, j = msglen+1; j; j /= 10)
                        buffer->tlsprefixlen++;
                /* one more for the space */
                buffer->tlsprefixlen++;

                buffer->prilen = snprintf(NULL, 0, "<%d>", buffer->pri);
                if (!BSDOutputFormat)
                        buffer->prilen += 2; /* version char and space */

                if (!(buffer->line = malloc(msglen + buffer->tlsprefixlen + 1))) {
                        logerror("Unable to allocate memory, drop message");
                        f->f_prevcount = 0;
                        /* skip the queue_add() without memory */
                        DELREF(buffer);
                        return;
                }
                if (BSDOutputFormat)
                        buffer->linelen = snprintf(buffer->line,
                                     msglen + buffer->tlsprefixlen + 1,
                                     "%d <%d>%s%.15s %s %s%s%s%s: %s%s%s",
                                     msglen, buffer->pri, fp_buf, buffer->timestamp, 
                                     (buffer->host ? buffer->host : buffer->recvhost),
                                     buffer->prog, buffer->pid ? "[" : "", 
                                     buffer->pid ? buffer->pid : "", 
                                     buffer->pid ? "]" : "", buffer->sd,
                                     (buffer->sd && buffer->msg ? " ": ""),
                                     buffer->msg);
                else
                        buffer->linelen = snprintf(buffer->line,
                                     msglen + buffer->tlsprefixlen + 1,
                                     "%d <%d>1 %s%s %s %s %s %s %s%s%s",
                                     msglen, buffer->pri, fp_buf, buffer->timestamp,
                                     (buffer->host ? buffer->host : buffer->recvhost),
                                     OUT(buffer->prog), OUT(buffer->pid),
                                     OUT(buffer->msgid), OUT(buffer->sd),
                                     (buffer->msg ? " ": ""), buffer->msg);
                DPRINTF(D_DATA, "formatted %d (of %d allowed) "
                        "octets to: %.*s\n", buffer->linelen,
                        TypeInfo[f->f_type].max_msg_length,
                        buffer->linelen, buffer->line);
        }

        /* set start and length of buffer and/or fill iovec */
        switch (f->f_type) {
        case F_UNUSED:
                /* nothing */
                break;
        case F_TLS:
                /* nothing, as TLS uses whole buffer to send */
                line = buffer->line;
                len = buffer->linelen;
                break;
        case F_FORW:
                line = buffer->line + buffer->tlsprefixlen;
                len = buffer->linelen - buffer->tlsprefixlen;
                break;
        case F_PIPE:
                line = buffer->line + buffer->tlsprefixlen + buffer->prilen;
                len = buffer->linelen - buffer->tlsprefixlen - buffer->prilen;
                v->iov_base = line;
                v->iov_len = len;
                ADDEV();
                v->iov_base = "\n";
                v->iov_len = 1;
                ADDEV();
                break;
        case F_CONSOLE:
        case F_TTY:
                len = buffer->linelen - buffer->tlsprefixlen - buffer->prilen;
                MALLOC(line, len);
                /* filter non-ASCII */
                q = line;
                p = buffer->line + buffer->tlsprefixlen + buffer->prilen;
                while (*p) {
                        if (iscntrl(*p) && *p != '\t') {
                                *q++ = '?';
                                *p += 1;
                        } else
                                *q++ = *p++;
                }
                v->iov_base = line;
                v->iov_len = len;
                ADDEV();
                v->iov_base = "\r\n";
                v->iov_len = 2;
                ADDEV();
                break;
        case F_FILE:
                line = buffer->line + buffer->tlsprefixlen + buffer->prilen;
                len = buffer->linelen - buffer->tlsprefixlen - buffer->prilen;
                v->iov_base = line;
                v->iov_len = len;
                ADDEV();
                v->iov_base = "\n";
                v->iov_len = 1;
                ADDEV();
                break;
        case F_USERS:
        case F_WALL:
                len = buffer->linelen - buffer->tlsprefixlen - buffer->prilen;
                MALLOC(line, len);
                /* filter non-ASCII */
                q = line;
                p = buffer->line + buffer->tlsprefixlen + buffer->prilen;
                while (*p) {
                        if (iscntrl(*p) && *p != '\t') {
                                *q++ = '?';
                                *p += 1;
                        } else
                                *q++ = *p++;
                }
                
                v->iov_base = greetings;
                v->iov_len = snprintf(greetings, sizeof(greetings),
                        "\r\n\7Message from syslogd@%s at %s ...\r\n",
                        (buffer->host ? buffer->host : buffer->recvhost),
                        buffer->timestamp);
                ADDEV();
                v->iov_base = line;
                v->iov_len = len;
                ADDEV();
                v->iov_base = "\n";
                v->iov_len = 1;
                ADDEV();
                break;
        }

        /* assert maximum message length */
        if (TypeInfo[f->f_type].max_msg_length != -1
         && TypeInfo[f->f_type].max_msg_length < len) {
                len = TypeInfo[f->f_type].max_msg_length;
                DPRINTF(D_DATA, "truncating oversized message to %d octets\n", len);
        }

        /* send */
        switch (f->f_type) {
        case F_UNUSED:
                DPRINTF(D_MISC, "Logging to %s\n", TypeInfo[f->f_type].name);
                break;

        case F_FORW:
                DPRINTF(D_MISC, "Logging to %s %s\n", TypeInfo[f->f_type].name, f->f_un.f_forw.f_hname);
                if (finet) {
                        lsent = -1;
                        fail = 0;
                        for (r = f->f_un.f_forw.f_addr; r; r = r->ai_next) {
                                retry = 0;
                                for (j = 0; j < finet->fd; j++) {
#if 0 
                                        /*
                                         * should we check AF first, or just
                                         * trial and error? FWD
                                         */
                                        if (r->ai_family ==
                                            address_family_of(finet[j+1])) 
#endif
sendagain:
                                        lsent = sendto(finet[j+1].fd, line, len, 0,
                                            r->ai_addr, r->ai_addrlen);
                                        if (lsent == -1) {
                                                switch (errno) {
                                                case ENOBUFS:
                                                        /* wait/retry/drop */
                                                        /* TODO: use event for
                                                         * this. problem:
                                                         * how to test?  */ 
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
                                        } else if (lsent == len) 
                                                break;
                                }
                        }
                        if (lsent != len && fail) {
                                f->f_type = F_UNUSED;
                                logerror("sendto() failed");
                        }
                }
                break;

#ifndef DISABLE_TLS
        case F_TLS:
                DPRINTF(D_MISC, "Logging to %s %s\n", TypeInfo[f->f_type].name, f->f_un.f_tls.tls_conn->hostname);
                if (!tls_send(f, buffer) && !qentry) {
                                message_queue_add(f, NEWREF(buffer));
                }
                break;
#endif /* !DISABLE_TLS */

        case F_PIPE:
                DPRINTF(D_MISC, "Logging to %s %s\n", TypeInfo[f->f_type].name, f->f_un.f_pipe.f_pname);
                if (f->f_un.f_pipe.f_pid == 0) {
                        /* (re-)open */
                        if ((f->f_file = p_open(f->f_un.f_pipe.f_pname,
                                                &f->f_un.f_pipe.f_pid)) < 0) {
                                f->f_type = F_UNUSED;
                                logerror(f->f_un.f_pipe.f_pname);
                                if (buffer && !qentry) {
                                        message_queue_add(f, NEWREF(buffer));
                                }
                                break;
                        }
                        else
                                send_queue(f);
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
                                        message_queue_freeall(f);
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
                                        f->f_prevcount = 0;
                                        if (buffer && !qentry) {
                                                message_queue_add(f, NEWREF(buffer));
                                        }
                                        DELREF(buffer);
                                        return;
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
                if (buffer->flags & IGN_CONS) {
                        DPRINTF(D_MISC, "Logging to %s (ignored)\n", TypeInfo[f->f_type].name);
                        break;
                }
                /* FALLTHROUGH */

        case F_TTY:
        case F_FILE:
                DPRINTF(D_MISC, "Logging to %s %s\n", TypeInfo[f->f_type].name, f->f_un.f_fname);
        again:
                if (writev(f->f_file, iov, v - iov) < 0) {
                        int e = errno;
                        if (f->f_type == F_FILE && e == ENOSPC) {
                                int lasterror = f->f_lasterror;
                                f->f_lasterror = e;
                                if (lasterror != e)
                                        logerror(f->f_un.f_fname);
                                /* TODO: can we get an event when file is writeable again? */
                                f->f_prevcount = 0;
                                if (buffer && !qentry) {
                                        message_queue_add(f, NEWREF(buffer));
                                }
                                DELREF(buffer);
                                return;
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
                                        message_queue_freeall(f);
                                } else
                                        goto again;
                        } else {
                                f->f_type = F_UNUSED;
                                errno = e;
                                f->f_lasterror = e;
                                logerror(f->f_un.f_fname);
                                message_queue_freeall(f);
                        }
                } else {
                        f->f_lasterror = 0;
                        if ((buffer->flags & SYNC_FILE) && (f->f_flags & FFLAG_SYNC))
                                (void)fsync(f->f_file);
                }
                break;

        case F_USERS:
        case F_WALL:
                DPRINTF(D_MISC, "Logging to %s\n", TypeInfo[f->f_type].name);
                wallmsg(f, iov, v - iov);
                break;
        }
        f->f_prevcount = 0;
        /* this belongs to the ad-hoc buffer at the first if(buffer) */
        DELREF(buffer);
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
#ifdef __NetBSD_Version
        static int reenter;                     /* avoid calling ourselves */
        int i;
        char *p;
        static struct utmpentry *ohead = NULL;
        struct utmpentry *ep;

        if (reenter++)
                return;

        /* TODO: dh found a memory allocation bug in the utmp functions
         *       --> check sometime sater if it got fixed.            */
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
#endif /* __NetBSD_Version */
#ifdef __FreeBSD_Version
        static int reenter;                     /* avoid calling ourselves */
        FILE *uf;
        struct utmp ut;
        int i;
        const char *p;
        char line[sizeof(ut.ut_line) + 1];

        if (reenter++)
                return;
        if ((uf = fopen(_PATH_UTMP, "r")) == NULL) {
                logerror(_PATH_UTMP);
                reenter = 0;
                return;
        }
        /* NOSTRICT */
        while (fread((char *)&ut, sizeof(ut), 1, uf) == 1) {
                if (ut.ut_name[0] == '\0')
                        continue;
                /* We must use strncpy since ut_* may not be NUL terminated. */
                strncpy(line, ut.ut_line, sizeof(line) - 1);
                line[sizeof(line) - 1] = '\0';
                if (f->f_type == F_WALL) {
                        if ((p = ttymsg(iov, iovcnt, line, TTYMSGTIME)) != NULL) {
                                errno = 0;      /* already in msg */
                                logerror(p);
                        }
                        continue;
                }
                /* should we send the message to this user? */
                for (i = 0; i < MAXUNAMES; i++) {
                        if (!f->f_un.f_uname[i][0])
                                break;
                        if (!strncmp(f->f_un.f_uname[i], ut.ut_name,
                            UT_NAMESIZE)) {
                                if ((p = ttymsg(iov, iovcnt, line, TTYMSGTIME))
                                                                != NULL) {
                                        errno = 0;      /* already in msg */
                                        logerror(p);
                                }
                                break;
                        }
                }
        }
        (void)fclose(uf);
        reenter = 0;
#endif /* __FreeBSD_Version */
}

void
reapchild(int fd, short event, void *ev)
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
 * 
 * TODO: use FQDN for syslog-protocol
 */
char *
cvthname(struct sockaddr_storage *f)
{
        int error;
        const int niflag = NI_DGRAM;
        static char host[NI_MAXHOST], ip[NI_MAXHOST];

        error = getnameinfo((struct sockaddr*)f, ((struct sockaddr*)f)->sa_len,
                        ip, sizeof ip, NULL, 0, NI_NUMERICHOST|niflag);

        DPRINTF(D_CALL, "cvthname(%s)\n", ip);

        if (error) {
                DPRINTF(D_NET, "Malformed from address %s\n", gai_strerror(error));
                return ("???");
        }

        if (!UseNameService)
                return (ip);

        error = getnameinfo((struct sockaddr*)f, ((struct sockaddr*)f)->sa_len,
                        host, sizeof host, NULL, 0, niflag);
        if (error) {
                DPRINTF(D_NET, "Host name for your address (%s) unknown\n", ip);
                return (ip);
        }

        trim_localdomain(host);

        return (host);
}

/*
 * TODO: Check if a local domain has to be treated different than other
 * domains. I am not quite certain when the local domain is used at all.
 */ 
void
trim_localdomain(char *host)
{
        size_t hl;

        if (!BSDOutputFormat)
                return;

        hl = strlen(host);
        if (hl > 0 && host[hl - 1] == '.')
                host[--hl] = '\0';

        if (hl > LocalDomainLen && host[hl - LocalDomainLen - 1] == '.' &&
            strcasecmp(&host[hl - LocalDomainLen], LocalDomain) == 0)
                host[hl - LocalDomainLen - 1] = '\0';
}

void
trim_anydomain(char *host)
{
        bool onlydigits = true;
        int i;

        if (!BSDOutputFormat)
                return;

        /* if non-digits found, then assume hostname and cut at first dot (this
         * case also covers IPv6 addresses which should not contain dots), 
         * if only digits then assume IPv4 address and do not cut at all */
        for (i = 0; host[i]; i++) {
                if (host[i] == '.' && !onlydigits)
                        host[i] = '\0';
                else if (!isdigit(host[i]) && host[i] != '.')
                        onlydigits = false;
        }
}

void
domark(int fd, short event, void *ev)
{
        struct event *ev_pass = (struct event *)ev;
        struct filed *f;
        dq_t q, nextq;
        struct rlimit rlp;
        struct rusage ru;
#define MARKLINELENGTH 120
        char markline[MARKLINELENGTH];
        char maxmem[12];
        char usemem[12];
#define MEMORY_HIGH_PERC 95
        bool sweep_queues = false;
        
        schedule_event(&ev_pass,
                &((struct timeval){TIMERINTVL, 0}),
                domark, ev_pass);
        DPRINTF((D_CALL|D_EVENT), "domark()\n");

        if ((getrusage(RUSAGE_SELF, &ru) == -1)
         || (getrlimit(RLIMIT_DATA, &rlp) == -1)) {
                logerror("Unable to get ressource usage/limits");
                snprintf(markline, MARKLINELENGTH, "-- MARK --");
        } else {
                humanize_number(usemem, sizeof(usemem), 1024*(ru.ru_idrss+ru.ru_isrss), "bytes", HN_AUTOSCALE, 0);
                humanize_number(maxmem, sizeof(maxmem), rlp.rlim_max, "bytes", HN_AUTOSCALE, 0);
                
                snprintf(markline, MARKLINELENGTH, "-- MARK -- (mem usage: %s/%s)",
                        usemem, maxmem);
                /* negative numbers imply overflow. check necessary? */
                if ((ru.ru_idrss+ru.ru_isrss+ru.ru_ixrss > 0)
                 && ((MEMORY_HIGH_PERC * rlp.rlim_max) > 0)
                 && (ru.ru_idrss+ru.ru_isrss+ru.ru_ixrss >= (MEMORY_HIGH_PERC * rlp.rlim_max) / 100))
                        sweep_queues = true;
        }
        now = time((time_t *)NULL);
        MarkSeq += TIMERINTVL;
        if (MarkSeq >= MarkInterval) {
                logmsg_async(LOG_INFO, markline, ADDDATE|MARK);
                MarkSeq = 0;
        }

        for (f = Files; f; f = f->f_next) {
                if (f->f_prevcount && now >= REPEATTIME(f)) {
                        DPRINTF(D_DATA, "Flush %s: repeated %d times, %d sec.\n",
                            TypeInfo[f->f_type].name, f->f_prevcount,
                            repeatinterval[f->f_repeatcount]);
                        fprintlog(f, NULL, NULL);
                        BACKOFF(f);
                }
                if (sweep_queues)
                        message_queue_purge(f, f->f_qelements/10,
                                PURGE_BY_PRIORITY);
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
                logmsg_async(LOG_SYSLOG|LOG_ERR, buf, ADDDATE);
        if (!daemonized && Debug)
                DPRINTF(D_MISC, "%s\n", buf);
        if (!daemonized && !Debug)
                printf("%s\n", buf);

        logerror_running = 0;
}

/*
 * Print syslogd info some place.
 */
void
loginfo(const char *fmt, ...)
{
        va_list ap;
        char tmpbuf[BUFSIZ];
        char buf[BUFSIZ];

        va_start(ap, fmt);
        (void)vsnprintf(tmpbuf, sizeof(tmpbuf), fmt, ap);
        va_end(ap);
        (void)snprintf(buf, sizeof(buf), "syslogd: %s", tmpbuf);

        if (daemonized) 
                logmsg_async(LOG_SYSLOG|LOG_INFO, buf, ADDDATE);
        if (!daemonized && Debug)
                DPRINTF(D_MISC, "%s\n", buf);
        if (!daemonized && !Debug)
                printf("%s\n", buf);
}

/* used in init() and die() */
static inline void
free_incoming_tls_sockets(void)
{
        struct TLS_Incoming_Conn *tls_in;
        int i;
        
        /* 
         * close all listening and connected TLS sockets
         */
        if (TLS_Listen_Set)
                for (i = 0; i < TLS_Listen_Set->fd; i++) {
                        if (close(TLS_Listen_Set[i+1].fd) == -1)
                                logerror("close() failed");
                        if (event_del(TLS_Listen_Set[i+1].ev) == -1)
                                logerror("event_del() failed");
                        FREEPTR(TLS_Listen_Set[i+1].ev);
                }
        /* close/free incoming TLS connections */
        while (!SLIST_EMPTY(&TLS_Incoming_Head)) {
                tls_in = SLIST_FIRST(&TLS_Incoming_Head);
                SLIST_REMOVE_HEAD(&TLS_Incoming_Head, entries);
                FREEPTR(tls_in->inbuf);
                free_tls_conn(tls_in->tls_conn);
                free(tls_in);
        }
}

void
die(int fd, short event, void *ev)
{
        struct filed *f, *next;
        char **p;

        ShuttingDown = 1;       /* Don't log SIGCHLDs. */

#ifndef DISABLE_TLS
        free_incoming_tls_sockets();
#endif /* !DISABLE_TLS */

        /*
         *  Close all open log files.
         */
        for (f = Files; f != NULL; f = next) {
                DPRINTF(D_MEM, "die() cleaning f@%p)\n", f);
                /* flush any pending output */
                if (f->f_prevcount)
                        fprintlog(f, NULL, NULL);
                send_queue(f);
                message_queue_freeall(f);

                switch (f->f_type) {
                case F_FILE:
                case F_TTY:
                case F_CONSOLE:
                        (void)close(f->f_file);
                        break;
                case F_PIPE:
                        if (f->f_un.f_pipe.f_pid > 0) {
                                (void)close(f->f_file);
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
                DELREF(f->f_prevmsg);
                FREEPTR(f->f_program);
                FREEPTR(f->f_host);
                free((char *)f);
        }

#ifndef DISABLE_TLS
        FREEPTR(tls_opt.CAdir);
        FREEPTR(tls_opt.CAfile);
        FREEPTR(tls_opt.keyfile);
        FREEPTR(tls_opt.certfile);
        FREEPTR(tls_opt.x509verify);
        FREEPTR(tls_opt.bindhost);
        FREEPTR(tls_opt.bindport);
        FREEPTR(tls_opt.server);
        FREEPTR(tls_opt.gen_cert);
        free_cred_SLIST(&tls_opt.cert_head);
        free_cred_SLIST(&tls_opt.fprint_head);
        FREE_SSL_CTX(tls_opt.global_TLS_CTX);
#endif /* !DISABLE_TLS */

        errno = 0;
        if (ev != NULL)
                logerror("Exiting on signal %d", fd);
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
init(int fd, short event, void *ev)
{
        size_t i;
        FILE *cf;
        struct filed *f, *next, **nextp;
        char *p;
        char cline[LINE_MAX];
        char prog[NAME_MAX + 1];
        char host[MAXHOSTNAMELEN];
        unsigned int linenum;
        bool found_keyword;
#ifndef DISABLE_TLS
        struct peer_cred *cred = NULL;
        struct peer_cred_head *credhead = NULL;
        char *tmp_buf = NULL;

        /* central list of recognized configuration keywords
         * and an address for their values as strings */
        const struct config_keywords {
                char *keyword;
                char **variable;
        } config_keywords[] = {
                {"tls_ca",                &tls_opt.CAfile},
                {"tls_cadir",             &tls_opt.CAdir},
                {"tls_cert",              &tls_opt.certfile},
                {"tls_key",               &tls_opt.keyfile},
                {"tls_verify",            &tls_opt.x509verify},
                {"tls_bindport",          &tls_opt.bindport},
                {"tls_bindhost",          &tls_opt.bindhost},
                {"tls_server",            &tls_opt.server},
                {"tls_gen_cert",          &tls_opt.gen_cert},
                /* special cases in parsing */
                {"tls_allow_fingerprints",&tmp_buf},
                {"tls_allow_clientcerts", &tmp_buf},
                {"tls_queue_length",      &TypeInfo[F_TLS].queue_length_string},
                {"file_queue_length",     &TypeInfo[F_FILE].queue_length_string},
                {"pipe_queue_length",     &TypeInfo[F_PIPE].queue_length_string},
                {"tls_queue_size",        &TypeInfo[F_TLS].queue_size_string},
                {"file_queue_size",       &TypeInfo[F_FILE].queue_size_string},
                {"pipe_queue_size",       &TypeInfo[F_PIPE].queue_size_string},
                {"mem_size_limit",        &global_memory_limit.configstring}
        };
#endif /* !DISABLE_TLS */

        DPRINTF((D_EVENT|D_CALL), "init\n");

        /* get FQDN and hostname/domain */
        if (LocalFQDN)
                (void)strlcpy(oldLocalHostName, LocalFQDN, sizeof(oldLocalHostName));
        FREEPTR(LocalFQDN);
        LocalFQDN = getLocalFQDN();
        if ((p = strchr(LocalFQDN, '.')) != NULL) {
                LocalDomain = p;
                (void)strlcpy(LocalHostName, LocalFQDN, 1+p-LocalFQDN);
        } else {
                LocalDomain = "";
                (void)strlcpy(LocalHostName, LocalFQDN, sizeof(LocalHostName));
        }
        LocalDomainLen = strlen(LocalDomain);

        Initialized = 0;

#ifndef DISABLE_TLS
        free_incoming_tls_sockets();
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
        for (f = Files; f != NULL; f = next) {
                /* flush any pending output */
                if (f->f_prevcount)
                        fprintlog(f, NULL, NULL);
                send_queue(f);
                message_queue_freeall(f);

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
                DELREF(f->f_prevmsg);
                FREEPTR(f->f_program);
                FREEPTR(f->f_host);
                free((char *)f);
        }
        Files = NULL;
        nextp = &Files;

        /*
         *  Close all open UDP sockets
         */

        if (finet) {
                for (i = 0; i < finet->fd; i++) {
                        if (close(finet[i+1].fd) < 0) {
                                logerror("close() failed");
                                die(0, 0, NULL);
                        }
                        if (event_del(finet[i+1].ev) == -1)
                                logerror("event_del() failed");
                                /* what do we do now? */
                        else
                                FREEPTR(finet[i+1].ev);
                }
        }

        /*
         *  Reset counter of forwarding actions
         */

        NumForwards=0;

        /* open the configuration file */
        if ((cf = fopen(ConfFile, "r")) == NULL) {
                DPRINTF(D_FILE, "Cannot open `%s'\n", ConfFile);
                *nextp = (struct filed *)calloc(1, sizeof(*f));
                cfline(0, "*.ERR\t/dev/console", *nextp, "*", "*");
                (*nextp)->f_next = (struct filed *)calloc(1, sizeof(*f));
                cfline(0, "*.PANIC\t*", (*nextp)->f_next, "*", "*");
                Initialized = 1;
                return;
        }
        linenum = 0;

        /* free all previous config options */
        for (i = 0; i < A_CNT(TypeInfo); i++) {
                if (TypeInfo[i].queue_length_string
                 && TypeInfo[i].queue_length_string != TypeInfo[i].default_length_string) {
                        FREEPTR(TypeInfo[i].queue_length_string);
                        TypeInfo[i].queue_length_string = strdup(TypeInfo[i].default_length_string);
                 }
                if (TypeInfo[i].queue_size_string
                 && TypeInfo[i].queue_size_string != TypeInfo[i].default_size_string) {
                        FREEPTR(TypeInfo[i].queue_size_string);
                        TypeInfo[i].queue_size_string = strdup(TypeInfo[i].default_size_string);
                 }
        }
        for (i = 0; i < A_CNT(config_keywords); i++)
                FREEPTR(*config_keywords[i].variable);

#ifndef DISABLE_TLS
        /* init with new TLS_CTX
         * as far as I see one cannot change the cert/key of an existing CTX
         */
        FREE_SSL_CTX(tls_opt.global_TLS_CTX);

        free_cred_SLIST(&tls_opt.cert_head);
        free_cred_SLIST(&tls_opt.fprint_head);

        /* 
         * global settings
         * I introduced a second parsing loop, because I do not want
         * errors caused by exotic line ordering.
         */
        while (fgets(cline, sizeof(cline), cf) != NULL) {
                linenum++;
                for (p = cline; isspace((unsigned char)*p); ++p)
                        continue;
                if ((*p == '\0') || (*p == '#'))
                        continue;

                for (i = 0; i < A_CNT(config_keywords); i++) {
                        if (copy_config_value(config_keywords[i].keyword,
                                                config_keywords[i].variable,
                                                &p, ConfFile, linenum)) {
                                DPRINTF((D_PARSE|D_MEM), "found option %s, saved @%p\n", config_keywords[i].keyword, *config_keywords[i].variable);

                                /* special cases with multiple parameters */
                                if (!strcmp("tls_allow_fingerprints", config_keywords[i].keyword))
                                        credhead = &tls_opt.fprint_head;
                                else if (!strcmp("tls_allow_clientcerts", config_keywords[i].keyword))
                                        credhead = &tls_opt.cert_head;

                                if (credhead) do {
                                        if(!(cred = malloc(sizeof(*cred)))) {
                                                logerror("Unable to allocate memory");
                                                break;
                                        }
                                        cred->data = tmp_buf;
                                        tmp_buf = NULL;
                                        SLIST_INSERT_HEAD(credhead, cred, entries);
                                } while /* additional values? */ (copy_config_value_word(&tmp_buf, &p));
                                credhead = NULL;
                                break;
                        }
                }
        }
        /* convert strings to integer values */
        if (global_memory_limit.configstring
         && !dehumanize_number(global_memory_limit.configstring, &global_memory_limit.numeric)) {
                if (setrlimit(RLIMIT_DATA,
                        &((struct rlimit) {global_memory_limit.numeric, global_memory_limit.numeric})) == -1)
                        logerror("Unable to setrlimit()");
        }
        for (i = 0; i < A_CNT(TypeInfo); i++) {
                if (!TypeInfo[i].queue_length_string
                 || dehumanize_number(TypeInfo[i].queue_length_string, &TypeInfo[i].queue_length) == -1)
                        TypeInfo[i].queue_length = strtol(TypeInfo[i].default_length_string, NULL, 10);
                if (!TypeInfo[i].queue_size_string
                 || dehumanize_number(TypeInfo[i].queue_size_string, &TypeInfo[i].queue_size) == -1)
                        TypeInfo[i].queue_size = strtol(TypeInfo[i].default_size_string, NULL, 10);
        }
        rewind(cf);
        linenum = 0;
#endif /* !DISABLE_TLS */

        /*
         *  Foreach line in the conf table, open that file.
         */
        f = NULL;
        strcpy(prog, "*");
        strcpy(host, "*");
        while (fgets(cline, sizeof(cline), cf) != NULL) {
                linenum++;
                found_keyword = false;
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

                for (i = 0; i < A_CNT(config_keywords); i++) {
                        if (!strncasecmp(p, config_keywords[i].keyword, strlen(config_keywords[i].keyword))) {
                                DPRINTF(D_PARSE, "skip cline %d with keyword %s\n", linenum, config_keywords[i].keyword);
                                found_keyword = true;
                        }
                }
                if (found_keyword)
                        continue;

                if (*p == '+' || *p == '-') {
                        host[0] = *p++;
                        while (isspace((unsigned char)*p))
                                p++;
                        if (*p == '\0' || *p == '*') {
                                strcpy(host, "*");
                                continue;
                        }
                        /* the +hostname expression will continue
                         * to use the LocalHostName, not the FQDN */
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
                cfline(linenum, cline, f, prog, host);
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
                        printf("%s: ", TypeInfo[f->f_type].name);
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
                        for (i = 0; i < finet->fd; i++) {
                                if (shutdown(finet[i+1].fd, SHUT_RD) < 0) {
                                        logerror("shutdown() failed");
                                        die(0, 0, NULL);
                                }
                        }
                } else
                        DPRINTF(D_NET, "Listening on inet and/or inet6 socket\n");
                DPRINTF(D_NET, "Sending on inet and/or inet6 socket\n");
        }

#ifndef DISABLE_TLS
        /* TLS setup -- after all local destinations opened  */
        DPRINTF(D_PARSE, "Parsed options: tls_ca: %s, tls_cadir: %s, "
                "tls_cert: %s, tls_key: %s, tls_verify: %s, "
                "bind: %s:%s, max. queue_lengths: %lld, %lld, %lld, "
                "max. queue_sizes: %lld, %lld, %lld\n",
                tls_opt.CAfile, tls_opt.CAdir, tls_opt.certfile,
                tls_opt.keyfile, tls_opt.x509verify, tls_opt.bindhost,
                tls_opt.bindport, TypeInfo[F_TLS].queue_length,
                TypeInfo[F_FILE].queue_length, TypeInfo[F_PIPE].queue_length,
                TypeInfo[F_TLS].queue_size, TypeInfo[F_FILE].queue_size,
                TypeInfo[F_PIPE].queue_size);
        SLIST_FOREACH(cred, &tls_opt.cert_head, entries) {
                DPRINTF(D_PARSE, "Accepting peer certificate from file: \"%s\"\n", cred->data);
        }
        SLIST_FOREACH(cred, &tls_opt.fprint_head, entries) {
                DPRINTF(D_PARSE, "Accepting peer certificate with fingerprint: \"%s\"\n", cred->data);
        }

        DPRINTF((D_NET|D_TLS), "Preparing sockets for TLS\n");
        TLS_Listen_Set = socksetup_tls(PF_UNSPEC, tls_opt.bindhost, tls_opt.bindport);

        for (f = Files; f; f = f->f_next) {
                if (f->f_type != F_TLS)
                        continue;
                if (!tls_connect(f->f_un.f_tls.tls_conn)) {
                        logerror("Unable to connect to TLS server %s", f->f_un.f_tls.tls_conn->hostname);
                        /* Reconnect after x seconds  */
                        schedule_event(&f->f_un.f_tls.tls_conn->event,
                                &((struct timeval){TLS_RECONNECT_SEC, 0}),
                                tls_reconnect, f->f_un.f_tls.tls_conn);
                }
        }
#endif /* !DISABLE_TLS */

        loginfo("restart");
        /*
         * Log a change in hostname, but only on a restart (we detect this
         * by checking to see if we're passed a kevent).
         */
        if (ev != NULL && strcmp(oldLocalHostName, LocalHostName) != 0)
                loginfo("host name changed, \"%s\" to \"%s\"",
                    oldLocalHostName, LocalHostName);
}

/*
 * Crack a configuration file line
 */
void
cfline(const unsigned int linenum, char *line, struct filed *f, char *prog, char *host)
{
        struct addrinfo hints, *res;
        int    error, i, pri, syncfile;
        char   *bp, *p, *q;
        char   buf[MAXLINE];

        DPRINTF((D_CALL|D_PARSE), "cfline(%d, \"%s\", f, \"%s\", \"%s\")\n", linenum, line, prog, host);

        errno = 0;      /* keep strerror() stuff out of logerror messages */

        /* clear out file entry */
        memset(f, 0, sizeof(*f));
        for (i = 0; i <= LOG_NFACILITIES; i++)
                f->f_pmask[i] = INTERNAL_NOPRI;
        f->f_qhead = ((struct buf_queue_head)
                        TAILQ_HEAD_INITIALIZER(f->f_qhead));
        TAILQ_INIT(&f->f_qhead); 
        
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
                trim_anydomain(f->f_host);
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
                                logerror("Unable to parse action %s", p);
                                break;
                        }
                        f->f_type = F_TLS;
                        break;
                }
#endif /* !DISABLE_TLS */
                (void)strlcpy(f->f_un.f_forw.f_hname, ++p,
                    sizeof(f->f_un.f_forw.f_hname));
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_protocol = 0;
                error = getaddrinfo(f->f_un.f_forw.f_hname, "syslog", &hints,
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
                DPRINTF(D_MISC, "Couldn't get kern.msgbufsize\n");
                return (0);
        }
        return (msgbufsize);
#else
        return 16368;  /* value on my NetBSD/i386 */
#endif /* !_NO_NETBSD_USR_SRC_ */
}

/*
 * Retrieve the hostname, via sysctl.
 */
char *
getLocalFQDN(void)
{
        int mib[2];
        char *hostname;
        size_t len;

        mib[0] = CTL_KERN;
        mib[1] = KERN_HOSTNAME;
        sysctl(mib, 2, NULL, &len, NULL, 0);

        if (!(hostname = malloc(len))) {
                logerror("Unable to allocate memory");
                die(0,0,NULL);
        } else if (sysctl(mib, 2, hostname, &len, NULL, 0) == -1) {
                        DPRINTF(D_MISC, "Couldn't get kern.hostname\n");
                        (void)gethostname(hostname, sizeof(len));
        }
        return hostname;
}

struct socketEvent *
socksetup(int af, const char *hostname)
{
        struct addrinfo hints, *res, *r;
        int error, maxs;
        const int on = 1;
        struct socketEvent *s, *socks;

        if(SecureMode && !NumForwards)
                return(NULL);

        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_PASSIVE;
        hints.ai_family = af;
        hints.ai_socktype = SOCK_DGRAM;
        error = getaddrinfo(hostname, "syslog", &hints, &res);
        if (error) {
                logerror(gai_strerror(error));
                errno = 0;
                die(0, 0, NULL);
        }

        /* Count max number of sockets we may open */
        for (maxs = 0, r = res; r; r = r->ai_next, maxs++)
                continue;
        socks = malloc((maxs+1) * sizeof(*socks));
        if (!socks) {
                logerror("Couldn't allocate memory for sockets");
                die(0, 0, NULL);
        }

        socks->fd = 0;   /* num of sockets counter at start of array */
        s = socks + 1;
        for (r = res; r; r = r->ai_next) {
                s->fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
                if (s->fd < 0) {
                        logerror("socket() failed");
                        continue;
                }
                if (r->ai_family == AF_INET6 && setsockopt(s->fd, IPPROTO_IPV6,
                    IPV6_V6ONLY, &on, sizeof(on)) < 0) {
                        logerror("setsockopt(IPV6_V6ONLY) failed");
                        close(s->fd);
                        continue;
                }

                if (!SecureMode) {
                        if (bind(s->fd, r->ai_addr, r->ai_addrlen) < 0) {
                                logerror("bind() failed");
                                close(s->fd);
                                continue;
                        } else {
                                s->ev = allocev();
                                event_set(s->ev, s->fd, EV_READ | EV_PERSIST, dispatch_read_finet, s->ev);
                                if (event_add(s->ev, NULL) == -1) {
                                        DPRINTF((D_EVENT|D_NET), "Failure in event_add()\n");
                                } else {
                                        DPRINTF((D_EVENT|D_NET), "Listen on UDP port\n");
                                }
                        }
                }

                socks->fd = socks->fd + 1;  /* num counter */
                s++;
        }

        if (socks->fd == 0) {
                free (socks);
                if(Debug)
                        return(NULL);
                else
                        die(0, 0, NULL);
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

struct event *
allocev(void)
{
        struct event *ev;

        if (!(ev = malloc(sizeof(*ev))))
                logerror("Unable to allocate memory");
        return ev;
}

/* 
 * seems like event_once uses always the same event object
 * and cannot be used for different timers (?)
 * 
 * *ev is allocated if necessary
 */
void 
schedule_event(struct event **ev, struct timeval *tv, void (*cb)(int, short, void *), void *arg)
{
        if (!*ev && !(*ev = allocev())) {
                return;
        }
        event_set(*ev, 0, 0, cb, arg);
        if (event_add(*ev, tv) == -1) {
                DPRINTF(D_EVENT, "Failure in event_add()\n");
        }
}

/* abbreviation for freeing credential lists */
void
free_cred_SLIST(struct peer_cred_head *head)
{
        struct peer_cred *cred;
        
        while (!SLIST_EMPTY(head)) {
                cred = SLIST_FIRST(head);
                SLIST_REMOVE_HEAD(head, entries);
                FREEPTR(cred->data);
                free(cred);
        }
}

/* 
 * send message queue after reconnect 
 */
void
send_queue(struct filed *f)
{
        struct buf_queue *qentry;
        
        DPRINTF((D_DATA|D_CALL), "send_queue(f@%p with %d msgs)\n",
                f, f->f_qelements);
        TAILQ_FOREACH(qentry, &f->f_qhead, entries) {
                DPRINTF((D_DATA|D_CALL), "send_queue() calls fprintlog()\n");
                fprintlog(f, qentry->msg, qentry);
        }
}

/* 
 * finds the next queue element to delete
 * 
 * has stateful behaviour, before using it call once with reset = true
 * after that every call will return one next queue elemen to delete,
 * depending on strategy either the oldest or the one with the lowest priority
 */
static struct buf_queue *
find_qentry_to_delete(const struct buf_queue_head *head, const int strategy, const bool reset)
{
        static int pri;
        static struct buf_queue *qentry_static;
 
        struct buf_queue *qentry_tmp;
 
        if (reset || TAILQ_EMPTY(head)) {
                pri = LOG_DEBUG;
                qentry_static = TAILQ_FIRST(head);
                return NULL;
        }

        /* find elements to delete */
        if (strategy == PURGE_BY_PRIORITY) {
                qentry_tmp = qentry_static;
                while ((qentry_tmp = TAILQ_NEXT(qentry_tmp, entries))) {
                        if (LOG_PRI(qentry_tmp->msg->pri) == pri) {
                                /* save the successor, because qentry_tmp
                                 * is probably deleted by the caller */
                                qentry_static = TAILQ_NEXT(qentry_tmp, entries);
                                return qentry_tmp;
                        }
                }
                /* nothing found in while loop --> next pri */
                if (--pri)
                        return find_qentry_to_delete(head, strategy, false);
                else
                        return NULL;
        } else /* strategy == PURGE_OLDEST or other value */ {
                qentry_tmp = qentry_static;
                qentry_static = TAILQ_NEXT(qentry_tmp, entries);
                return qentry_tmp;  /* is NULL on empty queue */
        }
}

/* note on TAILQ: newest message added at TAIL,
 *                oldest to be removed is FIRST
 */
/*
 * checks length of a destination's message queue
 * if del_entries == 0 then assert queue length is
 *   less or equal to configured number of queue elements
 * otherwise del_entries tells how many entries to delete
 * 
 * returns the number of removed queue elements
 * (which not necessarily means free'd messages)
 * 
 * strategy PURGE_OLDEST to delete oldest entry, e.g. after it was resent
 * strategy PURGE_BY_PRIORITY to delete messages with lowest priority first,
 *      this is much slower but might be desirable when unsent messages have
 *      to be deleted, e.g. in call from domark() 
 */
unsigned int
message_queue_purge(struct filed *f, const unsigned int del_entries, const int strategy)
{
        int removed = 0;
        struct buf_queue *qentry = NULL;

        DPRINTF((D_CALL|D_BUFFER), "purge_message_queue(%p, %d, %d) with "
                "f_qelements=%d and f_qsize=%d\n",
                f, del_entries, strategy,
                f->f_qelements, f->f_qsize);

        (void)find_qentry_to_delete(&f->f_qhead, strategy, true);

        while (removed < del_entries
          || (TypeInfo[f->f_type].queue_length != -1
              && TypeInfo[f->f_type].queue_length > f->f_qelements)
          || (TypeInfo[f->f_type].queue_size != -1
              && TypeInfo[f->f_type].queue_size > f->f_qsize)) {
                qentry = find_qentry_to_delete(&f->f_qhead, strategy, 0);
                if (message_queue_remove(f, qentry))
                        removed++;
                else
                        break;
        }

        DPRINTF(D_BUFFER, "removed %d entries\n", removed);
        return removed;
}

struct buf_msg *
buf_msg_new(const size_t len)
{
        struct buf_msg *newbuf;

        MALLOC(newbuf, sizeof(*newbuf));
        memset(newbuf, 0, sizeof(*newbuf));

        if (len) {/* len = 0 is valid */         
                if (!(newbuf->msg = malloc(len))) {
                        logerror("Couldn't allocate new message buffer");
                } else {
                        newbuf->msgorig = newbuf->msg;
                        newbuf->msgsize = len;
                }
        }
        return NEWREF(newbuf);
}

void
buf_msg_free(struct buf_msg *buf)
{
        if (!buf)
                return;

        buf->refcount--;
        if (!buf->refcount) {
                /* small optimization: the host/recvhost may point to the
                 * global HostName/FQDN. of course this must not be free()d */
                if (buf->recvhost != LocalHostName && buf->recvhost != LocalFQDN)
                        FREEPTR(buf->recvhost);
                if (buf->host != LocalHostName && buf->host != LocalFQDN)
                        FREEPTR(buf->host);
                FREEPTR(buf->msgorig);  /* instead of msg */
                FREEPTR(buf->sd);
                FREEPTR(buf->timestamp);
                FREEPTR(buf->line);
                FREEPTR(buf);
        }
}

bool
message_queue_remove(struct filed *f, struct buf_queue *qentry)
{
        if (!f || !qentry)
                return false;

        TAILQ_REMOVE(&f->f_qhead, qentry, entries);
        f->f_qelements--;
        f->f_qsize -= sizeof(*qentry)
                      + sizeof(*qentry->msg)
                      + qentry->msg->msgsize
                      + qentry->msg->linelen
                      + SAFEstrlen(qentry->msg->timestamp)
                      + SAFEstrlen(qentry->msg->prog)
                      + SAFEstrlen(qentry->msg->pid)
                      + SAFEstrlen(qentry->msg->msgid);
        if (qentry->msg->recvhost
         && qentry->msg->recvhost != LocalHostName
         && qentry->msg->recvhost != LocalFQDN)
                f->f_qsize -= strlen(qentry->msg->recvhost);
        if (qentry->msg->host
         && qentry->msg->host != LocalHostName
         && qentry->msg->host != LocalFQDN)
                f->f_qsize -= strlen(qentry->msg->host);
        DELREF(qentry->msg);
        FREEPTR(qentry);
        return true;
}

bool
message_queue_add(struct filed *f, struct buf_msg *buffer)
{
        struct buf_queue *qentry;
        
        while (!(qentry = malloc(sizeof(*qentry)))
              && message_queue_purge(f, 1, PURGE_OLDEST))
             /* try allocating memory */;
        if (!qentry) {
                logerror("Unable to allocate memory");
                DPRINTF(D_BUFFER, "queue empty, no memory, msg dropped\n");
                return false;
        } else {
                qentry->msg = buffer;
                f->f_qelements++;
                f->f_qsize += sizeof(*qentry)
                              + sizeof(*qentry->msg)
                              + qentry->msg->msgsize
                              + qentry->msg->linelen
                              + SAFEstrlen(qentry->msg->timestamp)
                              + SAFEstrlen(qentry->msg->prog)
                              + SAFEstrlen(qentry->msg->pid)
                              + SAFEstrlen(qentry->msg->msgid);
                if (qentry->msg->recvhost
                 && qentry->msg->recvhost != LocalHostName
                 && qentry->msg->recvhost != LocalFQDN)
                        f->f_qsize += strlen(qentry->msg->recvhost);
                if (qentry->msg->host
                 && qentry->msg->host != LocalHostName
                 && qentry->msg->host != LocalFQDN)
                        f->f_qsize += strlen(qentry->msg->host);
                TAILQ_INSERT_TAIL(&f->f_qhead, qentry, entries);
                DPRINTF(D_BUFFER, "msg queued\n");
                return true;
        }
}

void
message_queue_freeall(struct filed *f)
{
        struct buf_queue *qentry;

        if (!f) return;
        DPRINTF(D_MEM, "message_queue_freeall(f@%p) with f_qhead@%p\n", f, &f->f_qhead);

        while (!TAILQ_EMPTY(&f->f_qhead)) {
                qentry = TAILQ_FIRST(&f->f_qhead);
                TAILQ_REMOVE(&f->f_qhead, qentry, entries);
                DELREF(qentry->msg);
                FREEPTR(qentry);                
        }

        f->f_qelements = 0;
        f->f_qsize = 0;
}

#ifndef DISABLE_TLS
/* utility function for tls_reconnect() */
struct filed *
get_f_by_conninfo(struct tls_conn_settings *conn_info)
{
        struct filed *f;

        for (f = Files; f; f = f->f_next) {
                if ((f->f_type == F_TLS)
                 && f->f_un.f_tls.tls_conn == conn_info)
                return f;
        }
        DPRINTF(D_TLS, "get_f_by_conninfo() called on invalid conn_info\n");
        return NULL;
}
#endif /* !DISABLE_TLS */

/*
 * return a timestamp in a static buffer
 * extended to format a timestamp given by parameter in_now
 * (no input parameter for tv -- would that be useful?)
 */
char *
make_timestamp(time_t *in_now, bool iso)
{
        const int frac_digits = 6;
        struct timeval tv;
        struct timeval *tvptr = NULL;
        time_t mytime;
        struct tm *ltime;
        int len = 0;
        int tzlen = 0;
        /* uses global var: time_t now; */

        if (in_now) {
                mytime = *in_now;
                tvptr = NULL;
        } else {
                mytime = time(&now);
                tvptr = &tv;
        }

        if (!iso)
                return ctime(&mytime) + 4;
        if (tvptr)
                gettimeofday(tvptr, NULL);

        ltime = localtime(&mytime);
        len += strftime(timestamp, TIMESTAMPBUFSIZE, "%FT%T", ltime);

        if (tvptr) {
                snprintf(&(timestamp[len]), frac_digits+2, ".%.*ld", frac_digits, tvptr->tv_usec);
                len += frac_digits+1;
        }
        tzlen = strftime(&(timestamp[len]), TIMESTAMPBUFSIZE-len, "%z", ltime);
        len += tzlen;
        
        if (tzlen == 5) {
                /* strftime gives "+0200", but we need "+02:00" */ 
                timestamp[len+1] = timestamp[len];
                timestamp[len] = timestamp[len-1];
                timestamp[len-1] = timestamp[len-2];
                timestamp[len-2] = ':';
        }
        return timestamp;
}
