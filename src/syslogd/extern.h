/*
 * extern.h
 * 
 * declarations for variables and functions from syslogd.c
 * that are used in tls.c and sign.c 
 */
#ifndef EXTERN_H_
#define EXTERN_H_


/* variables */
extern short int Debug;
extern struct tls_global_options_t tls_opt;
extern struct TLS_Incoming TLS_Incoming_Head;
extern struct sign_global_t GlobalSign;
extern char  *linebuf;
extern size_t linebufsize;
extern int    RemoteAddDate; 

extern bool     BSDOutputFormat;
extern unsigned GlobalMsgCounter;
extern time_t   now;
extern char     timestamp[];
extern char     appname[];
extern char    *LocalFQDN;
extern char    *include_pid;

/* functions */
extern void     logerror(const char *, ...);
extern void     loginfo(const char *, ...);
extern void     parseline(char *, char *, int);
extern void     die(int fd, short event, void *ev);
extern struct event *allocev(void);
extern void     send_queue(int __unused, short __unused, void *);
extern void     schedule_event(struct event **, struct timeval *,
                                void (*)(int, short, void *), void *);
extern char    *make_timestamp(time_t *, bool);
extern struct filed *get_f_by_conninfo(struct tls_conn_settings *conn_info);
extern bool     message_queue_remove(struct filed *, struct buf_queue *);
extern void     buf_msg_free(struct buf_msg *msg);
extern void     message_queue_freeall(struct filed *);
extern bool     copy_string(char **, const char *, const char *);
extern bool     copy_config_value_quoted(const char *, char **, char **);
extern unsigned message_allqueues_purge(void);
extern bool  format_buffer(struct buf_msg*, char**, size_t*, size_t*, size_t*, size_t*);
extern void  fprintlog(struct filed *, struct buf_msg *, struct buf_queue *);
extern struct buf_msg 
            *buf_msg_new(const size_t);

#endif /*EXTERN_H_*/
