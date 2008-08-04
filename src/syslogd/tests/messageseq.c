/*
 * messageseq.c
 * send sequence of syslog test messages 
 *
 * Martin Schütte
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syslog.h>
#include <errno.h>

int
main()
{
        const int num = 50;
        char buf[128];
        int j = 0;

        setvbuf(stdout, NULL, _IONBF, 0);
        for (int h = 0; h < 192; h++) {
                openlog("test", LOG_PID, h);
                if (h % 8 == 0) printf("\n%d\t", h/8);
                for (int i = 0; i < num; i++) {
                        snprintf(buf, sizeof(buf), "msg%d", i);
                        syslog(i % 8, "%s", buf);
                        if (i % 20 == 0 && j) {
                                /* create some repeated lines */
                                i--; j--;
                                printf(".");
                        }
                        if (i % 20 == 0 && !j) {
                                j = 3;
                        }
                }
                printf(" ");
                closelog();
        }
        printf("\n");
        return 0;
}
