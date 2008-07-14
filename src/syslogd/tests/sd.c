/*
 * messages.c
 * send syslog test messages 
 *
 * Martin Schütte
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

char* messages[] = {
/* valid */
"[e]",
"[exampleSDID@0]",
"[exampleSDID@0] [exampleSDID@0]",   /* should match only first [] */
"[exampleSDID@0 iut=\"\"]",
"[exampleSDID@0 iut=\"3\"] hallo19",
"[exampleSDID@0 iut=\"3\"]",
"[exampleSDID@0 iut=\"3\" iut=\"32\"]",
"[exampleSDID@0 iut=\"3\" iut2=\"32\" iut3=\"32\"]",
"[exampleSDID@0 iut=\" 3 \"]",
"[exampleSDID@0 iut=\"\\\"3\"]",
"[exampleSDID@0 iut=\"\\\\[3\"]",
"[exampleSDID@0 iut=\"\\\\\\\\[3\"]",
"[exampleSDID@0 iut=\"\\] \"]",
"[exampleSDID@0 iut=\" [\\] \"]",
"[exampleSDID@0 iut=\" [iut=\\\"3\\\"\\] \"]",
"[exampleSDID@0 iut=\"3\\]\"]",
"[exampleSDID@0][exampleSDID@1]",
"[exampleSDID@0][exampleSDID@1][exampleSDID@3][exampleSDID@6]",
"[exampleSDID@0 iut=\"3\\\\\"]",
"[exampleSDID@0 iut=\"3\\\\\\\\\"]",
"[exampleSDID@0 iut=\"3\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"]",
"[exampleSDID@0 iut=\"\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\3\"]",
"[exampleSDID@0 iut=\"\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\3\"]",
"[exampleSDID@0 iut=\"\\\\\\ 3\"]",
"[exampleSDID@0 iut=\"\\3\" iut2=\"\\abc\"]",
"[exampleSDID@0 iut=\"3\\3\"]",
"[exampleSDID@0 iut=\" \\[\\] \"]",
"[exampleSDID@0 iut=\"\\[3\"]",
NULL,
/* not valid */
"[]",
"[ ]",
"[exampleSDID@0 ]",
"[ exampleSDID@0]",
"[ exampleSDID@0 ]",
"[exampleSDID@0 iut]",
"[exampleSDID@0 iut=\"]",
"[exampleSDID@0 iut=\"3]",
"[exampleSDID@0 iut=\"3\"\"]",
"[exampleSDID@0 iut=\"3]\"]",
"[exampleSDID@0 iut=\"3\\",
"[exampleSDID@0 iut=\"3\\\\\\\"]",
"[exampleSDID@0 iut=\"3\\\\\\\\\\\"]",
NULL,
};

/* following syslog-protocol */
#define sdname(ch) (ch != '=' && ch != ' ' && ch != ']' && ch != '"' && ch >= 33 && ch <= 126)
/* 
 * returns number of chars found in SD at beginning of string p
 * thus returns 0 if no valid SD is found
 */
unsigned
check_sd(const char* p)
{
        const char *q = p;
        bool esc = false;
        while (/*CONSTCOND*/1) { /* SD-ELEMENT */
                if (*q++ != '[') return 0;
                /* SD-ID */
                if (!sdname(*q)) return 0;
                while (sdname(*q)) q++;
                while (/*CONSTCOND*/1) { /* SD-PARAM */
                        if (*q == ']') {
                                q++;
                                if (*q == ' ' || *q == '\0') return q-p;
                                else if (*q == '[') break;
                        } else if (*q++ != ' ') return 0;

                        /* PARAM-NAME */
                        if (!sdname(*q)) return 0;
                        while (sdname(*q)) q++;

                        if (*q++ != '=') return 0;
                        if (*q++ != '"') return 0;

                        /* PARAM-VALUE */
                        while (/*CONSTCOND*/1) {
                                if (esc) {
                                        esc = false;
                                        if (*q == '\\'
                                         || *q == '"'
                                         || *q == ']') {
                                                q++;
                                                continue;
                                        }
                                        /* no else because invalid
                                         * escape sequences are accepted */
                                }
                                else if (*q == '"') break;
                                else if (*q == '\0' || *q == ']') return 0;
                                else if (*q == '\\') esc = true;
                                q++;
                        }
                        q++;
                }
        }
}

int
main()
{
        unsigned i, rc;
        
        for (i = 0; messages[i]; i++) {
                rc = check_sd(messages[i]);
                if (!rc) 
                        printf("FAIL - false negative on:   %s\n", messages[i]);
                else
                        printf("PASS - correct positive on: %.*s\n", rc, messages[i]);
        }
        for (i++; messages[i]; i++) {
                rc = check_sd(messages[i]);
                if (rc) 
                        printf("FAIL - false positive on:   %.*s\n", rc, messages[i]);
                else
                        printf("PASS - correct negative on: %s\n", messages[i]);
        }
        
}
