/*
 * sd.c
 * test function check_sd() and check_msgid()
 *
 * Martin Schütte
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

char* sds[] = {
/* valid */
"-",
"- some message",
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

char* msgids[] = {
/* valid */
"- ",
"- some message",
"[e] ",
"msgid msg",
"msgid [sd]",
"msgidwithd123digits msg",
"123456789012345678901234567890 msg ",
"1234567890123456789012345678901 msg ",
"12345678901234567890123456789012 msg ",
NULL,
/* not valid */
"-",
"ab",
"[e]",
"\tab ",
"-\tab ",
"abcdë some",
"nomsgidbecauseoftoomanycharacters msg",
"123456789012345678901234567890123 msg ",
"1234567890123456789012345678901234 msg ",
NULL,
};

/* following syslog-protocol */
#define MSGID_MAX    32
#define printusascii(ch) (ch >= 33 && ch <= 126)
#define sdname(ch) (ch != '=' && ch != ' ' && ch != ']' && ch != '"' && printusascii(ch))

/* checks whether the first word of string p can be interpreted as
 * a syslog-protocol MSGID and if so returns its length.
 * 
 * otherwise returns 0
 */
static unsigned
check_msgid(char *p)
{
        char *q = p;
        
        /* consider the NILVALUE to be valid */
        if (*q == '-' && *(q+1) == ' ')
                return 1;

        while (/*CONSTCOND*/1) {
                if (*q == ' ')
                        return q - p;
                else if (*q == '\0'
                      || !printusascii(*q)
                      || q - p >= MSGID_MAX)
                        return 0;
                else
                        q++;
        }
}

/* 
 * returns number of chars found in SD at beginning of string p
 * thus returns 0 if no valid SD is found
 */
unsigned
check_sd(const char* p)
{
        const char *q = p;
        bool esc = false;
        
        /* consider the NILVALUE to be valid */
        if (*q == '-' && (*(q+1) == ' ' || *(q+1) == '\0'))
                return 1;
        
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
        
        for (i = 0; sds[i]; i++) {
                rc = check_sd(sds[i]);
                if (!rc) 
                        printf("FAIL - false negative   on: %s\n", sds[i]);
                else
                        printf("PASS - correct positive on: %.*s\n", rc, sds[i]);
        }
        for (i++; sds[i]; i++) {
                rc = check_sd(sds[i]);
                if (rc) 
                        printf("FAIL - false positive   on: %.*s\n", rc, sds[i]);
                else
                        printf("PASS - correct negative on: %s\n", sds[i]);
        }

        for (i = 0; msgids[i]; i++) {
                rc = check_msgid(msgids[i]);
                if (!rc) 
                        printf("FAIL - false negative   on: %s\n", msgids[i]);
                else
                        printf("PASS - correct positive on: %.*s\n", rc, msgids[i]);
        }
        for (i++; msgids[i]; i++) {
                rc = check_msgid(msgids[i]);
                if (rc) 
                        printf("FAIL - false positive   on: %.*s\n", rc, msgids[i]);
                else
                        printf("PASS - correct negative on: %s\n", msgids[i]);
        }
        
}
