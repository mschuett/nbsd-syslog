/*
 * utf8.c
 * test function valid_utf8()
 *
 * Martin Schütte
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/stdint.h>

/* 
 * checks UTF-8 codepoint
 * returns either its length in bytes or 0 if *input is invalid
 * 
 */
static unsigned
valid_utf8(const char *c) {
        unsigned rc, nb;

        /* first byte gives sequence length */
             if ((*c & 0x80) == 0x00) return 1; /* 0bbbbbbb -- ASCII */
        else if ((*c & 0xc0) == 0x80) return 0; /* 10bbbbbb -- trailing byte */
        else if ((*c & 0xe0) == 0xc0) nb = 2;   /* 110bbbbb */
        else if ((*c & 0xf0) == 0xe0) nb = 3;   /* 1110bbbb */
        else if ((*c & 0xf8) == 0xf0) nb = 4;   /* 11110bbb */
        else return 0; /* UTF-8 allows only up to 4 bytes */ 

        /* catch overlong encodings */
        if ((*c & 0xfe) == 0xc0)
                return 0; /* 1100000b ... */
        else if (((*c & 0xff) == 0xe0) && ((*(c+1) & 0xe0) == 0x80))
                return 0; /* 11100000 100bbbbb ... */
        else if (((*c & 0xff) == 0xf0) && ((*(c+1) & 0xf0) == 0x80))
                return 0; /* 11110000 1000bbbb ... ... */

        /* and also filter UTF-16 surrogates (=invalid in UTF-8) */
        if (((*c & 0xff) == 0xed) && ((*(c+1) & 0xe0) == 0xa0))
                return 0; /* 11101101 101bbbbb ... */

        rc = nb;
        /* check trailing bytes */
        switch (nb) {
        default: return 0;
        case 4: if ((*(c+3) & 0xc0) != 0x80) return 0;
        case 3: if ((*(c+2) & 0xc0) != 0x80) return 0;
        case 2: if ((*(c+1) & 0xc0) != 0x80) return 0;
        }
        return rc;
}

/* 
 * read UTF-8 value
 * returns a the codepoint number
 */
static uint_fast32_t
get_utf8_value(const char *c) {
        uint_fast32_t sum;
        unsigned nb, i;

        /* first byte gives sequence length */
             if ((*c & 0x80) == 0x00) return *c;/* 0bbbbbbb -- ASCII */
        else if ((*c & 0xc0) == 0x80) return 0; /* 10bbbbbb -- trailing byte */
        else if ((*c & 0xe0) == 0xc0) {         /* 110bbbbb */
                nb = 2;
                sum = (*c & ~0xe0) & 0xff;
        } else if ((*c & 0xf0) == 0xe0) {       /* 1110bbbb */
                nb = 3;
                sum = (*c & ~0xf0) & 0xff;
        } else if ((*c & 0xf8) == 0xf0) {       /* 11110bbb */
                nb = 4;
                sum = (*c & ~0xf8) & 0xff;
        } else return 0; /* UTF-8 allows only up to 4 bytes */

        /* check trailing bytes -- 10bbbbbb */
        i = 1;
        while (i < nb) {
                sum <<= 6;
                sum |= ((*(c+i) & ~0xc0) & 0xff);
                i++;
        }
        return sum;
}


/* many tests from
 * http://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
 */
char *inputs[] = {
/* return 0 */
"\xff",
"\x80",
"\xbf",
"\xc0",
"\xf4\x90\x80",  /* last byte missing */
"\xf8\x90\x80\x80\x80",  /* 5 bytes --> too long */
"\xed\x00\xbf",
"\xc0\x80",  /* overlong, = \0 */
/* overlong sequences */
"\xe0\x80\xaf",
"\xe0\x9f\xbf",
"\xe0\x9f\x80",
"\xf0\x80\x80\x80",  /* overlong, = \0 */
/* UTF-16 surrogates */
"\xed\xa0\x80",
"\xed\xaf\xbf",
NULL,
/* return 1 */
"a",
"0",
" ",
"\0",
NULL,
/* return 2 */
"é",
"ø",
"ñ",
"\xce\xb1",
NULL,
/* return 3 */
"€",
"ℵ",
"子",
"�",
"\xed\x9f\xbf",
"\xee\x80\x80",
"\xef\xbf\xbd",
NULL,
/* return 4 */
"\xf4\x8f\xbf\xbf",
"\xf4\x90\x80\x80",
NULL,
};

int
main()
{
        unsigned i, rc, rightrc;
        
        for (i = 0, rightrc = 0; rightrc <= 4; rightrc++, i++) {
                for (; inputs[i]; i++) {
                        //printf("rightrc %d, i %d\n", rightrc, i);
                        rc = valid_utf8(inputs[i]);
                        if (rc == rightrc) {
                                printf("PASS on: lenght %d for %.*s: ",
                                        rightrc, rightrc+1, inputs[i]);
                                for (int k = 0; k <= rightrc; k++) {
                                        printf("%02x", (unsigned char) (inputs[i][k] % 0xff));
                                }
                                printf(" U+%x\n", get_utf8_value(inputs[i]));
                        } else {
                                printf("FAIL on: lenght %d != %d for %.*s: ",
                                        rc, rightrc, rightrc+1, inputs[i]);
                                for (int k = 0; k <= rightrc; k++) {
                                        printf("%02x", (unsigned char) (inputs[i][k] % 0xff));
                                }
                                printf(" U+%x\n", get_utf8_value(inputs[i]));
                        }
                }
        }
}
