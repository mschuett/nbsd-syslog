/*
 * bpg.c
 * holds all functions copied from the BPG project
 * to use OpenPGP MPI encoding in syslog-sign
 */
/*
 * Copyright (c) 2005 Manuel Freire.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "bpg.h"

/* Push a multi precission integer at the end of the buffer. */
void
push_mpi(BPG_BUF *buf, BIGNUM *bn)
{
	int bnlen;
	unsigned char *ptr;

	bnlen = BN_num_bytes(bn);
	if (BPG_BUF_resize(buf, buf->len + 2 + bnlen) == -1)
		return;		/* TODO: this resize can be optimized */
	ptr = &buf->body[buf->len - 2 - bnlen];

	/* MPI = len in bits (big-endian) + BIGNUM */
	ptr[0] = (bnlen * 8) >> 8;
	ptr[1] = (bnlen * 8) & 0xff;
	BN_bn2bin(bn, &ptr[2]);
}

/* Allocate a new buffer. */
BPG_BUF *
BPG_BUF_new(size_t len)
{
	BPG_BUF *buf;

	if ((buf = malloc(sizeof(BPG_BUF))) == NULL)
		return NULL;

	buf->body = NULL;
	BPG_BUF_resize(buf, len);
	buf->pos = 0;

	return buf;
}

/* Free a buffer. */
void
BPG_BUF_free(BPG_BUF *buf)
{
	if (buf != NULL) {
		if (buf->body != NULL)
			free(buf->body);
		free(buf);
	}
}


/* Reallocate buffer.  Buffer lenght is set to `len'. */
int
BPG_BUF_resize(BPG_BUF *buf, size_t len)
{
	if (buf == NULL) {
		return -1;
	}
	if (len < 0) {
		return -1;
	}
	if (len)
		if ((buf->body = realloc(buf->body, len)) == NULL) {
			return -1;
		}
	buf->len = len;
	return 0;
}
