/*
 * mcrypt_port.c: mcrypt wrapper port
 *
 * Copyright (c) 2005-2008 Tatsuya BIZENN, All rights reserved.
 */
#include <stdlib.h>
#include "mcrypt_if.h"

typedef struct {
    ScmMcrypt *mcrypt;
    ScmPort   *remote;
    int        remoteClosed;
    int        ownerp;
    int      (*padding)(char*,int,int);
    int      (*unpadding)(char*,int,int);
    int        datasize;
    int        bufsize;
    char       buf[1];
} ScmMcryptCtx;

#define DEFAULT_BUFSIZE 8192

static ScmObj mcrypt_port_name(MCRYPT mcrypt, ScmPort *remote, int dir)
{
    char *algo = mcrypt_enc_get_algorithms_name(mcrypt);
    char *mode = mcrypt_enc_get_modes_name(mcrypt);
    ScmObj out = Scm_MakeOutputStringPort(TRUE);
    Scm_Printf(SCM_PORT(out), "[mcrypt(%s/%s) %s %S]",
	       algo, mode,
	       dir == SCM_PORT_INPUT ? "<-" : "->",
	       Scm_PortName(remote));
    free(algo);
    free(mode);
    SCM_RETURN(Scm_GetOutputStringUnsafe(SCM_PORT(out), 0));
}

static int padding_std(char *buf, int datasize, int blocksize)
{
    int len = ((datasize/blocksize)+1)*blocksize;
    int ch = len - datasize;
    memset(buf+datasize, ch, ch);
    return len;
}

static int unpadding_std(char *buf, int datasize, int blocksize)
{
    int bodysize = (datasize/blocksize)*blocksize;
    int len = (unsigned char)buf[bodysize-1];
    if (len > blocksize)
	return bodysize;
    return bodysize - len;
}

static int padding_1_0s(char *buf, int datasize, int blocksize)
{
    int len = ((datasize/blocksize)+1)*blocksize;
    buf[datasize++] = '\x80';
    memset(buf+datasize, '\0', len - datasize);
    return len;
}

static int unpadding_1_0s(char *buf, int datasize, int blocksize)
{
    int bodysize = (datasize/blocksize)*blocksize;
    char *p = &buf[bodysize-1];
    char *lim = &buf[bodysize-blocksize];

    while ((p>=lim) && (*p-- == '\0')) {
	if (*p == '\x80')
	    return p - buf;
    }

    return bodysize;		       /* MAYBE ERROR */
}

static int padding_char(char *buf, int datasize, int blocksize, char ch)
{
    int len = ((datasize/blocksize)+1)*blocksize;
    memset(buf+datasize, ch, len - datasize);
    return len;
}
static int unpadding_char(char *buf, int datasize, int blocksize, char ch)
{
    int bodysize = (datasize/blocksize)*blocksize;
    char *p = &buf[bodysize-1];
    char *lim = &buf[bodysize-blocksize];

    while ((p>=lim) && (*p-- == ch))
	; /* SKIP IT */
    return p - buf + 1;
}

static int padding_space(char *buf, int datasize, int blocksize)
{
    return padding_char(buf, datasize, blocksize, ' ');
}

static int unpadding_space(char *buf, int datasize, int blocksize)
{
    return unpadding_char(buf, datasize, blocksize, ' ');
}

static int padding_null(char *buf, int datasize, int blocksize)
{
    return padding_char(buf, datasize, blocksize, '\0');
}

static int unpadding_null(char *buf, int datasize, int blocksize)
{
    return unpadding_char(buf, datasize, blocksize, '\0');
}

static ScmMcryptCtx *create_ScmMcryptCtx(ScmMcrypt *mcrypt, ScmPort *remote,
					 int padding_mode, int bufsize, int ownerp)
{
    ScmMcryptCtx *ctx = NULL;
    SCM_ASSERT(mcrypt != NULL);
    SCM_ASSERT(remote != NULL);
    SCM_ASSERT(bufsize > 2);
    if ((ctx = SCM_NEW_ATOMIC2(ScmMcryptCtx*, sizeof(ScmMcryptCtx)+bufsize - 1)) == NULL)
	Scm_Error("Cannot sufficient memory");
    ctx->mcrypt = mcrypt;
    ctx->remote = remote;
    ctx->remoteClosed = SCM_PORT_CLOSED_P(remote);
    ctx->ownerp = ownerp;
    ctx->datasize = 0;
    ctx->bufsize = bufsize;
    switch (padding_mode) {
	default: /* THROUGH to Standard */
	case PADDING_STD:
	    ctx->padding = padding_std;
	    ctx->unpadding = unpadding_std;
	    break;
	case PADDING_1_0s:
	    ctx->padding = padding_1_0s;
	    ctx->unpadding = unpadding_1_0s;
	    break;
	case PADDING_SPACE:
	    ctx->padding = padding_space;
	    ctx->unpadding = unpadding_space;
	    break;
	case PADDING_NULL:
	    ctx->padding = padding_null;
	    ctx->unpadding = unpadding_null;
	    break;
    }
    return ctx;
}

static int mcrypt_ready(ScmPort *p)
{
    ScmMcryptCtx *ctx = (ScmMcryptCtx*)p->src.buf.data;
    return Scm_CharReady(ctx->remote);
}

static int mcrypt_fileno(ScmPort *p)
{
    ScmMcryptCtx *ctx = (ScmMcryptCtx*)p->src.buf.data;
    return Scm_PortFileNo(ctx->remote);
}

static void mcrypt_closer(ScmPort *p)
{
    ScmMcryptCtx *ctx = (ScmMcryptCtx*)p->src.buf.data;
    MCRYPT mcrypt = SCM_MCRYPT_MCRYPT(ctx->mcrypt);
    if (SCM_OPORTP(ctx->remote) && (!SCM_PORT_CLOSED_P(ctx->remote)) && (!ctx->datasize)) {
	ctx->datasize = ctx->padding(ctx->buf, 0, mcrypt_enc_get_block_size(mcrypt));
	mcrypt_generic(mcrypt, ctx->buf, ctx->datasize);
	Scm_Putz(ctx->buf, ctx->datasize, ctx->remote);
    }
    if (ctx->ownerp) {
	Scm_ClosePort(ctx->remote);
	ctx->remoteClosed = TRUE;
    }
}

static int mcrypt_decryption_filler(ScmPort *p, int cnt)
{
    ScmMcryptCtx *ctx = (ScmMcryptCtx*)p->src.buf.data;
    MCRYPT mcrypt = SCM_MCRYPT_MCRYPT(ctx->mcrypt);
    int bs = mcrypt_enc_get_block_size(mcrypt);
    char *ptr = p->src.buf.end;
    int nread, len;
    while (cnt > 0) {
	if ((nread = Scm_Getz(ctx->buf+ctx->datasize, ctx->bufsize-ctx->datasize, ctx->remote)) <= 0) {
	    if (ctx->datasize < bs)
		break;
	    len = (ctx->datasize/bs)*bs;
	    mdecrypt_generic(mcrypt, ctx->buf, len);
	    ctx->datasize -= len;
	    len = ctx->unpadding(ctx->buf, len, bs);
	    memcpy(ptr, ctx->buf, len);
	    ptr += len;
	    cnt -= len;
	} else { /* nread > 0 */
	    ctx->datasize += nread;
	    len = (ctx->datasize/bs-1)*bs;
	    if (len < bs)
		continue;
	    mdecrypt_generic(mcrypt, ctx->buf, len);
	    memcpy(ptr, ctx->buf, len);
	    ptr += len;
	    ctx->datasize -= len;
	    memmove(ctx->buf, ctx->buf+len, ctx->datasize);
	    cnt -= len;
	}
    }
    return ptr - p->src.buf.end;
}

static int mcrypt_encryption_flusher(ScmPort *p, int cnt, int forcep)
{
    ScmMcryptCtx *ctx = (ScmMcryptCtx*)p->src.buf.data;
    MCRYPT mcrypt = SCM_MCRYPT_MCRYPT(ctx->mcrypt);
    int bs = mcrypt_enc_get_block_size(mcrypt);

    if (forcep) {
	memcpy(ctx->buf, p->src.buf.buffer, cnt);
	ctx->datasize = ctx->padding(ctx->buf, cnt, bs);
    } else {
	ctx->datasize = (cnt / bs ) * bs;
	memcpy(ctx->buf, p->src.buf.buffer, ctx->datasize);
    }
    mcrypt_generic(mcrypt, ctx->buf, ctx->datasize);
    Scm_Putz(ctx->buf, ctx->datasize, ctx->remote);

    return ctx->datasize;
}

ScmObj Scm_MakeInputDecryptionPort(ScmPort *fromPort,
				   ScmMcrypt *mcrypt,
				   int padding_mode,
				   int bufsize, int ownerp)
{
    ScmMcryptCtx *ctx;
    ScmPortBuffer bufrec = {0};
    MCRYPT m;
    int    bs;

    m = SCM_MCRYPT_MCRYPT(mcrypt);
    bs = mcrypt_enc_get_block_size(m);
    if (bufsize <= 0)
	bufsize = DEFAULT_BUFSIZE;
    else if (bufsize < bs*2)
	bufsize = bs*2;
    if ((ctx = create_ScmMcryptCtx(mcrypt, fromPort, padding_mode, bufsize, ownerp)) == NULL)
	Scm_Error("Cannot create mcrypt context object");
    bufrec.size = bufsize;
    bufrec.buffer = SCM_NEW_ATOMIC2(char*, bufrec.size);
    bufrec.mode = SCM_PORT_BUFFER_FULL;
    bufrec.filler = mcrypt_decryption_filler;
    bufrec.flusher = NULL;
    bufrec.closer = mcrypt_closer;
    bufrec.ready = mcrypt_ready;
    bufrec.filenum = mcrypt_fileno;
    bufrec.data = (void*)ctx;
    SCM_RETURN(Scm_MakeBufferedPort(SCM_CLASS_PORT, mcrypt_port_name(m, fromPort, SCM_PORT_INPUT),
				    SCM_PORT_INPUT, TRUE, &bufrec));
}

ScmObj Scm_MakeOutputEncryptionPort(ScmPort *toPort,
				    ScmMcrypt *mcrypt,
				    int padding_mode,
				    int bufsize, int ownerp)
{
    ScmMcryptCtx *ctx;
    ScmPortBuffer bufrec = {0};
    MCRYPT m;
    int    bs;

    m = SCM_MCRYPT_MCRYPT(mcrypt);
    bs = mcrypt_enc_get_block_size(m);
    if (bufsize <= 0)
	bufsize = DEFAULT_BUFSIZE;
    else if (bufsize < bs*2)
	bufsize = bs*2;
    if ((ctx = create_ScmMcryptCtx(mcrypt, toPort, padding_mode, ((bufsize/bs)+1)*bs, ownerp)) == NULL)
	Scm_Error("Cannot create mcrypt context object");
    bufrec.size = bufsize;
    bufrec.buffer = SCM_NEW_ATOMIC2(char*, bufrec.size);
    bufrec.mode = SCM_PORT_BUFFER_FULL;
    bufrec.filler = NULL;
    bufrec.flusher = mcrypt_encryption_flusher;
    bufrec.closer = mcrypt_closer;
    bufrec.ready = mcrypt_ready;
    bufrec.filenum = mcrypt_fileno;
    bufrec.data = (void*)ctx;
    SCM_RETURN(Scm_MakeBufferedPort(SCM_CLASS_PORT, mcrypt_port_name(m, toPort, SCM_PORT_OUTPUT),
				    SCM_PORT_OUTPUT, TRUE, &bufrec));
}

/*
  Local Variables:
  mode: c++
  tab-width: 8
  End:
*/
