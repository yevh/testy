/*-
 * Copyright (c) 2008 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/kobj.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sx.h>
#include <sys/ucred.h>

#include <rpc/rpc.h>
#include <rpc/rpc_com.h>
#include <rpc/rpcsec_gss.h>

#include <kgssapi/gssapi.h>
#include <kgssapi/gssapi_impl.h>

#include "rpcsec_gss_int.h"

#define	RPCSEC_GSS_MAXSEQ	0x80000000
#define	RPCSEC_GSS_WINDOW	128

#define	MAX_AUTH_BYTES	400
#define	RPCBUF_SIZE	128

static MALLOC_DEFINE(M_RPCSEC_GSS, "rpcsec_gss", "RPCSEC_GSS state");

struct svc_rpc_gss_cookedcred {
	struct svc_rpc_gss_client	*cc_client;
	rpc_gss_service_t		 cc_service;
	uint32_t			 cc_seq;
};

bool_t
svc_rpc_gss_validate(struct svc_req *rqst, struct rpc_msg *msg)
{
	struct opaque_auth	*oa;
	XDR			 xdrs;
	rpc_gss_cred_t		 gc;
	int32_t			 rpchdr[RPCBUF_SIZE / sizeof(int32_t)];
	int32_t			*buf;
	uint32_t		 verf_len;

	oa = &msg->rm_call.cb_cred;

	if (oa->oa_length > MAX_AUTH_BYTES)
		return (FALSE);

	buf = rpchdr;
	IXDR_PUT_INT32(buf, msg->rm_xid);
	IXDR_PUT_INT32(buf, msg->rm_direction);
	IXDR_PUT_INT32(buf, msg->rm_call.cb_rpcvers);
	IXDR_PUT_INT32(buf, msg->rm_call.cb_prog);
	IXDR_PUT_INT32(buf, msg->rm_call.cb_vers);
	IXDR_PUT_INT32(buf, msg->rm_call.cb_proc);
	IXDR_PUT_INT32(buf, oa->oa_flavor);
	IXDR_PUT_INT32(buf, oa->oa_length);

	memcpy(buf, oa->oa_base, oa->oa_length);

	xdrmem_create(&xdrs, (caddr_t)rpchdr, sizeof(rpchdr), XDR_DECODE);
	memset(&gc, 0, sizeof(gc));

	if (!xdr_rpc_gss_cred(&xdrs, &gc)) {
		XDR_DESTROY(&xdrs);
		return (FALSE);
	}
	XDR_DESTROY(&xdrs);

	rqst->rq_clntcred = (caddr_t)&gc;
	return (TRUE);
}

bool_t
svc_rpc_gss_nextverf(struct svc_req *rqst, u_int writelen)
{
	return (TRUE);
}

bool_t
svc_rpc_gss_checksum(struct svc_req *rqst, struct rpc_msg *msg)
{
	struct svc_rpc_gss_cookedcred	*cc;
	struct svc_rpc_gss_client	*client;
	gss_buffer_desc			 rpcbuf, checksum;
	OM_uint32			 maj_stat, min_stat;
	bool_t				 result;

	cc = rqst->rq_clntcred;
	client = cc->cc_client;

	rpcbuf.value = msg;
	rpcbuf.length = sizeof(*msg);

	maj_stat = gss_verify_mic(&min_stat, client->cl_ctx,
	    &rpcbuf, &checksum, NULL);

	if (maj_stat != GSS_S_COMPLETE) {
		rpc_gss_log_status("gss_verify_mic", client->cl_mech,
		    maj_stat, min_stat);
		return (FALSE);
	}

	return (TRUE);
}

bool_t
svc_rpc_gss_destroy(struct svc_req *rqst)
{
	struct svc_rpc_gss_cookedcred	*cc;

	cc = rqst->rq_clntcred;
	if (cc->cc_client)
		svc_rpc_gss_release_client(cc->cc_client);

	return (TRUE);
}

static void
svc_rpc_gss_timeout(void *arg)
{
	struct svc_rpc_gss_client	*client = arg;

	svc_rpc_gss_release_client(client);
}

int
svc_rpc_gss_init(void)
{
	return (0);
}

void
svc_rpc_gss_fini(void)
{
}
