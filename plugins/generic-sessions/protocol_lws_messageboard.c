/*
 * ws protocol handler plugin for messageboard "generic sessions" demo
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation:
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301  USA
 */

#include "lwsgs.h"

struct per_vhost_data__gs_mb {
	struct lws_vhost *vh;
	const struct lws_protocols *gsp;
	sqlite3 *pdb;
	char message_db[256];
};

struct per_session_data__gs_mb {
	struct per_session_data__gs pss_gs;
	struct lws_session_info sinfo;
	struct lws_spa *spa;

	unsigned int our_form:1;
};

static const char * const param_names[] = {
	"send",
	"msg",
};

enum {
	MBSPA_SUBMIT,
	MBSPA_MSG,
};

static int
callback_messageboard(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	struct per_session_data__gs_mb *pss = (struct per_session_data__gs_mb *)user;
	const struct lws_protocol_vhost_options *pvo;
	struct per_vhost_data__gs_mb *vhd = (struct per_vhost_data__gs_mb *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	unsigned char *p, *start, *end, buffer[LWS_PRE + 256];
	char s[512];
	int n;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						  lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__gs));
		if (!vhd)
			return 1;
		vhd->vh = lws_get_vhost(wsi);

		vhd->gsp = lws_vhost_name_to_protocol(vhd->vh,
						"protocol-generic-sessions");

		if (!vhd->gsp) {
			lwsl_err("messageboard: requires generic-sessions\n");

			return 1;
		}

		pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			if (!strcmp(pvo->name, "message-db"))
				strncpy(vhd->message_db, pvo->value,
					sizeof(vhd->message_db) - 1);
			pvo = pvo->next;
		}
		if (!vhd->message_db[0]) {
			lwsl_err("messageboard: "
				 "You must give \"message-db\" per-vhost options\n");
			return 1;
		}

		if (sqlite3_open_v2(vhd->message_db, &vhd->pdb,
				    SQLITE_OPEN_READWRITE |
				    SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
			lwsl_err("Unable to open message db %s: %s\n",
				 vhd->message_db, sqlite3_errmsg(vhd->pdb));

			return 1;
		}

		sprintf(s, "create table if not exists msg ("
				 " idx integer primary key,"
				 " time integer,"
				 " username varchar(32),"
				 " email varchar(100),"
				 " ip varchar(80),"
				 " content blob);");
		if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
			lwsl_err("Unable to create msg table: %s\n",
				 sqlite3_errmsg(vhd->pdb));

			return 1;
		}
		break;

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_notice("LWS_CALLBACK_ESTABLISHED: messageboard\n");
		vhd->gsp->callback(wsi, LWS_CALLBACK_SESSION_INFO,
				   &pss->pss_gs, &pss->sinfo, 0);

		lwsl_notice("messageboard: username=%s, email=%s, mask=%d, session=%s\n",
				pss->sinfo.username, pss->sinfo.email, pss->sinfo.mask,
				pss->sinfo.session);

		if (!pss->sinfo.username[0]) {
			lwsl_notice("messageboard ws attempt with no session\n");

			return -1;
		}




		break;

	case LWS_CALLBACK_HTTP:
		lwsl_notice("LWS_CALLBACK_HTTP: %s\n", in);

		pss->our_form = 0;

		/* ie, it's our messageboard new message form */
		if (!strcmp((const char *)in, "/msg")) {
			pss->our_form = 1;
			break;
		}

		goto passthru;

	case LWS_CALLBACK_HTTP_BODY:

		if (!pss->our_form)
			goto passthru;

		if (len < 2)
			break;

		if (!pss->spa) {
			pss->spa = lws_spa_create(wsi, param_names,
						ARRAY_SIZE(param_names), 1024,
						NULL, NULL);
			if (!pss->spa)
				return -1;
		}

		if (lws_spa_process(pss->spa, in, len)) {
			lwsl_notice("spa process blew\n");
			return -1;
		}
		break;
		goto passthru;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		if (!pss->our_form)
			goto passthru;

		lwsl_notice("messageboard submit '%s', msg '%s'\n",
				lws_spa_get_string(pss->spa, MBSPA_SUBMIT),
				lws_spa_get_string(pss->spa, MBSPA_MSG));

		p = buffer + LWS_PRE;
		start = p;
		end = p + sizeof(buffer) - LWS_PRE;

		if (lws_add_http_header_status(wsi, 200, &p, end))
			return -1;
		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
						 (unsigned char *)"text/plain", 10,
						 &p, end))
			return -1;

		if (lws_add_http_header_content_length(wsi, 1, &p, end))
			return -1;

		if (lws_finalize_http_header(wsi, &p, end))
			return -1;

		n = lws_write(wsi, start, p - start, LWS_WRITE_HTTP_HEADERS);
		if (n != (p - start)) {
			lwsl_err("_write returned %d from %d\n", n, (p - start));
			return -1;
		}
		n = lws_write(wsi, (unsigned char *)s, 1, LWS_WRITE_HTTP);
		if (n != 1)
			return -1;

		goto try_to_reuse;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		if (pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		goto passthru;

	default:
passthru:
		return vhd->gsp->callback(wsi, reason, &pss->pss_gs, in, len);
	}

	return 0;


try_to_reuse:
	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		"protocol-lws-messageboard",
		callback_messageboard,
		sizeof(struct per_session_data__gs_mb),
		1024,
	},
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_lws_messageboard(struct lws_context *context,
			       struct lws_plugin_capability *c)
{
	if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
		lwsl_err("Plugin API %d, library API %d", LWS_PLUGIN_API_MAGIC,
			 c->api_magic);
		return 1;
	}

	c->protocols = protocols;
	c->count_protocols = ARRAY_SIZE(protocols);
	c->extensions = NULL;
	c->count_extensions = 0;

	return 0;
}

LWS_EXTERN LWS_VISIBLE int
destroy_protocol_lws_messageboard(struct lws_context *context)
{
	return 0;
}
