/*
Copyright (c) 2013,2014 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/

#ifdef WITH_SRV
#  include <ares.h>

#  include <arpa/nameser.h>
#  include <stdio.h>
#  include <string.h>
#endif

#include "logging_ecld.h"
#include "memory_ecld.h"
#include "eecloud_internal.h"
#include "eecloud.h"

#ifdef WITH_SRV
static void srv_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen)
{   
	struct eecloud *ecld = arg;
	struct ares_srv_reply *reply = NULL;
	if(status == ARES_SUCCESS){
		status = ares_parse_srv_reply(abuf, alen, &reply);
		if(status == ARES_SUCCESS){
			// FIXME - choose which answer to use based on rfc2782 page 3. */
			eecloud_connect(ecld, reply->host, reply->port, ecld->keepalive);
		}
	}else{
		_eecloud_log_printf(ecld, ECLD_LOG_ERR, "Error: SRV lookup failed (%d).", status);
		/* FIXME - calling on_disconnect here isn't correct. */
		pthread_mutex_lock(&ecld->callback_mutex);
		if(ecld->on_disconnect){
			ecld->in_callback = true;
			ecld->on_disconnect(ecld, ecld->userdata, 2);
			ecld->in_callback = false;
		}
		pthread_mutex_unlock(&ecld->callback_mutex);
	}
}
#endif

int eecloud_connect_srv(struct eecloud *ecld, const char *host, int keepalive, const char *bind_address)
{
#ifdef WITH_SRV
	char *h;
	int rc;
	if(!ecld) return ECLD_ERR_INVAL;

	rc = ares_init(&ecld->achan);
	if(rc != ARES_SUCCESS){
		return ECLD_ERR_UNKNOWN;
	}

	if(!host){
		// get local domain
	}else{
#ifdef WITH_TLS
		if(ecld->tls_cafile || ecld->tls_capath || ecld->tls_psk){
			h = _eecloud_malloc(strlen(host) + strlen("_secure-mqtt._tcp.") + 1);
			if(!h) return ECLD_ERR_NOMEM;
			sprintf(h, "_secure-mqtt._tcp.%s", host);
		}else{
#endif
			h = _eecloud_malloc(strlen(host) + strlen("_mqtt._tcp.") + 1);
			if(!h) return ECLD_ERR_NOMEM;
			sprintf(h, "_mqtt._tcp.%s", host);
#ifdef WITH_TLS
		}
#endif
		ares_search(ecld->achan, h, ns_c_in, ns_t_srv, srv_callback, ecld);
		_eecloud_free(h);
	}

	pthread_mutex_lock(&ecld->state_mutex);
	ecld->state = ecld_cs_connect_srv;
	pthread_mutex_unlock(&ecld->state_mutex);

	ecld->keepalive = keepalive;

	return ECLD_ERR_SUCCESS;

#else
	return ECLD_ERR_NOT_SUPPORTED;
#endif
}


