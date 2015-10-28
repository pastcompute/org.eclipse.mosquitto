/*
Copyright (c) 2011-2014 Roger Light <roger@atchoo.org>

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

#include <config.h>

#ifndef WIN32
#include <unistd.h>
#endif

#include <eecloud_internal.h>
#include <net_ecld.h>

void *_eecloud_thread_main(void *obj);

int eecloud_loop_start(struct eecloud *ecld)
{
#ifdef WITH_THREADING
	if(!ecld || ecld->threaded) return ECLD_ERR_INVAL;

	ecld->threaded = true;
	pthread_create(&ecld->thread_id, NULL, _eecloud_thread_main, ecld);
	return ECLD_ERR_SUCCESS;
#else
	return ECLD_ERR_NOT_SUPPORTED;
#endif
}

int eecloud_loop_stop(struct eecloud *ecld, bool force)
{
#ifdef WITH_THREADING
#  ifndef WITH_BROKER
	char sockpair_data = 0;
#  endif

	if(!ecld || !ecld->threaded) return ECLD_ERR_INVAL;


	/* Write a single byte to sockpairW (connected to sockpairR) to break out
	 * of select() if in threaded mode. */
	if(ecld->sockpairW != INVALID_SOCKET){
#ifndef WIN32
		if(write(ecld->sockpairW, &sockpair_data, 1)){
		}
#else
		send(ecld->sockpairW, &sockpair_data, 1, 0);
#endif
	}
	
	if(force){
		pthread_cancel(ecld->thread_id);
	}
	pthread_join(ecld->thread_id, NULL);
	ecld->thread_id = pthread_self();
	ecld->threaded = false;

	return ECLD_ERR_SUCCESS;
#else
	return ECLD_ERR_NOT_SUPPORTED;
#endif
}

#ifdef WITH_THREADING
void *_eecloud_thread_main(void *obj)
{
	struct eecloud *ecld = obj;

	if(!ecld) return NULL;

	pthread_mutex_lock(&ecld->state_mutex);
	if(ecld->state == ecld_cs_connect_async){
		pthread_mutex_unlock(&ecld->state_mutex);
		eecloud_reconnect(ecld);
	}else{
		pthread_mutex_unlock(&ecld->state_mutex);
	}

	if(!ecld->keepalive){
		/* Sleep for a day if keepalive disabled. */
		eecloud_loop_forever(ecld, ecld->keepalive*1000*86400, 1);
	}else{
		/* Sleep for our keepalive value. publish() etc. will wake us up. */
		eecloud_loop_forever(ecld, ecld->keepalive*1000, 1);
	}

	return obj;
}
#endif

int eecloud_threaded_set(struct eecloud *ecld, bool threaded)
{
	if(!ecld) return ECLD_ERR_INVAL;

	ecld->threaded = threaded;

	return ECLD_ERR_SUCCESS;
}
