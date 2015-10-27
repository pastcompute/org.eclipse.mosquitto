/*
Copyright (c) 2009-2014 Roger Light <roger@atchoo.org>

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

#include <assert.h>

#include <eecloud.h>
#include <logging_ecld.h>
#include <memory_ecld.h>
#include <net_ecld.h>
#include <read_handle.h>

int _eecloud_handle_connack(struct eecloud *ecld)
{
	uint8_t byte;
	uint8_t result;
	int rc;

	assert(ecld);
	_eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Client %s received CONNACK", ecld->id);
	rc = _eecloud_read_byte(&ecld->in_packet, &byte); // Reserved byte, not used
	if(rc) return rc;
	rc = _eecloud_read_byte(&ecld->in_packet, &result);
	if(rc) return rc;
	pthread_mutex_lock(&ecld->callback_mutex);
	if(ecld->on_connect){
		ecld->in_callback = true;
		ecld->on_connect(ecld, ecld->userdata, result);
		ecld->in_callback = false;
	}
	pthread_mutex_unlock(&ecld->callback_mutex);
	switch(result){
		case 0:
			if(ecld->state != ecld_cs_disconnecting){
				ecld->state = ecld_cs_connected;
			}
			return MOSQ_ERR_SUCCESS;
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
			return MOSQ_ERR_CONN_REFUSED;
		default:
			return MOSQ_ERR_PROTOCOL;
	}
}

