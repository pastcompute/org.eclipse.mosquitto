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
#include <stdio.h>
#include <string.h>

#include <eecloud.h>
#include <logging_ecld.h>
#include <memory_ecld.h>
#include <messages_ecld.h>
#include <mqtt3_protocol.h>
#include <net_ecld.h>
#include <read_handle.h>
#include <send_ecld.h>
#include <util_ecld.h>
#ifdef WITH_BROKER
#include <eecloud_broker.h>
#endif

int _eecloud_handle_pingreq(struct eecloud *ecld)
{
	assert(ecld);
#ifdef WITH_BROKER
	_eecloud_log_printf(NULL, ECLD_LOG_DEBUG, "Received PINGREQ from %s", ecld->id);
#else
	_eecloud_log_printf(ecld, ECLD_LOG_DEBUG, "Client %s received PINGREQ", ecld->id);
#endif
	return _eecloud_send_pingresp(ecld);
}

int _eecloud_handle_pingresp(struct eecloud *ecld)
{
	assert(ecld);
	ecld->ping_t = 0; /* No longer waiting for a PINGRESP. */
#ifdef WITH_BROKER
	_eecloud_log_printf(NULL, ECLD_LOG_DEBUG, "Received PINGRESP from %s", ecld->id);
#else
	_eecloud_log_printf(ecld, ECLD_LOG_DEBUG, "Client %s received PINGRESP", ecld->id);
#endif
	return ECLD_ERR_SUCCESS;
}

#ifdef WITH_BROKER
int _eecloud_handle_pubackcomp(struct eecloud_db *db, struct eecloud *ecld, const char *type)
#else
int _eecloud_handle_pubackcomp(struct eecloud *ecld, const char *type)
#endif
{
	uint16_t mid;
	int rc;

	assert(ecld);
	rc = _eecloud_read_uint16(&ecld->in_packet, &mid);
	if(rc) return rc;
#ifdef WITH_BROKER
	_eecloud_log_printf(NULL, ECLD_LOG_DEBUG, "Received %s from %s (Mid: %d)", type, ecld->id, mid);

	if(mid){
		rc = mqtt3_db_message_delete(db, ecld, mid, ecld_md_out);
		if(rc) return rc;
	}
#else
	_eecloud_log_printf(ecld, ECLD_LOG_DEBUG, "Client %s received %s (Mid: %d)", ecld->id, type, mid);

	if(!_eecloud_message_delete(ecld, mid, ecld_md_out)){
		/* Only inform the client the message has been sent once. */
		pthread_mutex_lock(&ecld->callback_mutex);
		if(ecld->on_publish){
			ecld->in_callback = true;
			ecld->on_publish(ecld, ecld->userdata, mid);
			ecld->in_callback = false;
		}
		pthread_mutex_unlock(&ecld->callback_mutex);
	}
#endif

	return ECLD_ERR_SUCCESS;
}

int _eecloud_handle_pubrec(struct eecloud *ecld)
{
	uint16_t mid;
	int rc;

	assert(ecld);
	rc = _eecloud_read_uint16(&ecld->in_packet, &mid);
	if(rc) return rc;
#ifdef WITH_BROKER
	_eecloud_log_printf(NULL, ECLD_LOG_DEBUG, "Received PUBREC from %s (Mid: %d)", ecld->id, mid);

	rc = mqtt3_db_message_update(ecld, mid, ecld_md_out, ecld_ms_wait_for_pubcomp);
#else
	_eecloud_log_printf(ecld, ECLD_LOG_DEBUG, "Client %s received PUBREC (Mid: %d)", ecld->id, mid);

	rc = _eecloud_message_out_update(ecld, mid, ecld_ms_wait_for_pubcomp);
#endif
	if(rc) return rc;
	rc = _eecloud_send_pubrel(ecld, mid);
	if(rc) return rc;

	return ECLD_ERR_SUCCESS;
}

int _eecloud_handle_pubrel(struct eecloud_db *db, struct eecloud *ecld)
{
	uint16_t mid;
#ifndef WITH_BROKER
	struct eecloud_message_all *message = NULL;
#endif
	int rc;

	assert(ecld);
	if(ecld->protocol == ecld_p_mqtt311){
		if((ecld->in_packet.command&0x0F) != 0x02){
			return ECLD_ERR_PROTOCOL;
		}
	}
	rc = _eecloud_read_uint16(&ecld->in_packet, &mid);
	if(rc) return rc;
#ifdef WITH_BROKER
	_eecloud_log_printf(NULL, ECLD_LOG_DEBUG, "Received PUBREL from %s (Mid: %d)", ecld->id, mid);

	if(mqtt3_db_message_release(db, ecld, mid, ecld_md_in)){
		/* Message not found. Still send a PUBCOMP anyway because this could be
		 * due to a repeated PUBREL after a client has reconnected. */
	}
#else
	_eecloud_log_printf(ecld, ECLD_LOG_DEBUG, "Client %s received PUBREL (Mid: %d)", ecld->id, mid);

	if(!_eecloud_message_remove(ecld, mid, ecld_md_in, &message)){
		/* Only pass the message on if we have removed it from the queue - this
		 * prevents multiple callbacks for the same message. */
		pthread_mutex_lock(&ecld->callback_mutex);
		if(ecld->on_message){
			ecld->in_callback = true;
			ecld->on_message(ecld, ecld->userdata, &message->msg);
			ecld->in_callback = false;
		}
		pthread_mutex_unlock(&ecld->callback_mutex);
		_eecloud_message_cleanup(&message);
	}
#endif
	rc = _eecloud_send_pubcomp(ecld, mid);
	if(rc) return rc;

	return ECLD_ERR_SUCCESS;
}

int _eecloud_handle_suback(struct eecloud *ecld)
{
	uint16_t mid;
	uint8_t qos;
	int *granted_qos;
	int qos_count;
	int i = 0;
	int rc;

	assert(ecld);
#ifdef WITH_BROKER
	_eecloud_log_printf(NULL, ECLD_LOG_DEBUG, "Received SUBACK from %s", ecld->id);
#else
	_eecloud_log_printf(ecld, ECLD_LOG_DEBUG, "Client %s received SUBACK", ecld->id);
#endif
	rc = _eecloud_read_uint16(&ecld->in_packet, &mid);
	if(rc) return rc;

	qos_count = ecld->in_packet.remaining_length - ecld->in_packet.pos;
	granted_qos = _eecloud_malloc(qos_count*sizeof(int));
	if(!granted_qos) return ECLD_ERR_NOMEM;
	while(ecld->in_packet.pos < ecld->in_packet.remaining_length){
		rc = _eecloud_read_byte(&ecld->in_packet, &qos);
		if(rc){
			_eecloud_free(granted_qos);
			return rc;
		}
		granted_qos[i] = (int)qos;
		i++;
	}
#ifndef WITH_BROKER
	pthread_mutex_lock(&ecld->callback_mutex);
	if(ecld->on_subscribe){
		ecld->in_callback = true;
		ecld->on_subscribe(ecld, ecld->userdata, mid, qos_count, granted_qos);
		ecld->in_callback = false;
	}
	pthread_mutex_unlock(&ecld->callback_mutex);
#endif
	_eecloud_free(granted_qos);

	return ECLD_ERR_SUCCESS;
}

int _eecloud_handle_unsuback(struct eecloud *ecld)
{
	uint16_t mid;
	int rc;

	assert(ecld);
#ifdef WITH_BROKER
	_eecloud_log_printf(NULL, ECLD_LOG_DEBUG, "Received UNSUBACK from %s", ecld->id);
#else
	_eecloud_log_printf(ecld, ECLD_LOG_DEBUG, "Client %s received UNSUBACK", ecld->id);
#endif
	rc = _eecloud_read_uint16(&ecld->in_packet, &mid);
	if(rc) return rc;
#ifndef WITH_BROKER
	pthread_mutex_lock(&ecld->callback_mutex);
	if(ecld->on_unsubscribe){
		ecld->in_callback = true;
	   	ecld->on_unsubscribe(ecld, ecld->userdata, mid);
		ecld->in_callback = false;
	}
	pthread_mutex_unlock(&ecld->callback_mutex);
#endif

	return ECLD_ERR_SUCCESS;
}

