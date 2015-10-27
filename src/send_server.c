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

#include <config.h>

#include <eecloud_broker.h>
#include <mqtt3_protocol.h>
#include <memory_ecld.h>
#include <util_ecld.h>

int _eecloud_send_connack(struct eecloud *context, int ack, int result)
{
	struct _eecloud_packet *packet = NULL;
	int rc;

	if(context){
		if(context->id){
			_eecloud_log_printf(NULL, MOSQ_LOG_DEBUG, "Sending CONNACK to %s (%d, %d)", context->id, ack, result);
		}else{
			_eecloud_log_printf(NULL, MOSQ_LOG_DEBUG, "Sending CONNACK to %s (%d, %d)", context->address, ack, result);
		}
	}

	packet = _eecloud_calloc(1, sizeof(struct _eecloud_packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->command = CONNACK;
	packet->remaining_length = 2;
	rc = _eecloud_packet_alloc(packet);
	if(rc){
		_eecloud_free(packet);
		return rc;
	}
	packet->payload[packet->pos+0] = ack;
	packet->payload[packet->pos+1] = result;

	return _eecloud_packet_queue(context, packet);
}

int _eecloud_send_suback(struct eecloud *context, uint16_t mid, uint32_t payloadlen, const void *payload)
{
	struct _eecloud_packet *packet = NULL;
	int rc;

	_eecloud_log_printf(NULL, MOSQ_LOG_DEBUG, "Sending SUBACK to %s", context->id);

	packet = _eecloud_calloc(1, sizeof(struct _eecloud_packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->command = SUBACK;
	packet->remaining_length = 2+payloadlen;
	rc = _eecloud_packet_alloc(packet);
	if(rc){
		_eecloud_free(packet);
		return rc;
	}
	_eecloud_write_uint16(packet, mid);
	if(payloadlen){
		_eecloud_write_bytes(packet, payload, payloadlen);
	}

	return _eecloud_packet_queue(context, packet);
}
