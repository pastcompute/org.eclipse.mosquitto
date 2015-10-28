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
#include <time_ecld.h>
#include <util_ecld.h>

int _eecloud_packet_handle(struct eecloud *ecld)
{
	assert(ecld);

	switch((ecld->in_packet.command)&0xF0){
		case PINGREQ:
			return _eecloud_handle_pingreq(ecld);
		case PINGRESP:
			return _eecloud_handle_pingresp(ecld);
		case PUBACK:
			return _eecloud_handle_pubackcomp(ecld, "PUBACK");
		case PUBCOMP:
			return _eecloud_handle_pubackcomp(ecld, "PUBCOMP");
		case PUBLISH:
			return _eecloud_handle_publish(ecld);
		case PUBREC:
			return _eecloud_handle_pubrec(ecld);
		case PUBREL:
			return _eecloud_handle_pubrel(NULL, ecld);
		case CONNACK:
			return _eecloud_handle_connack(ecld);
		case SUBACK:
			return _eecloud_handle_suback(ecld);
		case UNSUBACK:
			return _eecloud_handle_unsuback(ecld);
		default:
			/* If we don't recognise the command, return an error straight away. */
			_eecloud_log_printf(ecld, ECLD_LOG_ERR, "Error: Unrecognised command %d\n", (ecld->in_packet.command)&0xF0);
			return ECLD_ERR_PROTOCOL;
	}
}

int _eecloud_handle_publish(struct eecloud *ecld)
{
	uint8_t header;
	struct eecloud_message_all *message;
	int rc = 0;
	uint16_t mid;

	assert(ecld);

	message = _eecloud_calloc(1, sizeof(struct eecloud_message_all));
	if(!message) return ECLD_ERR_NOMEM;

	header = ecld->in_packet.command;

	message->dup = (header & 0x08)>>3;
	message->msg.qos = (header & 0x06)>>1;
	message->msg.retain = (header & 0x01);

	rc = _eecloud_read_string(&ecld->in_packet, &message->msg.topic);
	if(rc){
		_eecloud_message_cleanup(&message);
		return rc;
	}
	if(!strlen(message->msg.topic)){
		_eecloud_message_cleanup(&message);
		return ECLD_ERR_PROTOCOL;
	}

	if(message->msg.qos > 0){
		rc = _eecloud_read_uint16(&ecld->in_packet, &mid);
		if(rc){
			_eecloud_message_cleanup(&message);
			return rc;
		}
		message->msg.mid = (int)mid;
	}

	message->msg.payloadlen = ecld->in_packet.remaining_length - ecld->in_packet.pos;
	if(message->msg.payloadlen){
		message->msg.payload = _eecloud_calloc(message->msg.payloadlen+1, sizeof(uint8_t));
		if(!message->msg.payload){
			_eecloud_message_cleanup(&message);
			return ECLD_ERR_NOMEM;
		}
		rc = _eecloud_read_bytes(&ecld->in_packet, message->msg.payload, message->msg.payloadlen);
		if(rc){
			_eecloud_message_cleanup(&message);
			return rc;
		}
	}
	_eecloud_log_printf(ecld, ECLD_LOG_DEBUG,
			"Client %s received PUBLISH (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))",
			ecld->id, message->dup, message->msg.qos, message->msg.retain,
			message->msg.mid, message->msg.topic,
			(long)message->msg.payloadlen);

	message->timestamp = eecloud_time();
	switch(message->msg.qos){
		case 0:
			pthread_mutex_lock(&ecld->callback_mutex);
			if(ecld->on_message){
				ecld->in_callback = true;
				ecld->on_message(ecld, ecld->userdata, &message->msg);
				ecld->in_callback = false;
			}
			pthread_mutex_unlock(&ecld->callback_mutex);
			_eecloud_message_cleanup(&message);
			return ECLD_ERR_SUCCESS;
		case 1:
			rc = _eecloud_send_puback(ecld, message->msg.mid);
			pthread_mutex_lock(&ecld->callback_mutex);
			if(ecld->on_message){
				ecld->in_callback = true;
				ecld->on_message(ecld, ecld->userdata, &message->msg);
				ecld->in_callback = false;
			}
			pthread_mutex_unlock(&ecld->callback_mutex);
			_eecloud_message_cleanup(&message);
			return rc;
		case 2:
			rc = _eecloud_send_pubrec(ecld, message->msg.mid);
			pthread_mutex_lock(&ecld->in_message_mutex);
			message->state = ecld_ms_wait_for_pubrel;
			_eecloud_message_queue(ecld, message, ecld_md_in);
			pthread_mutex_unlock(&ecld->in_message_mutex);
			return rc;
		default:
			_eecloud_message_cleanup(&message);
			return ECLD_ERR_PROTOCOL;
	}
}

