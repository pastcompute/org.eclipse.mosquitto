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
#include <eecloud_internal.h>
#include <logging_ecld.h>
#include <mqtt3_protocol.h>
#include <memory_ecld.h>
#include <net_ecld.h>
#include <send_ecld.h>
#include <time_ecld.h>
#include <util_ecld.h>

#ifdef WITH_BROKER
#include <eecloud_broker.h>
#  ifdef WITH_SYS_TREE
extern uint64_t g_pub_bytes_sent;
#  endif
#endif

int _eecloud_send_pingreq(struct eecloud *ecld)
{
	int rc;
	assert(ecld);
#ifdef WITH_BROKER
	_eecloud_log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PINGREQ to %s", ecld->id);
#else
	_eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Client %s sending PINGREQ", ecld->id);
#endif
	rc = _eecloud_send_simple_command(ecld, PINGREQ);
	if(rc == MOSQ_ERR_SUCCESS){
		ecld->ping_t = eecloud_time();
	}
	return rc;
}

int _eecloud_send_pingresp(struct eecloud *ecld)
{
#ifdef WITH_BROKER
	if(ecld) _eecloud_log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PINGRESP to %s", ecld->id);
#else
	if(ecld) _eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Client %s sending PINGRESP", ecld->id);
#endif
	return _eecloud_send_simple_command(ecld, PINGRESP);
}

int _eecloud_send_puback(struct eecloud *ecld, uint16_t mid)
{
#ifdef WITH_BROKER
	if(ecld) _eecloud_log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBACK to %s (Mid: %d)", ecld->id, mid);
#else
	if(ecld) _eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Client %s sending PUBACK (Mid: %d)", ecld->id, mid);
#endif
	return _eecloud_send_command_with_mid(ecld, PUBACK, mid, false);
}

int _eecloud_send_pubcomp(struct eecloud *ecld, uint16_t mid)
{
#ifdef WITH_BROKER
	if(ecld) _eecloud_log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBCOMP to %s (Mid: %d)", ecld->id, mid);
#else
	if(ecld) _eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Client %s sending PUBCOMP (Mid: %d)", ecld->id, mid);
#endif
	return _eecloud_send_command_with_mid(ecld, PUBCOMP, mid, false);
}

int _eecloud_send_publish(struct eecloud *ecld, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, int qos, bool retain, bool dup)
{
#ifdef WITH_BROKER
	size_t len;
#ifdef WITH_BRIDGE
	int i;
	struct _mqtt3_bridge_topic *cur_topic;
	bool match;
	int rc;
	char *mapped_topic = NULL;
	char *topic_temp = NULL;
#endif
#endif
	assert(ecld);
	assert(topic);

#if defined(WITH_BROKER) && defined(WITH_WEBSOCKETS)
	if(ecld->sock == INVALID_SOCKET && !ecld->wsi) return MOSQ_ERR_NO_CONN;
#else
	if(ecld->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;
#endif

#ifdef WITH_BROKER
	if(ecld->listener && ecld->listener->mount_point){
		len = strlen(ecld->listener->mount_point);
		if(len < strlen(topic)){
			topic += len;
		}else{
			/* Invalid topic string. Should never happen, but silently swallow the message anyway. */
			return MOSQ_ERR_SUCCESS;
		}
	}
#ifdef WITH_BRIDGE
	if(ecld->bridge && ecld->bridge->topics && ecld->bridge->topic_remapping){
		for(i=0; i<ecld->bridge->topic_count; i++){
			cur_topic = &ecld->bridge->topics[i];
			if((cur_topic->direction == bd_both || cur_topic->direction == bd_out) 
					&& (cur_topic->remote_prefix || cur_topic->local_prefix)){
				/* Topic mapping required on this topic if the message matches */

				rc = eecloud_topic_matches_sub(cur_topic->local_topic, topic, &match);
				if(rc){
					return rc;
				}
				if(match){
					mapped_topic = _eecloud_strdup(topic);
					if(!mapped_topic) return MOSQ_ERR_NOMEM;
					if(cur_topic->local_prefix){
						/* This prefix needs removing. */
						if(!strncmp(cur_topic->local_prefix, mapped_topic, strlen(cur_topic->local_prefix))){
							topic_temp = _eecloud_strdup(mapped_topic+strlen(cur_topic->local_prefix));
							_eecloud_free(mapped_topic);
							if(!topic_temp){
								return MOSQ_ERR_NOMEM;
							}
							mapped_topic = topic_temp;
						}
					}

					if(cur_topic->remote_prefix){
						/* This prefix needs adding. */
						len = strlen(mapped_topic) + strlen(cur_topic->remote_prefix)+1;
						topic_temp = _eecloud_malloc(len+1);
						if(!topic_temp){
							_eecloud_free(mapped_topic);
							return MOSQ_ERR_NOMEM;
						}
						snprintf(topic_temp, len, "%s%s", cur_topic->remote_prefix, mapped_topic);
						topic_temp[len] = '\0';
						_eecloud_free(mapped_topic);
						mapped_topic = topic_temp;
					}
					_eecloud_log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBLISH to %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", ecld->id, dup, qos, retain, mid, mapped_topic, (long)payloadlen);
#ifdef WITH_SYS_TREE
					g_pub_bytes_sent += payloadlen;
#endif
					rc =  _eecloud_send_real_publish(ecld, mid, mapped_topic, payloadlen, payload, qos, retain, dup);
					_eecloud_free(mapped_topic);
					return rc;
				}
			}
		}
	}
#endif
	_eecloud_log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBLISH to %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", ecld->id, dup, qos, retain, mid, topic, (long)payloadlen);
#  ifdef WITH_SYS_TREE
	g_pub_bytes_sent += payloadlen;
#  endif
#else
	_eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Client %s sending PUBLISH (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", ecld->id, dup, qos, retain, mid, topic, (long)payloadlen);
#endif

	return _eecloud_send_real_publish(ecld, mid, topic, payloadlen, payload, qos, retain, dup);
}

int _eecloud_send_pubrec(struct eecloud *ecld, uint16_t mid)
{
#ifdef WITH_BROKER
	if(ecld) _eecloud_log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBREC to %s (Mid: %d)", ecld->id, mid);
#else
	if(ecld) _eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Client %s sending PUBREC (Mid: %d)", ecld->id, mid);
#endif
	return _eecloud_send_command_with_mid(ecld, PUBREC, mid, false);
}

int _eecloud_send_pubrel(struct eecloud *ecld, uint16_t mid)
{
#ifdef WITH_BROKER
	if(ecld) _eecloud_log_printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBREL to %s (Mid: %d)", ecld->id, mid);
#else
	if(ecld) _eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Client %s sending PUBREL (Mid: %d)", ecld->id, mid);
#endif
	return _eecloud_send_command_with_mid(ecld, PUBREL|2, mid, false);
}

/* For PUBACK, PUBCOMP, PUBREC, and PUBREL */
int _eecloud_send_command_with_mid(struct eecloud *ecld, uint8_t command, uint16_t mid, bool dup)
{
	struct _eecloud_packet *packet = NULL;
	int rc;

	assert(ecld);
	packet = _eecloud_calloc(1, sizeof(struct _eecloud_packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->command = command;
	if(dup){
		packet->command |= 8;
	}
	packet->remaining_length = 2;
	rc = _eecloud_packet_alloc(packet);
	if(rc){
		_eecloud_free(packet);
		return rc;
	}

	packet->payload[packet->pos+0] = MOSQ_MSB(mid);
	packet->payload[packet->pos+1] = MOSQ_LSB(mid);

	return _eecloud_packet_queue(ecld, packet);
}

/* For DISCONNECT, PINGREQ and PINGRESP */
int _eecloud_send_simple_command(struct eecloud *ecld, uint8_t command)
{
	struct _eecloud_packet *packet = NULL;
	int rc;

	assert(ecld);
	packet = _eecloud_calloc(1, sizeof(struct _eecloud_packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->command = command;
	packet->remaining_length = 0;

	rc = _eecloud_packet_alloc(packet);
	if(rc){
		_eecloud_free(packet);
		return rc;
	}

	return _eecloud_packet_queue(ecld, packet);
}

int _eecloud_send_real_publish(struct eecloud *ecld, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, int qos, bool retain, bool dup)
{
	struct _eecloud_packet *packet = NULL;
	int packetlen;
	int rc;

	assert(ecld);
	assert(topic);

	packetlen = 2+strlen(topic) + payloadlen;
	if(qos > 0) packetlen += 2; /* For message id */
	packet = _eecloud_calloc(1, sizeof(struct _eecloud_packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packet->mid = mid;
	packet->command = PUBLISH | ((dup&0x1)<<3) | (qos<<1) | retain;
	packet->remaining_length = packetlen;
	rc = _eecloud_packet_alloc(packet);
	if(rc){
		_eecloud_free(packet);
		return rc;
	}
	/* Variable header (topic string) */
	_eecloud_write_string(packet, topic, strlen(topic));
	if(qos > 0){
		_eecloud_write_uint16(packet, mid);
	}

	/* Payload */
	if(payloadlen){
		_eecloud_write_bytes(packet, payload, payloadlen);
	}

	return _eecloud_packet_queue(ecld, packet);
}
