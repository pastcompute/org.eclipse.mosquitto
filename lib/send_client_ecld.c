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
#include <string.h>

#include <eecloud.h>
#include <logging_ecld.h>
#include <memory_ecld.h>
#include <mqtt3_protocol.h>
#include <net_ecld.h>
#include <send_ecld.h>
#include <util_ecld.h>

#ifdef WITH_BROKER
#include <eecloud_broker.h>
#endif

int _eecloud_send_connect(struct eecloud *ecld, uint16_t keepalive, bool clean_session)
{
	struct _eecloud_packet *packet = NULL;
	int payloadlen;
	uint8_t will = 0;
	uint8_t byte;
	int rc;
	uint8_t version;
	char *clientid, *username, *password;
	int headerlen;

	assert(ecld);
	assert(ecld->id);

#if defined(WITH_BROKER) && defined(WITH_BRIDGE)
	if(ecld->bridge){
		clientid = ecld->bridge->remote_clientid;
		username = ecld->bridge->remote_username;
		password = ecld->bridge->remote_password;
	}else{
		clientid = ecld->id;
		username = ecld->username;
		password = ecld->password;
	}
#else
	clientid = ecld->id;
	username = ecld->username;
	password = ecld->password;
#endif

	if(ecld->protocol == ecld_p_mqtt31){
		version = MQTT_PROTOCOL_V31;
		headerlen = 12;
	}else if(ecld->protocol == ecld_p_mqtt311){
		version = MQTT_PROTOCOL_V311;
		headerlen = 10;
	}else{
		return MOSQ_ERR_INVAL;
	}

	packet = _eecloud_calloc(1, sizeof(struct _eecloud_packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	payloadlen = 2+strlen(clientid);
	if(ecld->will){
		will = 1;
		assert(ecld->will->topic);

		payloadlen += 2+strlen(ecld->will->topic) + 2+ecld->will->payloadlen;
	}
	if(username){
		payloadlen += 2+strlen(username);
		if(password){
			payloadlen += 2+strlen(password);
		}
	}

	packet->command = CONNECT;
	packet->remaining_length = headerlen+payloadlen;
	rc = _eecloud_packet_alloc(packet);
	if(rc){
		_eecloud_free(packet);
		return rc;
	}

	/* Variable header */
	if(version == MQTT_PROTOCOL_V31){
		_eecloud_write_string(packet, PROTOCOL_NAME_v31, strlen(PROTOCOL_NAME_v31));
	}else if(version == MQTT_PROTOCOL_V311){
		_eecloud_write_string(packet, PROTOCOL_NAME_v311, strlen(PROTOCOL_NAME_v311));
	}
#if defined(WITH_BROKER) && defined(WITH_BRIDGE)
	if(ecld->bridge && ecld->bridge->try_private && ecld->bridge->try_private_accepted){
		version |= 0x80;
	}else{
	}
#endif
	_eecloud_write_byte(packet, version);
	byte = (clean_session&0x1)<<1;
	if(will){
		byte = byte | ((ecld->will->retain&0x1)<<5) | ((ecld->will->qos&0x3)<<3) | ((will&0x1)<<2);
	}
	if(username){
		byte = byte | 0x1<<7;
		if(ecld->password){
			byte = byte | 0x1<<6;
		}
	}
	_eecloud_write_byte(packet, byte);
	_eecloud_write_uint16(packet, keepalive);

	/* Payload */
	_eecloud_write_string(packet, clientid, strlen(clientid));
	if(will){
		_eecloud_write_string(packet, ecld->will->topic, strlen(ecld->will->topic));
		_eecloud_write_string(packet, (const char *)ecld->will->payload, ecld->will->payloadlen);
	}
	if(username){
		_eecloud_write_string(packet, username, strlen(username));
		if(password){
			_eecloud_write_string(packet, password, strlen(password));
		}
	}

	ecld->keepalive = keepalive;
#ifdef WITH_BROKER
# ifdef WITH_BRIDGE
	_eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Bridge %s sending CONNECT", clientid);
# endif
#else
	_eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Client %s sending CONNECT", clientid);
#endif
	return _eecloud_packet_queue(ecld, packet);
}

int _eecloud_send_disconnect(struct eecloud *ecld)
{
	assert(ecld);
#ifdef WITH_BROKER
# ifdef WITH_BRIDGE
	_eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Bridge %s sending DISCONNECT", ecld->id);
# endif
#else
	_eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Client %s sending DISCONNECT", ecld->id);
#endif
	return _eecloud_send_simple_command(ecld, DISCONNECT);
}

int _eecloud_send_subscribe(struct eecloud *ecld, int *mid, const char *topic, uint8_t topic_qos)
{
	/* FIXME - only deals with a single topic */
	struct _eecloud_packet *packet = NULL;
	uint32_t packetlen;
	uint16_t local_mid;
	int rc;

	assert(ecld);
	assert(topic);

	packet = _eecloud_calloc(1, sizeof(struct _eecloud_packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packetlen = 2 + 2+strlen(topic) + 1;

	packet->command = SUBSCRIBE | (1<<1);
	packet->remaining_length = packetlen;
	rc = _eecloud_packet_alloc(packet);
	if(rc){
		_eecloud_free(packet);
		return rc;
	}

	/* Variable header */
	local_mid = _eecloud_mid_generate(ecld);
	if(mid) *mid = (int)local_mid;
	_eecloud_write_uint16(packet, local_mid);

	/* Payload */
	_eecloud_write_string(packet, topic, strlen(topic));
	_eecloud_write_byte(packet, topic_qos);

#ifdef WITH_BROKER
# ifdef WITH_BRIDGE
	_eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Bridge %s sending SUBSCRIBE (Mid: %d, Topic: %s, QoS: %d)", ecld->id, local_mid, topic, topic_qos);
# endif
#else
	_eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Client %s sending SUBSCRIBE (Mid: %d, Topic: %s, QoS: %d)", ecld->id, local_mid, topic, topic_qos);
#endif

	return _eecloud_packet_queue(ecld, packet);
}


int _eecloud_send_unsubscribe(struct eecloud *ecld, int *mid, const char *topic)
{
	/* FIXME - only deals with a single topic */
	struct _eecloud_packet *packet = NULL;
	uint32_t packetlen;
	uint16_t local_mid;
	int rc;

	assert(ecld);
	assert(topic);

	packet = _eecloud_calloc(1, sizeof(struct _eecloud_packet));
	if(!packet) return MOSQ_ERR_NOMEM;

	packetlen = 2 + 2+strlen(topic);

	packet->command = UNSUBSCRIBE | (1<<1);
	packet->remaining_length = packetlen;
	rc = _eecloud_packet_alloc(packet);
	if(rc){
		_eecloud_free(packet);
		return rc;
	}

	/* Variable header */
	local_mid = _eecloud_mid_generate(ecld);
	if(mid) *mid = (int)local_mid;
	_eecloud_write_uint16(packet, local_mid);

	/* Payload */
	_eecloud_write_string(packet, topic, strlen(topic));

#ifdef WITH_BROKER
# ifdef WITH_BRIDGE
	_eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Bridge %s sending UNSUBSCRIBE (Mid: %d, Topic: %s)", ecld->id, local_mid, topic);
# endif
#else
	_eecloud_log_printf(ecld, MOSQ_LOG_DEBUG, "Client %s sending UNSUBSCRIBE (Mid: %d, Topic: %s)", ecld->id, local_mid, topic);
#endif
	return _eecloud_packet_queue(ecld, packet);
}

