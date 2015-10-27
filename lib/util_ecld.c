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

#ifdef WIN32
#include <winsock2.h>
#endif


#include <eecloud.h>
#include <memory_ecld.h>
#include <net_ecld.h>
#include <send_ecld.h>
#include <time_ecld.h>
#include <tls_ecld.h>
#include <util_ecld.h>

#ifdef WITH_BROKER
#include <eecloud_broker.h>
#endif

#ifdef WITH_WEBSOCKETS
#include <libwebsockets.h>
#endif

int _eecloud_packet_alloc(struct _eecloud_packet *packet)
{
	uint8_t remaining_bytes[5], byte;
	uint32_t remaining_length;
	int i;

	assert(packet);

	remaining_length = packet->remaining_length;
	packet->payload = NULL;
	packet->remaining_count = 0;
	do{
		byte = remaining_length % 128;
		remaining_length = remaining_length / 128;
		/* If there are more digits to encode, set the top bit of this digit */
		if(remaining_length > 0){
			byte = byte | 0x80;
		}
		remaining_bytes[packet->remaining_count] = byte;
		packet->remaining_count++;
	}while(remaining_length > 0 && packet->remaining_count < 5);
	if(packet->remaining_count == 5) return MOSQ_ERR_PAYLOAD_SIZE;
	packet->packet_length = packet->remaining_length + 1 + packet->remaining_count;
#ifdef WITH_WEBSOCKETS
	packet->payload = _eecloud_malloc(sizeof(uint8_t)*packet->packet_length + LWS_SEND_BUFFER_PRE_PADDING + LWS_SEND_BUFFER_POST_PADDING);
#else
	packet->payload = _eecloud_malloc(sizeof(uint8_t)*packet->packet_length);
#endif
	if(!packet->payload) return MOSQ_ERR_NOMEM;

	packet->payload[0] = packet->command;
	for(i=0; i<packet->remaining_count; i++){
		packet->payload[i+1] = remaining_bytes[i];
	}
	packet->pos = 1 + packet->remaining_count;

	return MOSQ_ERR_SUCCESS;
}

#ifdef WITH_BROKER
void _eecloud_check_keepalive(struct eecloud_db *db, struct eecloud *ecld)
#else
void _eecloud_check_keepalive(struct eecloud *ecld)
#endif
{
	time_t last_msg_out;
	time_t last_msg_in;
	time_t now = eecloud_time();
#ifndef WITH_BROKER
	int rc;
#endif

	assert(ecld);
#if defined(WITH_BROKER) && defined(WITH_BRIDGE)
	/* Check if a lazy bridge should be timed out due to idle. */
	if(ecld->bridge && ecld->bridge->start_type == bst_lazy
				&& ecld->sock != INVALID_SOCKET
				&& now - ecld->last_msg_out >= ecld->bridge->idle_timeout){

		_eecloud_log_printf(NULL, MOSQ_LOG_NOTICE, "Bridge connection %s has exceeded idle timeout, disconnecting.", ecld->id);
		_eecloud_socket_close(db, ecld);
		return;
	}
#endif
	pthread_mutex_lock(&ecld->msgtime_mutex);
	last_msg_out = ecld->last_msg_out;
	last_msg_in = ecld->last_msg_in;
	pthread_mutex_unlock(&ecld->msgtime_mutex);
	if(ecld->keepalive && ecld->sock != INVALID_SOCKET &&
			(now - last_msg_out >= ecld->keepalive || now - last_msg_in >= ecld->keepalive)){

		if(ecld->state == ecld_cs_connected && ecld->ping_t == 0){
			_eecloud_send_pingreq(ecld);
			/* Reset last msg times to give the server time to send a pingresp */
			pthread_mutex_lock(&ecld->msgtime_mutex);
			ecld->last_msg_in = now;
			ecld->last_msg_out = now;
			pthread_mutex_unlock(&ecld->msgtime_mutex);
		}else{
#ifdef WITH_BROKER
			if(ecld->listener){
				ecld->listener->client_count--;
				assert(ecld->listener->client_count >= 0);
			}
			ecld->listener = NULL;
			_eecloud_socket_close(db, ecld);
#else
			_eecloud_socket_close(ecld);
			pthread_mutex_lock(&ecld->state_mutex);
			if(ecld->state == ecld_cs_disconnecting){
				rc = MOSQ_ERR_SUCCESS;
			}else{
				rc = 1;
			}
			pthread_mutex_unlock(&ecld->state_mutex);
			pthread_mutex_lock(&ecld->callback_mutex);
			if(ecld->on_disconnect){
				ecld->in_callback = true;
				ecld->on_disconnect(ecld, ecld->userdata, rc);
				ecld->in_callback = false;
			}
			pthread_mutex_unlock(&ecld->callback_mutex);
#endif
		}
	}
}

uint16_t _eecloud_mid_generate(struct eecloud *ecld)
{
	/* FIXME - this would be better with atomic increment, but this is safer
	 * for now for a bug fix release.
	 *
	 * If this is changed to use atomic increment, callers of this function
	 * will have to be aware that they may receive a 0 result, which may not be
	 * used as a mid.
	 */
	uint16_t mid;
	assert(ecld);

	pthread_mutex_lock(&ecld->mid_mutex);
	ecld->last_mid++;
	if(ecld->last_mid == 0) ecld->last_mid++;
	mid = ecld->last_mid;
	pthread_mutex_unlock(&ecld->mid_mutex);
	
	return mid;
}

/* Check that a topic used for publishing is valid.
 * Search for + or # in a topic. Return MOSQ_ERR_INVAL if found.
 * Also returns MOSQ_ERR_INVAL if the topic string is too long.
 * Returns MOSQ_ERR_SUCCESS if everything is fine.
 */
int eecloud_pub_topic_check(const char *str)
{
	int len = 0;
	while(str && str[0]){
		if(str[0] == '+' || str[0] == '#'){
			return MOSQ_ERR_INVAL;
		}
		len++;
		str = &str[1];
	}
	if(len > 65535) return MOSQ_ERR_INVAL;

	return MOSQ_ERR_SUCCESS;
}

/* Check that a topic used for subscriptions is valid.
 * Search for + or # in a topic, check they aren't in invalid positions such as
 * foo/#/bar, foo/+bar or foo/bar#.
 * Return MOSQ_ERR_INVAL if invalid position found.
 * Also returns MOSQ_ERR_INVAL if the topic string is too long.
 * Returns MOSQ_ERR_SUCCESS if everything is fine.
 */
int eecloud_sub_topic_check(const char *str)
{
	char c = '\0';
	int len = 0;
	while(str && str[0]){
		if(str[0] == '+'){
			if((c != '\0' && c != '/') || (str[1] != '\0' && str[1] != '/')){
				return MOSQ_ERR_INVAL;
			}
		}else if(str[0] == '#'){
			if((c != '\0' && c != '/')  || str[1] != '\0'){
				return MOSQ_ERR_INVAL;
			}
		}
		len++;
		c = str[0];
		str = &str[1];
	}
	if(len > 65535) return MOSQ_ERR_INVAL;

	return MOSQ_ERR_SUCCESS;
}

/* Does a topic match a subscription? */
int eecloud_topic_matches_sub(const char *sub, const char *topic, bool *result)
{
	int slen, tlen;
	int spos, tpos;
	bool multilevel_wildcard = false;

	if(!sub || !topic || !result) return MOSQ_ERR_INVAL;

	slen = strlen(sub);
	tlen = strlen(topic);

	if(slen && tlen){
		if((sub[0] == '$' && topic[0] != '$')
				|| (topic[0] == '$' && sub[0] != '$')){

			*result = false;
			return MOSQ_ERR_SUCCESS;
		}
	}

	spos = 0;
	tpos = 0;

	while(spos < slen && tpos < tlen){
		if(sub[spos] == topic[tpos]){
			if(tpos == tlen-1){
				/* Check for e.g. foo matching foo/# */
				if(spos == slen-3 
						&& sub[spos+1] == '/'
						&& sub[spos+2] == '#'){
					*result = true;
					multilevel_wildcard = true;
					return MOSQ_ERR_SUCCESS;
				}
			}
			spos++;
			tpos++;
			if(spos == slen && tpos == tlen){
				*result = true;
				return MOSQ_ERR_SUCCESS;
			}else if(tpos == tlen && spos == slen-1 && sub[spos] == '+'){
				spos++;
				*result = true;
				return MOSQ_ERR_SUCCESS;
			}
		}else{
			if(sub[spos] == '+'){
				spos++;
				while(tpos < tlen && topic[tpos] != '/'){
					tpos++;
				}
				if(tpos == tlen && spos == slen){
					*result = true;
					return MOSQ_ERR_SUCCESS;
				}
			}else if(sub[spos] == '#'){
				multilevel_wildcard = true;
				if(spos+1 != slen){
					*result = false;
					return MOSQ_ERR_SUCCESS;
				}else{
					*result = true;
					return MOSQ_ERR_SUCCESS;
				}
			}else{
				*result = false;
				return MOSQ_ERR_SUCCESS;
			}
		}
	}
	if(multilevel_wildcard == false && (tpos < tlen || spos < slen)){
		*result = false;
	}

	return MOSQ_ERR_SUCCESS;
}

#ifdef REAL_WITH_TLS_PSK
int _eecloud_hex2bin(const char *hex, unsigned char *bin, int bin_max_len)
{
	BIGNUM *bn = NULL;
	int len;

	if(BN_hex2bn(&bn, hex) == 0){
		if(bn) BN_free(bn);
		return 0;
	}
	if(BN_num_bytes(bn) > bin_max_len){
		BN_free(bn);
		return 0;
	}

	len = BN_bn2bin(bn, bin);
	BN_free(bn);
	return len;
}
#endif

FILE *_eecloud_fopen(const char *path, const char *mode)
{
#ifdef WIN32
	char buf[4096];
	int rc;
	rc = ExpandEnvironmentStrings(path, buf, 4096);
	if(rc == 0 || rc > 4096){
		return NULL;
	}else{
		return fopen(buf, mode);
	}
#else
	return fopen(path, mode);
#endif
}

