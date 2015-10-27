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
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef WIN32
#include <netdb.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <config.h>

#include <eecloud.h>
#include <eecloud_broker.h>
#include <eecloud_internal.h>
#include <net_ecld.h>
#include <memory_ecld.h>
#include <send_ecld.h>
#include <time_ecld.h>
#include <tls_ecld.h>
#include <util_ecld.h>
#include <will_ecld.h>

#ifdef WITH_BRIDGE

int mqtt3_bridge_new(struct eecloud_db *db, struct _mqtt3_bridge *bridge)
{
	struct eecloud *new_context = NULL;
	struct eecloud **bridges;
	char hostname[256];
	int len;
	char *id, *local_id;

	assert(db);
	assert(bridge);

	if(!bridge->remote_clientid){
		if(!gethostname(hostname, 256)){
			len = strlen(hostname) + strlen(bridge->name) + 2;
			id = _eecloud_malloc(len);
			if(!id){
				return MOSQ_ERR_NOMEM;
			}
			snprintf(id, len, "%s.%s", hostname, bridge->name);
		}else{
			return 1;
		}
		bridge->remote_clientid = id;
	}
	if(bridge->local_clientid){
		local_id = _eecloud_strdup(bridge->local_clientid);
		if(!local_id){
			return MOSQ_ERR_NOMEM;
		}
	}else{
		len = strlen(bridge->remote_clientid) + strlen("local.") + 2;
		local_id = _eecloud_malloc(len);
		if(!local_id){
			return MOSQ_ERR_NOMEM;
		}
		snprintf(local_id, len, "local.%s", bridge->remote_clientid);
		bridge->local_clientid = _eecloud_strdup(local_id);
		if(!bridge->local_clientid){
			_eecloud_free(local_id);
			return MOSQ_ERR_NOMEM;
		}
	}

	HASH_FIND(hh_id, db->contexts_by_id, local_id, strlen(local_id), new_context);
	if(new_context){
		/* (possible from persistent db) */
		_eecloud_free(local_id);
	}else{
		/* id wasn't found, so generate a new context */
		new_context = mqtt3_context_init(db, -1);
		if(!new_context){
			_eecloud_free(local_id);
			return MOSQ_ERR_NOMEM;
		}
		new_context->id = local_id;
		HASH_ADD_KEYPTR(hh_id, db->contexts_by_id, new_context->id, strlen(new_context->id), new_context);
	}
	new_context->bridge = bridge;
	new_context->is_bridge = true;

	new_context->username = new_context->bridge->remote_username;
	new_context->password = new_context->bridge->remote_password;

#ifdef WITH_TLS
	new_context->tls_cafile = new_context->bridge->tls_cafile;
	new_context->tls_capath = new_context->bridge->tls_capath;
	new_context->tls_certfile = new_context->bridge->tls_certfile;
	new_context->tls_keyfile = new_context->bridge->tls_keyfile;
	new_context->tls_cert_reqs = SSL_VERIFY_PEER;
	new_context->tls_version = new_context->bridge->tls_version;
	new_context->tls_insecure = new_context->bridge->tls_insecure;
#ifdef REAL_WITH_TLS_PSK
	new_context->tls_psk_identity = new_context->bridge->tls_psk_identity;
	new_context->tls_psk = new_context->bridge->tls_psk;
#endif
#endif

	bridge->try_private_accepted = true;
	new_context->protocol = bridge->protocol_version;

	bridges = _eecloud_realloc(db->bridges, (db->bridge_count+1)*sizeof(struct eecloud *));
	if(bridges){
		db->bridges = bridges;
		db->bridge_count++;
		db->bridges[db->bridge_count-1] = new_context;
	}else{
		return MOSQ_ERR_NOMEM;
	}

	return mqtt3_bridge_connect(db, new_context);
}

int mqtt3_bridge_connect(struct eecloud_db *db, struct eecloud *context)
{
	int rc;
	int i;
	char *notification_topic;
	int notification_topic_len;
	uint8_t notification_payload;

	if(!context || !context->bridge) return MOSQ_ERR_INVAL;

	context->state = ecld_cs_new;
	context->sock = INVALID_SOCKET;
	context->last_msg_in = eecloud_time();
	context->last_msg_out = eecloud_time();
	context->keepalive = context->bridge->keepalive;
	context->clean_session = context->bridge->clean_session;
	context->in_packet.payload = NULL;
	context->ping_t = 0;
	context->bridge->lazy_reconnect = false;
	mqtt3_bridge_packet_cleanup(context);
	mqtt3_db_message_reconnect_reset(db, context);

	if(context->clean_session){
		mqtt3_db_messages_delete(db, context);
	}

	/* Delete all local subscriptions even for clean_session==false. We don't
	 * remove any messages and the next loop carries out the resubscription
	 * anyway. This means any unwanted subs will be removed.
	 */
	mqtt3_subs_clean_session(db, context);

	for(i=0; i<context->bridge->topic_count; i++){
		if(context->bridge->topics[i].direction == bd_out || context->bridge->topics[i].direction == bd_both){
			_eecloud_log_printf(NULL, MOSQ_LOG_DEBUG, "Bridge %s doing local SUBSCRIBE on topic %s", context->id, context->bridge->topics[i].local_topic);
			if(mqtt3_sub_add(db, context, context->bridge->topics[i].local_topic, context->bridge->topics[i].qos, &db->subs)) return 1;
		}
	}

	if(context->bridge->notifications){
		if(context->bridge->notification_topic){
			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				mqtt3_db_messages_easy_queue(db, context, context->bridge->notification_topic, 1, 1, &notification_payload, 1);
				context->bridge->initial_notification_done = true;
			}
			notification_payload = '0';
			rc = _eecloud_will_set(context, context->bridge->notification_topic, 1, &notification_payload, 1, true);
			if(rc != MOSQ_ERR_SUCCESS){
				return rc;
			}
		}else{
			notification_topic_len = strlen(context->bridge->remote_clientid)+strlen("$SYS/broker/connection//state");
			notification_topic = _eecloud_malloc(sizeof(char)*(notification_topic_len+1));
			if(!notification_topic) return MOSQ_ERR_NOMEM;

			snprintf(notification_topic, notification_topic_len+1, "$SYS/broker/connection/%s/state", context->bridge->remote_clientid);

			if(!context->bridge->initial_notification_done){
				notification_payload = '0';
				mqtt3_db_messages_easy_queue(db, context, notification_topic, 1, 1, &notification_payload, 1);
				context->bridge->initial_notification_done = true;
			}

			notification_payload = '0';
			rc = _eecloud_will_set(context, notification_topic, 1, &notification_payload, 1, true);
			_eecloud_free(notification_topic);
			if(rc != MOSQ_ERR_SUCCESS){
				return rc;
			}
		}
	}

	_eecloud_log_printf(NULL, MOSQ_LOG_NOTICE, "Connecting bridge %s (%s:%d)", context->bridge->name, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port);
	rc = _eecloud_socket_connect(context, context->bridge->addresses[context->bridge->cur_address].address, context->bridge->addresses[context->bridge->cur_address].port, NULL, false);
	if(rc > 0 ){
		if(rc == MOSQ_ERR_TLS){
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}

		return rc;
	}

	HASH_ADD(hh_sock, db->contexts_by_sock, sock, sizeof(context->sock), context);

	if(rc == MOSQ_ERR_CONN_PENDING){
		context->state = ecld_cs_connect_pending;
	}
	rc = _eecloud_send_connect(context, context->keepalive, context->clean_session);
	if(rc == MOSQ_ERR_SUCCESS){
		return MOSQ_ERR_SUCCESS;
	}else if(rc == MOSQ_ERR_ERRNO && errno == ENOTCONN){
		return MOSQ_ERR_SUCCESS;
	}else{
		if(rc == MOSQ_ERR_TLS){
			return rc; /* Error already printed */
		}else if(rc == MOSQ_ERR_ERRNO){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", strerror(errno));
		}else if(rc == MOSQ_ERR_EAI){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR, "Error creating bridge: %s.", gai_strerror(errno));
		}
		_eecloud_socket_close(db, context);
		return rc;
	}
}

void mqtt3_bridge_packet_cleanup(struct eecloud *context)
{
	struct _eecloud_packet *packet;
	if(!context) return;

	if(context->current_out_packet){
		_eecloud_packet_cleanup(context->current_out_packet);
		_eecloud_free(context->current_out_packet);
		context->current_out_packet = NULL;
	}
    while(context->out_packet){
		_eecloud_packet_cleanup(context->out_packet);
		packet = context->out_packet;
		context->out_packet = context->out_packet->next;
		_eecloud_free(packet);
	}
	context->out_packet = NULL;
	context->out_packet_last = NULL;

	_eecloud_packet_cleanup(&(context->in_packet));
}

#endif
