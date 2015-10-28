/*
Copyright (c) 2010-2014 Roger Light <roger@atchoo.org>

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
#include <signal.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <windows.h>
typedef int ssize_t;
#endif

#include <eecloud.h>
#include <eecloud_internal.h>
#include <logging_ecld.h>
#include <messages_ecld.h>
#include <memory_ecld.h>
#include <mqtt3_protocol.h>
#include <net_ecld.h>
#include <read_handle.h>
#include <send_ecld.h>
#include <socks_ecld.h>
#include <time_ecld.h>
#include <tls_ecld.h>
#include <util_ecld.h>
#include <will_ecld.h>

#include "config.h"

#if !defined(WIN32) && !defined(__SYMBIAN32__)
#define HAVE_PSELECT
#endif

void _eecloud_destroy(struct eecloud *ecld);
static int _eecloud_reconnect(struct eecloud *ecld, bool blocking);
static int _eecloud_connect_init(struct eecloud *ecld, const char *host, int port, int keepalive, const char *bind_address);

int eecloud_lib_version(int *major, int *minor, int *revision)
{
	if(major) *major = LIBEECLOUD_MAJOR;
	if(minor) *minor = LIBEECLOUD_MINOR;
	if(revision) *revision = LIBEECLOUD_REVISION;
	return LIBEECLOUD_VERSION_NUMBER;
}

int eecloud_lib_init(void)
{
#ifdef WIN32
	srand(GetTickCount());
#else
	struct timeval tv;

	gettimeofday(&tv, NULL);
	srand(tv.tv_sec*1000 + tv.tv_usec/1000);
#endif

	_eecloud_net_init();

	return ECLD_ERR_SUCCESS;
}

int eecloud_lib_cleanup(void)
{
	_eecloud_net_cleanup();

	return ECLD_ERR_SUCCESS;
}

struct eecloud *eecloud_new(const char *id, bool clean_session, void *userdata)
{
	struct eecloud *ecld = NULL;
	int rc;

	if(clean_session == false && id == NULL){
		errno = EINVAL;
		return NULL;
	}

#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	ecld = (struct eecloud *)_eecloud_calloc(1, sizeof(struct eecloud));
	if(ecld){
		ecld->sock = INVALID_SOCKET;
		ecld->sockpairR = INVALID_SOCKET;
		ecld->sockpairW = INVALID_SOCKET;
#ifdef WITH_THREADING
		ecld->thread_id = pthread_self();
#endif
		rc = eecloud_reinitialise(ecld, id, clean_session, userdata);
		if(rc){
			eecloud_destroy(ecld);
			if(rc == ECLD_ERR_INVAL){
				errno = EINVAL;
			}else if(rc == ECLD_ERR_NOMEM){
				errno = ENOMEM;
			}
			return NULL;
		}
	}else{
		errno = ENOMEM;
	}
	return ecld;
}

int eecloud_reinitialise(struct eecloud *ecld, const char *id, bool clean_session, void *userdata)
{
	int i;

	if(!ecld) return ECLD_ERR_INVAL;

	if(clean_session == false && id == NULL){
		return ECLD_ERR_INVAL;
	}

	_eecloud_destroy(ecld);
	memset(ecld, 0, sizeof(struct eecloud));

	if(userdata){
		ecld->userdata = userdata;
	}else{
		ecld->userdata = ecld;
	}
	ecld->protocol = ecld_p_mqtt31;
	ecld->sock = INVALID_SOCKET;
	ecld->sockpairR = INVALID_SOCKET;
	ecld->sockpairW = INVALID_SOCKET;
	ecld->keepalive = 60;
	ecld->message_retry = 20;
	ecld->last_retry_check = 0;
	ecld->clean_session = clean_session;
	if(id){
		if(strlen(id) == 0){
			return ECLD_ERR_INVAL;
		}
		ecld->id = _eecloud_strdup(id);
	}else{
		ecld->id = (char *)_eecloud_calloc(24, sizeof(char));
		if(!ecld->id){
			return ECLD_ERR_NOMEM;
		}
		ecld->id[0] = 'm';
		ecld->id[1] = 'o';
		ecld->id[2] = 's';
		ecld->id[3] = 'q';
		ecld->id[4] = '/';

		for(i=5; i<23; i++){
			ecld->id[i] = (rand()%73)+48;
		}
	}
	ecld->in_packet.payload = NULL;
	_eecloud_packet_cleanup(&ecld->in_packet);
	ecld->out_packet = NULL;
	ecld->current_out_packet = NULL;
	ecld->last_msg_in = eecloud_time();
	ecld->last_msg_out = eecloud_time();
	ecld->ping_t = 0;
	ecld->last_mid = 0;
	ecld->state = ecld_cs_new;
	ecld->in_messages = NULL;
	ecld->in_messages_last = NULL;
	ecld->out_messages = NULL;
	ecld->out_messages_last = NULL;
	ecld->max_inflight_messages = 20;
	ecld->will = NULL;
	ecld->on_connect = NULL;
	ecld->on_publish = NULL;
	ecld->on_message = NULL;
	ecld->on_subscribe = NULL;
	ecld->on_unsubscribe = NULL;
	ecld->host = NULL;
	ecld->port = 1883;
	ecld->in_callback = false;
	ecld->in_queue_len = 0;
	ecld->out_queue_len = 0;
	ecld->reconnect_delay = 1;
	ecld->reconnect_delay_max = 1;
	ecld->reconnect_exponential_backoff = false;
	ecld->threaded = false;
#ifdef WITH_TLS
	ecld->ssl = NULL;
	ecld->tls_cert_reqs = SSL_VERIFY_PEER;
	ecld->tls_insecure = false;
	ecld->want_write = false;
#endif
#ifdef WITH_THREADING
	pthread_mutex_init(&ecld->callback_mutex, NULL);
	pthread_mutex_init(&ecld->log_callback_mutex, NULL);
	pthread_mutex_init(&ecld->state_mutex, NULL);
	pthread_mutex_init(&ecld->out_packet_mutex, NULL);
	pthread_mutex_init(&ecld->current_out_packet_mutex, NULL);
	pthread_mutex_init(&ecld->msgtime_mutex, NULL);
	pthread_mutex_init(&ecld->in_message_mutex, NULL);
	pthread_mutex_init(&ecld->out_message_mutex, NULL);
	pthread_mutex_init(&ecld->mid_mutex, NULL);
	ecld->thread_id = pthread_self();
#endif

	return ECLD_ERR_SUCCESS;
}

int eecloud_will_set(struct eecloud *ecld, const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
	if(!ecld) return ECLD_ERR_INVAL;
	return _eecloud_will_set(ecld, topic, payloadlen, payload, qos, retain);
}

int eecloud_will_clear(struct eecloud *ecld)
{
	if(!ecld) return ECLD_ERR_INVAL;
	return _eecloud_will_clear(ecld);
}

int eecloud_username_pw_set(struct eecloud *ecld, const char *username, const char *password)
{
	if(!ecld) return ECLD_ERR_INVAL;

	if(ecld->username){
		_eecloud_free(ecld->username);
		ecld->username = NULL;
	}
	if(ecld->password){
		_eecloud_free(ecld->password);
		ecld->password = NULL;
	}

	if(username){
		ecld->username = _eecloud_strdup(username);
		if(!ecld->username) return ECLD_ERR_NOMEM;
		if(password){
			ecld->password = _eecloud_strdup(password);
			if(!ecld->password){
				_eecloud_free(ecld->username);
				ecld->username = NULL;
				return ECLD_ERR_NOMEM;
			}
		}
	}
	return ECLD_ERR_SUCCESS;
}

int eecloud_reconnect_delay_set(struct eecloud *ecld, unsigned int reconnect_delay, unsigned int reconnect_delay_max, bool reconnect_exponential_backoff)
{
	if(!ecld) return ECLD_ERR_INVAL;
	
	ecld->reconnect_delay = reconnect_delay;
	ecld->reconnect_delay_max = reconnect_delay_max;
	ecld->reconnect_exponential_backoff = reconnect_exponential_backoff;
	
	return ECLD_ERR_SUCCESS;
	
}

void _eecloud_destroy(struct eecloud *ecld)
{
	struct _eecloud_packet *packet;
	if(!ecld) return;

#ifdef WITH_THREADING
	if(ecld->threaded && !pthread_equal(ecld->thread_id, pthread_self())){
		pthread_cancel(ecld->thread_id);
		pthread_join(ecld->thread_id, NULL);
		ecld->threaded = false;
	}

	if(ecld->id){
		/* If ecld->id is not NULL then the client has already been initialised
		 * and so the mutexes need destroying. If ecld->id is NULL, the mutexes
		 * haven't been initialised. */
		pthread_mutex_destroy(&ecld->callback_mutex);
		pthread_mutex_destroy(&ecld->log_callback_mutex);
		pthread_mutex_destroy(&ecld->state_mutex);
		pthread_mutex_destroy(&ecld->out_packet_mutex);
		pthread_mutex_destroy(&ecld->current_out_packet_mutex);
		pthread_mutex_destroy(&ecld->msgtime_mutex);
		pthread_mutex_destroy(&ecld->in_message_mutex);
		pthread_mutex_destroy(&ecld->out_message_mutex);
		pthread_mutex_destroy(&ecld->mid_mutex);
	}
#endif
	if(ecld->sock != INVALID_SOCKET){
		_eecloud_socket_close(ecld);
	}
	_eecloud_message_cleanup_all(ecld);
	_eecloud_will_clear(ecld);
#ifdef WITH_TLS
	if(ecld->ssl){
		SSL_free(ecld->ssl);
	}
	if(ecld->ssl_ctx){
		SSL_CTX_free(ecld->ssl_ctx);
	}
	if(ecld->tls_cafile) _eecloud_free(ecld->tls_cafile);
	if(ecld->tls_capath) _eecloud_free(ecld->tls_capath);
	if(ecld->tls_certfile) _eecloud_free(ecld->tls_certfile);
	if(ecld->tls_keyfile) _eecloud_free(ecld->tls_keyfile);
	if(ecld->tls_pw_callback) ecld->tls_pw_callback = NULL;
	if(ecld->tls_version) _eecloud_free(ecld->tls_version);
	if(ecld->tls_ciphers) _eecloud_free(ecld->tls_ciphers);
	if(ecld->tls_psk) _eecloud_free(ecld->tls_psk);
	if(ecld->tls_psk_identity) _eecloud_free(ecld->tls_psk_identity);
#endif

	if(ecld->address){
		_eecloud_free(ecld->address);
		ecld->address = NULL;
	}
	if(ecld->id){
		_eecloud_free(ecld->id);
		ecld->id = NULL;
	}
	if(ecld->username){
		_eecloud_free(ecld->username);
		ecld->username = NULL;
	}
	if(ecld->password){
		_eecloud_free(ecld->password);
		ecld->password = NULL;
	}
	if(ecld->host){
		_eecloud_free(ecld->host);
		ecld->host = NULL;
	}
	if(ecld->bind_address){
		_eecloud_free(ecld->bind_address);
		ecld->bind_address = NULL;
	}

	/* Out packet cleanup */
	if(ecld->out_packet && !ecld->current_out_packet){
		ecld->current_out_packet = ecld->out_packet;
		ecld->out_packet = ecld->out_packet->next;
	}
	while(ecld->current_out_packet){
		packet = ecld->current_out_packet;
		/* Free data and reset values */
		ecld->current_out_packet = ecld->out_packet;
		if(ecld->out_packet){
			ecld->out_packet = ecld->out_packet->next;
		}

		_eecloud_packet_cleanup(packet);
		_eecloud_free(packet);
	}

	_eecloud_packet_cleanup(&ecld->in_packet);
	if(ecld->sockpairR != INVALID_SOCKET){
		COMPAT_CLOSE(ecld->sockpairR);
		ecld->sockpairR = INVALID_SOCKET;
	}
	if(ecld->sockpairW != INVALID_SOCKET){
		COMPAT_CLOSE(ecld->sockpairW);
		ecld->sockpairW = INVALID_SOCKET;
	}
}

void eecloud_destroy(struct eecloud *ecld)
{
	if(!ecld) return;

	_eecloud_destroy(ecld);
	_eecloud_free(ecld);
}

int eecloud_socket(struct eecloud *ecld)
{
	if(!ecld) return INVALID_SOCKET;
	return ecld->sock;
}

static int _eecloud_connect_init(struct eecloud *ecld, const char *host, int port, int keepalive, const char *bind_address)
{
	if(!ecld) return ECLD_ERR_INVAL;
	if(!host || port <= 0) return ECLD_ERR_INVAL;

	if(ecld->host) _eecloud_free(ecld->host);
	ecld->host = _eecloud_strdup(host);
	if(!ecld->host) return ECLD_ERR_NOMEM;
	ecld->port = port;

	if(ecld->bind_address) _eecloud_free(ecld->bind_address);
	if(bind_address){
		ecld->bind_address = _eecloud_strdup(bind_address);
		if(!ecld->bind_address) return ECLD_ERR_NOMEM;
	}

	ecld->keepalive = keepalive;

	if(_eecloud_socketpair(&ecld->sockpairR, &ecld->sockpairW)){
		_eecloud_log_printf(ecld, ECLD_LOG_WARNING,
				"Warning: Unable to open socket pair, outgoing publish commands may be delayed.");
	}

	return ECLD_ERR_SUCCESS;
}

int eecloud_connect(struct eecloud *ecld, const char *host, int port, int keepalive)
{
	return eecloud_connect_bind(ecld, host, port, keepalive, NULL);
}

int eecloud_connect_bind(struct eecloud *ecld, const char *host, int port, int keepalive, const char *bind_address)
{
	int rc;
	rc = _eecloud_connect_init(ecld, host, port, keepalive, bind_address);
	if(rc) return rc;

	pthread_mutex_lock(&ecld->state_mutex);
	ecld->state = ecld_cs_new;
	pthread_mutex_unlock(&ecld->state_mutex);

	return _eecloud_reconnect(ecld, true);
}

int eecloud_connect_async(struct eecloud *ecld, const char *host, int port, int keepalive)
{
	return eecloud_connect_bind_async(ecld, host, port, keepalive, NULL);
}

int eecloud_connect_bind_async(struct eecloud *ecld, const char *host, int port, int keepalive, const char *bind_address)
{
	int rc = _eecloud_connect_init(ecld, host, port, keepalive, bind_address);
	if(rc) return rc;

	pthread_mutex_lock(&ecld->state_mutex);
	ecld->state = ecld_cs_connect_async;
	pthread_mutex_unlock(&ecld->state_mutex);

	return _eecloud_reconnect(ecld, false);
}

int eecloud_reconnect_async(struct eecloud *ecld)
{
	return _eecloud_reconnect(ecld, false);
}

int eecloud_reconnect(struct eecloud *ecld)
{
	return _eecloud_reconnect(ecld, true);
}

static int _eecloud_reconnect(struct eecloud *ecld, bool blocking)
{
	int rc;
	struct _eecloud_packet *packet;
	if(!ecld) return ECLD_ERR_INVAL;
	if(!ecld->host || ecld->port <= 0) return ECLD_ERR_INVAL;

	pthread_mutex_lock(&ecld->state_mutex);
#ifdef WITH_SOCKS
	if(ecld->socks5_host){
		ecld->state = ecld_cs_socks5_new;
	}else
#endif
	{
		ecld->state = ecld_cs_new;
	}
	pthread_mutex_unlock(&ecld->state_mutex);

	pthread_mutex_lock(&ecld->msgtime_mutex);
	ecld->last_msg_in = eecloud_time();
	ecld->last_msg_out = eecloud_time();
	pthread_mutex_unlock(&ecld->msgtime_mutex);

	ecld->ping_t = 0;

	_eecloud_packet_cleanup(&ecld->in_packet);
		
	pthread_mutex_lock(&ecld->current_out_packet_mutex);
	pthread_mutex_lock(&ecld->out_packet_mutex);

	if(ecld->out_packet && !ecld->current_out_packet){
		ecld->current_out_packet = ecld->out_packet;
		ecld->out_packet = ecld->out_packet->next;
	}

	while(ecld->current_out_packet){
		packet = ecld->current_out_packet;
		/* Free data and reset values */
		ecld->current_out_packet = ecld->out_packet;
		if(ecld->out_packet){
			ecld->out_packet = ecld->out_packet->next;
		}

		_eecloud_packet_cleanup(packet);
		_eecloud_free(packet);
	}
	pthread_mutex_unlock(&ecld->out_packet_mutex);
	pthread_mutex_unlock(&ecld->current_out_packet_mutex);

	_eecloud_messages_reconnect_reset(ecld);

#ifdef WITH_SOCKS
	if(ecld->socks5_host){
		rc = _eecloud_socket_connect(ecld, ecld->socks5_host, ecld->socks5_port, ecld->bind_address, blocking);
	}else
#endif
	{
		rc = _eecloud_socket_connect(ecld, ecld->host, ecld->port, ecld->bind_address, blocking);
	}
	if(rc>0){
		return rc;
	}

#ifdef WITH_SOCKS
	if(ecld->socks5_host){
		return eecloud__socks5_send(ecld);
	}else
#endif
	{
		return _eecloud_send_connect(ecld, ecld->keepalive, ecld->clean_session);
	}
}

int eecloud_disconnect(struct eecloud *ecld)
{
	if(!ecld) return ECLD_ERR_INVAL;

	pthread_mutex_lock(&ecld->state_mutex);
	ecld->state = ecld_cs_disconnecting;
	pthread_mutex_unlock(&ecld->state_mutex);

	if(ecld->sock == INVALID_SOCKET) return ECLD_ERR_NO_CONN;
	return _eecloud_send_disconnect(ecld);
}

int eecloud_publish(struct eecloud *ecld, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
	struct eecloud_message_all *message;
	uint16_t local_mid;

	if(!ecld || !topic || qos<0 || qos>2) return ECLD_ERR_INVAL;
	if(strlen(topic) == 0) return ECLD_ERR_INVAL;
	if(payloadlen < 0 || payloadlen > MQTT_MAX_PAYLOAD) return ECLD_ERR_PAYLOAD_SIZE;

	if(eecloud_pub_topic_check(topic) != ECLD_ERR_SUCCESS){
		return ECLD_ERR_INVAL;
	}

	local_mid = _eecloud_mid_generate(ecld);
	if(mid){
		*mid = local_mid;
	}

	if(qos == 0){
		return _eecloud_send_publish(ecld, local_mid, topic, payloadlen, payload, qos, retain, false);
	}else{
		message = _eecloud_calloc(1, sizeof(struct eecloud_message_all));
		if(!message) return ECLD_ERR_NOMEM;

		message->next = NULL;
		message->timestamp = eecloud_time();
		message->msg.mid = local_mid;
		message->msg.topic = _eecloud_strdup(topic);
		if(!message->msg.topic){
			_eecloud_message_cleanup(&message);
			return ECLD_ERR_NOMEM;
		}
		if(payloadlen){
			message->msg.payloadlen = payloadlen;
			message->msg.payload = _eecloud_malloc(payloadlen*sizeof(uint8_t));
			if(!message->msg.payload){
				_eecloud_message_cleanup(&message);
				return ECLD_ERR_NOMEM;
			}
			memcpy(message->msg.payload, payload, payloadlen*sizeof(uint8_t));
		}else{
			message->msg.payloadlen = 0;
			message->msg.payload = NULL;
		}
		message->msg.qos = qos;
		message->msg.retain = retain;
		message->dup = false;

		pthread_mutex_lock(&ecld->out_message_mutex);
		_eecloud_message_queue(ecld, message, ecld_md_out);
		if(ecld->max_inflight_messages == 0 || ecld->inflight_messages < ecld->max_inflight_messages){
			if(qos == 1){
				message->state = ecld_ms_wait_for_puback;
			}else if(qos == 2){
				message->state = ecld_ms_wait_for_pubrec;
			}
			pthread_mutex_unlock(&ecld->out_message_mutex);
			return _eecloud_send_publish(ecld, message->msg.mid, message->msg.topic, message->msg.payloadlen, message->msg.payload, message->msg.qos, message->msg.retain, message->dup);
		}else{
			message->state = ecld_ms_invalid;
			pthread_mutex_unlock(&ecld->out_message_mutex);
			return ECLD_ERR_SUCCESS;
		}
	}
}

int eecloud_subscribe(struct eecloud *ecld, int *mid, const char *sub, int qos)
{
	if(!ecld) return ECLD_ERR_INVAL;
	if(ecld->sock == INVALID_SOCKET) return ECLD_ERR_NO_CONN;

	if(eecloud_sub_topic_check(sub)) return ECLD_ERR_INVAL;

	return _eecloud_send_subscribe(ecld, mid, sub, qos);
}

int eecloud_unsubscribe(struct eecloud *ecld, int *mid, const char *sub)
{
	if(!ecld) return ECLD_ERR_INVAL;
	if(ecld->sock == INVALID_SOCKET) return ECLD_ERR_NO_CONN;

	if(eecloud_sub_topic_check(sub)) return ECLD_ERR_INVAL;

	return _eecloud_send_unsubscribe(ecld, mid, sub);
}

int eecloud_tls_set(struct eecloud *ecld, const char *cafile, const char *capath, const char *certfile, const char *keyfile, int (*pw_callback)(char *buf, int size, int rwflag, void *userdata))
{
#ifdef WITH_TLS
	FILE *fptr;

	if(!ecld || (!cafile && !capath) || (certfile && !keyfile) || (!certfile && keyfile)) return ECLD_ERR_INVAL;

	if(cafile){
		fptr = _eecloud_fopen(cafile, "rt");
		if(fptr){
			fclose(fptr);
		}else{
			return ECLD_ERR_INVAL;
		}
		ecld->tls_cafile = _eecloud_strdup(cafile);

		if(!ecld->tls_cafile){
			return ECLD_ERR_NOMEM;
		}
	}else if(ecld->tls_cafile){
		_eecloud_free(ecld->tls_cafile);
		ecld->tls_cafile = NULL;
	}

	if(capath){
		ecld->tls_capath = _eecloud_strdup(capath);
		if(!ecld->tls_capath){
			return ECLD_ERR_NOMEM;
		}
	}else if(ecld->tls_capath){
		_eecloud_free(ecld->tls_capath);
		ecld->tls_capath = NULL;
	}

	if(certfile){
		fptr = _eecloud_fopen(certfile, "rt");
		if(fptr){
			fclose(fptr);
		}else{
			if(ecld->tls_cafile){
				_eecloud_free(ecld->tls_cafile);
				ecld->tls_cafile = NULL;
			}
			if(ecld->tls_capath){
				_eecloud_free(ecld->tls_capath);
				ecld->tls_capath = NULL;
			}
			return ECLD_ERR_INVAL;
		}
		ecld->tls_certfile = _eecloud_strdup(certfile);
		if(!ecld->tls_certfile){
			return ECLD_ERR_NOMEM;
		}
	}else{
		if(ecld->tls_certfile) _eecloud_free(ecld->tls_certfile);
		ecld->tls_certfile = NULL;
	}

	if(keyfile){
		fptr = _eecloud_fopen(keyfile, "rt");
		if(fptr){
			fclose(fptr);
		}else{
			if(ecld->tls_cafile){
				_eecloud_free(ecld->tls_cafile);
				ecld->tls_cafile = NULL;
			}
			if(ecld->tls_capath){
				_eecloud_free(ecld->tls_capath);
				ecld->tls_capath = NULL;
			}
			if(ecld->tls_certfile){
				_eecloud_free(ecld->tls_certfile);
				ecld->tls_certfile = NULL;
			}
			return ECLD_ERR_INVAL;
		}
		ecld->tls_keyfile = _eecloud_strdup(keyfile);
		if(!ecld->tls_keyfile){
			return ECLD_ERR_NOMEM;
		}
	}else{
		if(ecld->tls_keyfile) _eecloud_free(ecld->tls_keyfile);
		ecld->tls_keyfile = NULL;
	}

	ecld->tls_pw_callback = pw_callback;


	return ECLD_ERR_SUCCESS;
#else
	return ECLD_ERR_NOT_SUPPORTED;

#endif
}

int eecloud_tls_opts_set(struct eecloud *ecld, int cert_reqs, const char *tls_version, const char *ciphers)
{
#ifdef WITH_TLS
	if(!ecld) return ECLD_ERR_INVAL;

	ecld->tls_cert_reqs = cert_reqs;
	if(tls_version){
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
		if(!strcasecmp(tls_version, "tlsv1.2")
				|| !strcasecmp(tls_version, "tlsv1.1")
				|| !strcasecmp(tls_version, "tlsv1")){

			ecld->tls_version = _eecloud_strdup(tls_version);
			if(!ecld->tls_version) return ECLD_ERR_NOMEM;
		}else{
			return ECLD_ERR_INVAL;
		}
#else
		if(!strcasecmp(tls_version, "tlsv1")){
			ecld->tls_version = _eecloud_strdup(tls_version);
			if(!ecld->tls_version) return ECLD_ERR_NOMEM;
		}else{
			return ECLD_ERR_INVAL;
		}
#endif
	}else{
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
		ecld->tls_version = _eecloud_strdup("tlsv1.2");
#else
		ecld->tls_version = _eecloud_strdup("tlsv1");
#endif
		if(!ecld->tls_version) return ECLD_ERR_NOMEM;
	}
	if(ciphers){
		ecld->tls_ciphers = _eecloud_strdup(ciphers);
		if(!ecld->tls_ciphers) return ECLD_ERR_NOMEM;
	}else{
		ecld->tls_ciphers = NULL;
	}


	return ECLD_ERR_SUCCESS;
#else
	return ECLD_ERR_NOT_SUPPORTED;

#endif
}


int eecloud_tls_insecure_set(struct eecloud *ecld, bool value)
{
#ifdef WITH_TLS
	if(!ecld) return ECLD_ERR_INVAL;
	ecld->tls_insecure = value;
	return ECLD_ERR_SUCCESS;
#else
	return ECLD_ERR_NOT_SUPPORTED;
#endif
}


int eecloud_tls_psk_set(struct eecloud *ecld, const char *psk, const char *identity, const char *ciphers)
{
#ifdef REAL_WITH_TLS_PSK
	if(!ecld || !psk || !identity) return ECLD_ERR_INVAL;

	/* Check for hex only digits */
	if(strspn(psk, "0123456789abcdefABCDEF") < strlen(psk)){
		return ECLD_ERR_INVAL;
	}
	ecld->tls_psk = _eecloud_strdup(psk);
	if(!ecld->tls_psk) return ECLD_ERR_NOMEM;

	ecld->tls_psk_identity = _eecloud_strdup(identity);
	if(!ecld->tls_psk_identity){
		_eecloud_free(ecld->tls_psk);
		return ECLD_ERR_NOMEM;
	}
	if(ciphers){
		ecld->tls_ciphers = _eecloud_strdup(ciphers);
		if(!ecld->tls_ciphers) return ECLD_ERR_NOMEM;
	}else{
		ecld->tls_ciphers = NULL;
	}

	return ECLD_ERR_SUCCESS;
#else
	return ECLD_ERR_NOT_SUPPORTED;
#endif
}


int eecloud_loop(struct eecloud *ecld, int timeout, int max_packets)
{
#ifdef HAVE_PSELECT
	struct timespec local_timeout;
#else
	struct timeval local_timeout;
#endif
	fd_set readfds, writefds;
	int fdcount;
	int rc;
	char pairbuf;
	int maxfd = 0;

	if(!ecld || max_packets < 1) return ECLD_ERR_INVAL;
#ifndef WIN32
	if(ecld->sock >= FD_SETSIZE || ecld->sockpairR >= FD_SETSIZE){
		return ECLD_ERR_INVAL;
	}
#endif

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	if(ecld->sock != INVALID_SOCKET){
		maxfd = ecld->sock;
		FD_SET(ecld->sock, &readfds);
		pthread_mutex_lock(&ecld->current_out_packet_mutex);
		pthread_mutex_lock(&ecld->out_packet_mutex);
		if(ecld->out_packet || ecld->current_out_packet){
			FD_SET(ecld->sock, &writefds);
		}
#ifdef WITH_TLS
		if(ecld->ssl){
			if(ecld->want_write){
				FD_SET(ecld->sock, &writefds);
				ecld->want_write = false;
			}else if(ecld->want_connect){
				/* Remove possible FD_SET from above, we don't want to check
				 * for writing if we are still connecting, unless want_write is
				 * definitely set. The presence of outgoing packets does not
				 * matter yet. */
				FD_CLR(ecld->sock, &writefds);
			}
		}
#endif
		pthread_mutex_unlock(&ecld->out_packet_mutex);
		pthread_mutex_unlock(&ecld->current_out_packet_mutex);
	}else{
#ifdef WITH_SRV
		if(ecld->achan){
			pthread_mutex_lock(&ecld->state_mutex);
			if(ecld->state == ecld_cs_connect_srv){
				rc = ares_fds(ecld->achan, &readfds, &writefds);
				if(rc > maxfd){
					maxfd = rc;
				}
			}else{
				pthread_mutex_unlock(&ecld->state_mutex);
				return ECLD_ERR_NO_CONN;
			}
			pthread_mutex_unlock(&ecld->state_mutex);
		}
#else
		return ECLD_ERR_NO_CONN;
#endif
	}
	if(ecld->sockpairR != INVALID_SOCKET){
		/* sockpairR is used to break out of select() before the timeout, on a
		 * call to publish() etc. */
		FD_SET(ecld->sockpairR, &readfds);
		if(ecld->sockpairR > maxfd){
			maxfd = ecld->sockpairR;
		}
	}

	if(timeout >= 0){
		local_timeout.tv_sec = timeout/1000;
#ifdef HAVE_PSELECT
		local_timeout.tv_nsec = (timeout-local_timeout.tv_sec*1000)*1e6;
#else
		local_timeout.tv_usec = (timeout-local_timeout.tv_sec*1000)*1000;
#endif
	}else{
		local_timeout.tv_sec = 1;
#ifdef HAVE_PSELECT
		local_timeout.tv_nsec = 0;
#else
		local_timeout.tv_usec = 0;
#endif
	}

#ifdef HAVE_PSELECT
	fdcount = pselect(maxfd+1, &readfds, &writefds, NULL, &local_timeout, NULL);
#else
	fdcount = select(maxfd+1, &readfds, &writefds, NULL, &local_timeout);
#endif
	if(fdcount == -1){
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		if(errno == EINTR){
			return ECLD_ERR_SUCCESS;
		}else{
			return ECLD_ERR_ERRNO;
		}
	}else{
		if(ecld->sock != INVALID_SOCKET){
			if(FD_ISSET(ecld->sock, &readfds)){
#ifdef WITH_TLS
				if(ecld->want_connect){
					rc = eecloud__socket_connect_tls(ecld);
					if(rc) return rc;
				}else
#endif
				{
					rc = eecloud_loop_read(ecld, max_packets);
					if(rc || ecld->sock == INVALID_SOCKET){
						return rc;
					}
				}
			}
			if(ecld->sockpairR != INVALID_SOCKET && FD_ISSET(ecld->sockpairR, &readfds)){
#ifndef WIN32
				if(read(ecld->sockpairR, &pairbuf, 1) == 0){
				}
#else
				recv(ecld->sockpairR, &pairbuf, 1, 0);
#endif
				/* Fake write possible, to stimulate output write even though
				 * we didn't ask for it, because at that point the publish or
				 * other command wasn't present. */
				FD_SET(ecld->sock, &writefds);
			}
			if(FD_ISSET(ecld->sock, &writefds)){
#ifdef WITH_TLS
				if(ecld->want_connect){
					rc = eecloud__socket_connect_tls(ecld);
					if(rc) return rc;
				}else
#endif
				{
					rc = eecloud_loop_write(ecld, max_packets);
					if(rc || ecld->sock == INVALID_SOCKET){
						return rc;
					}
				}
			}
		}
#ifdef WITH_SRV
		if(ecld->achan){
			ares_process(ecld->achan, &readfds, &writefds);
		}
#endif
	}
	return eecloud_loop_misc(ecld);
}

int eecloud_loop_forever(struct eecloud *ecld, int timeout, int max_packets)
{
	int run = 1;
	int rc;
	unsigned int reconnects = 0;
	unsigned long reconnect_delay;

	if(!ecld) return ECLD_ERR_INVAL;

	if(ecld->state == ecld_cs_connect_async){
		eecloud_reconnect(ecld);
	}

	while(run){
		do{
			rc = eecloud_loop(ecld, timeout, max_packets);
			if (reconnects !=0 && rc == ECLD_ERR_SUCCESS){
				reconnects = 0;
			}
		}while(run && rc == ECLD_ERR_SUCCESS);
		/* Quit after fatal errors. */
		switch(rc){
			case ECLD_ERR_NOMEM:
			case ECLD_ERR_PROTOCOL:
			case ECLD_ERR_INVAL:
			case ECLD_ERR_NOT_FOUND:
			case ECLD_ERR_TLS:
			case ECLD_ERR_PAYLOAD_SIZE:
			case ECLD_ERR_NOT_SUPPORTED:
			case ECLD_ERR_AUTH:
			case ECLD_ERR_ACL_DENIED:
			case ECLD_ERR_UNKNOWN:
			case ECLD_ERR_EAI:
			case ECLD_ERR_PROXY:
				return rc;
			case ECLD_ERR_ERRNO:
				break;
		}
		if(errno == EPROTO){
			return rc;
		}
		do{
			rc = ECLD_ERR_SUCCESS;
			pthread_mutex_lock(&ecld->state_mutex);
			if(ecld->state == ecld_cs_disconnecting){
				run = 0;
				pthread_mutex_unlock(&ecld->state_mutex);
			}else{
				pthread_mutex_unlock(&ecld->state_mutex);

				if(ecld->reconnect_delay > 0 && ecld->reconnect_exponential_backoff){
					reconnect_delay = ecld->reconnect_delay*reconnects*reconnects;
				}else{
					reconnect_delay = ecld->reconnect_delay;
				}

				if(reconnect_delay > ecld->reconnect_delay_max){
					reconnect_delay = ecld->reconnect_delay_max;
				}else{
					reconnects++;
				}

#ifdef WIN32
				Sleep(reconnect_delay*1000);
#else
				sleep(reconnect_delay);
#endif

				pthread_mutex_lock(&ecld->state_mutex);
				if(ecld->state == ecld_cs_disconnecting){
					run = 0;
					pthread_mutex_unlock(&ecld->state_mutex);
				}else{
					pthread_mutex_unlock(&ecld->state_mutex);
					rc = eecloud_reconnect(ecld);
				}
			}
		}while(run && rc != ECLD_ERR_SUCCESS);
	}
	return rc;
}

int eecloud_loop_misc(struct eecloud *ecld)
{
	time_t now;
	int rc;

	if(!ecld) return ECLD_ERR_INVAL;
	if(ecld->sock == INVALID_SOCKET) return ECLD_ERR_NO_CONN;

	_eecloud_check_keepalive(ecld);
	now = eecloud_time();
	if(ecld->last_retry_check+1 < now){
		_eecloud_message_retry_check(ecld);
		ecld->last_retry_check = now;
	}
	if(ecld->ping_t && now - ecld->ping_t >= ecld->keepalive){
		/* ecld->ping_t != 0 means we are waiting for a pingresp.
		 * This hasn't happened in the keepalive time so we should disconnect.
		 */
		_eecloud_socket_close(ecld);
		pthread_mutex_lock(&ecld->state_mutex);
		if(ecld->state == ecld_cs_disconnecting){
			rc = ECLD_ERR_SUCCESS;
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
		return ECLD_ERR_CONN_LOST;
	}
	return ECLD_ERR_SUCCESS;
}

static int _eecloud_loop_rc_handle(struct eecloud *ecld, int rc)
{
	if(rc){
		_eecloud_socket_close(ecld);
		pthread_mutex_lock(&ecld->state_mutex);
		if(ecld->state == ecld_cs_disconnecting){
			rc = ECLD_ERR_SUCCESS;
		}
		pthread_mutex_unlock(&ecld->state_mutex);
		pthread_mutex_lock(&ecld->callback_mutex);
		if(ecld->on_disconnect){
			ecld->in_callback = true;
			ecld->on_disconnect(ecld, ecld->userdata, rc);
			ecld->in_callback = false;
		}
		pthread_mutex_unlock(&ecld->callback_mutex);
		return rc;
	}
	return rc;
}

int eecloud_loop_read(struct eecloud *ecld, int max_packets)
{
	int rc;
	int i;
	if(max_packets < 1) return ECLD_ERR_INVAL;

	pthread_mutex_lock(&ecld->out_message_mutex);
	max_packets = ecld->out_queue_len;
	pthread_mutex_unlock(&ecld->out_message_mutex);

	pthread_mutex_lock(&ecld->in_message_mutex);
	max_packets += ecld->in_queue_len;
	pthread_mutex_unlock(&ecld->in_message_mutex);

	if(max_packets < 1) max_packets = 1;
	/* Queue len here tells us how many messages are awaiting processing and
	 * have QoS > 0. We should try to deal with that many in this loop in order
	 * to keep up. */
	for(i=0; i<max_packets; i++){
#ifdef WITH_SOCKS
		if(ecld->socks5_host){
			rc = eecloud__socks5_read(ecld);
		}else
#endif
		{
			rc = _eecloud_packet_read(ecld);
		}
		if(rc || errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
			return _eecloud_loop_rc_handle(ecld, rc);
		}
	}
	return rc;
}

int eecloud_loop_write(struct eecloud *ecld, int max_packets)
{
	int rc;
	int i;
	if(max_packets < 1) return ECLD_ERR_INVAL;

	pthread_mutex_lock(&ecld->out_message_mutex);
	max_packets = ecld->out_queue_len;
	pthread_mutex_unlock(&ecld->out_message_mutex);

	pthread_mutex_lock(&ecld->in_message_mutex);
	max_packets += ecld->in_queue_len;
	pthread_mutex_unlock(&ecld->in_message_mutex);

	if(max_packets < 1) max_packets = 1;
	/* Queue len here tells us how many messages are awaiting processing and
	 * have QoS > 0. We should try to deal with that many in this loop in order
	 * to keep up. */
	for(i=0; i<max_packets; i++){
		rc = _eecloud_packet_write(ecld);
		if(rc || errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
			return _eecloud_loop_rc_handle(ecld, rc);
		}
	}
	return rc;
}

bool eecloud_want_write(struct eecloud *ecld)
{
	if(ecld->out_packet || ecld->current_out_packet){
		return true;
#ifdef WITH_TLS
	}else if(ecld->ssl && ecld->want_write){
		return true;
#endif
	}else{
		return false;
	}
}

int eecloud_opts_set(struct eecloud *ecld, enum ecld_opt_t option, void *value)
{
	int ival;

	if(!ecld || !value) return ECLD_ERR_INVAL;

	switch(option){
		case ECLD_OPT_PROTOCOL_VERSION:
			ival = *((int *)value);
			if(ival == MQTT_PROTOCOL_V31){
				ecld->protocol = ecld_p_mqtt31;
			}else if(ival == MQTT_PROTOCOL_V311){
				ecld->protocol = ecld_p_mqtt311;
			}else{
				return ECLD_ERR_INVAL;
			}
			break;
		default:
			return ECLD_ERR_INVAL;
	}
	return ECLD_ERR_SUCCESS;
}


void eecloud_connect_callback_set(struct eecloud *ecld, void (*on_connect)(struct eecloud *, void *, int))
{
	pthread_mutex_lock(&ecld->callback_mutex);
	ecld->on_connect = on_connect;
	pthread_mutex_unlock(&ecld->callback_mutex);
}

void eecloud_disconnect_callback_set(struct eecloud *ecld, void (*on_disconnect)(struct eecloud *, void *, int))
{
	pthread_mutex_lock(&ecld->callback_mutex);
	ecld->on_disconnect = on_disconnect;
	pthread_mutex_unlock(&ecld->callback_mutex);
}

void eecloud_publish_callback_set(struct eecloud *ecld, void (*on_publish)(struct eecloud *, void *, int))
{
	pthread_mutex_lock(&ecld->callback_mutex);
	ecld->on_publish = on_publish;
	pthread_mutex_unlock(&ecld->callback_mutex);
}

void eecloud_message_callback_set(struct eecloud *ecld, void (*on_message)(struct eecloud *, void *, const struct eecloud_message *))
{
	pthread_mutex_lock(&ecld->callback_mutex);
	ecld->on_message = on_message;
	pthread_mutex_unlock(&ecld->callback_mutex);
}

void eecloud_subscribe_callback_set(struct eecloud *ecld, void (*on_subscribe)(struct eecloud *, void *, int, int, const int *))
{
	pthread_mutex_lock(&ecld->callback_mutex);
	ecld->on_subscribe = on_subscribe;
	pthread_mutex_unlock(&ecld->callback_mutex);
}

void eecloud_unsubscribe_callback_set(struct eecloud *ecld, void (*on_unsubscribe)(struct eecloud *, void *, int))
{
	pthread_mutex_lock(&ecld->callback_mutex);
	ecld->on_unsubscribe = on_unsubscribe;
	pthread_mutex_unlock(&ecld->callback_mutex);
}

void eecloud_log_callback_set(struct eecloud *ecld, void (*on_log)(struct eecloud *, void *, int, const char *))
{
	pthread_mutex_lock(&ecld->log_callback_mutex);
	ecld->on_log = on_log;
	pthread_mutex_unlock(&ecld->log_callback_mutex);
}

void eecloud_user_data_set(struct eecloud *ecld, void *userdata)
{
	if(ecld){
		ecld->userdata = userdata;
	}
}

const char *eecloud_strerror(int ecld_errno)
{
	switch(ecld_errno){
		case ECLD_ERR_SUCCESS:
			return "No error.";
		case ECLD_ERR_NOMEM:
			return "Out of memory.";
		case ECLD_ERR_PROTOCOL:
			return "A network protocol error occurred when communicating with the broker.";
		case ECLD_ERR_INVAL:
			return "Invalid function arguments provided.";
		case ECLD_ERR_NO_CONN:
			return "The client is not currently connected.";
		case ECLD_ERR_CONN_REFUSED:
			return "The connection was refused.";
		case ECLD_ERR_NOT_FOUND:
			return "Message not found (internal error).";
		case ECLD_ERR_CONN_LOST:
			return "The connection was lost.";
		case ECLD_ERR_TLS:
			return "A TLS error occurred.";
		case ECLD_ERR_PAYLOAD_SIZE:
			return "Payload too large.";
		case ECLD_ERR_NOT_SUPPORTED:
			return "This feature is not supported.";
		case ECLD_ERR_AUTH:
			return "Authorisation failed.";
		case ECLD_ERR_ACL_DENIED:
			return "Access denied by ACL.";
		case ECLD_ERR_UNKNOWN:
			return "Unknown error.";
		case ECLD_ERR_ERRNO:
			return strerror(errno);
		case ECLD_ERR_PROXY:
			return "Proxy error.";
		default:
			return "Unknown error.";
	}
}

const char *eecloud_connack_string(int connack_code)
{
	switch(connack_code){
		case 0:
			return "Connection Accepted.";
		case 1:
			return "Connection Refused: unacceptable protocol version.";
		case 2:
			return "Connection Refused: identifier rejected.";
		case 3:
			return "Connection Refused: broker unavailable.";
		case 4:
			return "Connection Refused: bad user name or password.";
		case 5:
			return "Connection Refused: not authorised.";
		default:
			return "Connection Refused: unknown reason.";
	}
}

int eecloud_sub_topic_tokenise(const char *subtopic, char ***topics, int *count)
{
	int len;
	int hier_count = 1;
	int start, stop;
	int hier;
	int tlen;
	int i, j;

	if(!subtopic || !topics || !count) return ECLD_ERR_INVAL;

	len = strlen(subtopic);

	for(i=0; i<len; i++){
		if(subtopic[i] == '/'){
			if(i > len-1){
				/* Separator at end of line */
			}else{
				hier_count++;
			}
		}
	}

	(*topics) = _eecloud_calloc(hier_count, sizeof(char *));
	if(!(*topics)) return ECLD_ERR_NOMEM;

	start = 0;
	stop = 0;
	hier = 0;

	for(i=0; i<len+1; i++){
		if(subtopic[i] == '/' || subtopic[i] == '\0'){
			stop = i;
			if(start != stop){
				tlen = stop-start + 1;
				(*topics)[hier] = _eecloud_calloc(tlen, sizeof(char));
				if(!(*topics)[hier]){
					for(i=0; i<hier_count; i++){
						if((*topics)[hier]){
							_eecloud_free((*topics)[hier]);
						}
					}
					_eecloud_free((*topics));
					return ECLD_ERR_NOMEM;
				}
				for(j=start; j<stop; j++){
					(*topics)[hier][j-start] = subtopic[j];
				}
			}
			start = i+1;
			hier++;
		}
	}

	*count = hier_count;

	return ECLD_ERR_SUCCESS;
}

int eecloud_sub_topic_tokens_free(char ***topics, int count)
{
	int i;

	if(!topics || !(*topics) || count<1) return ECLD_ERR_INVAL;

	for(i=0; i<count; i++){
		if((*topics)[i]) _eecloud_free((*topics)[i]);
	}
	_eecloud_free(*topics);

	return ECLD_ERR_SUCCESS;
}

