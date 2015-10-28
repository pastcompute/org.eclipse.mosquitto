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

#include <cstdlib>
#include <eecloud.h>
#include <eecloudpp.h>

namespace ecldpp {

static void on_connect_wrapper(struct eecloud *ecld, void *userdata, int rc)
{
	class eecloudpp *m = (class eecloudpp *)userdata;
	m->on_connect(rc);
}

static void on_disconnect_wrapper(struct eecloud *ecld, void *userdata, int rc)
{
	class eecloudpp *m = (class eecloudpp *)userdata;
	m->on_disconnect(rc);
}

static void on_publish_wrapper(struct eecloud *ecld, void *userdata, int mid)
{
	class eecloudpp *m = (class eecloudpp *)userdata;
	m->on_publish(mid);
}

static void on_message_wrapper(struct eecloud *ecld, void *userdata, const struct eecloud_message *message)
{
	class eecloudpp *m = (class eecloudpp *)userdata;
	m->on_message(message);
}

static void on_subscribe_wrapper(struct eecloud *ecld, void *userdata, int mid, int qos_count, const int *granted_qos)
{
	class eecloudpp *m = (class eecloudpp *)userdata;
	m->on_subscribe(mid, qos_count, granted_qos);
}

static void on_unsubscribe_wrapper(struct eecloud *ecld, void *userdata, int mid)
{
	class eecloudpp *m = (class eecloudpp *)userdata;
	m->on_unsubscribe(mid);
}


static void on_log_wrapper(struct eecloud *ecld, void *userdata, int level, const char *str)
{
	class eecloudpp *m = (class eecloudpp *)userdata;
	m->on_log(level, str);
}

int lib_version(int *major, int *minor, int *revision)
{
	if(major) *major = LIBEECLOUD_MAJOR;
	if(minor) *minor = LIBEECLOUD_MINOR;
	if(revision) *revision = LIBEECLOUD_REVISION;
	return LIBEECLOUD_VERSION_NUMBER;
}

int lib_init()
{
	return eecloud_lib_init();
}

int lib_cleanup()
{
	return eecloud_lib_cleanup();
}

const char* strerror(int ecld_errno)
{
	return eecloud_strerror(ecld_errno);
}

const char* connack_string(int connack_code)
{
	return eecloud_connack_string(connack_code);
}

int sub_topic_tokenise(const char *subtopic, char ***topics, int *count)
{
	return eecloud_sub_topic_tokenise(subtopic, topics, count);
}

int sub_topic_tokens_free(char ***topics, int count)
{
	return eecloud_sub_topic_tokens_free(topics, count);
}

int topic_matches_sub(const char *sub, const char *topic, bool *result)
{
	return eecloud_topic_matches_sub(sub, topic, result);
}

eecloudpp::eecloudpp(const char *id, bool clean_session)
{
	m_ecld = eecloud_new(id, clean_session, this);
	eecloud_connect_callback_set(m_ecld, on_connect_wrapper);
	eecloud_disconnect_callback_set(m_ecld, on_disconnect_wrapper);
	eecloud_publish_callback_set(m_ecld, on_publish_wrapper);
	eecloud_message_callback_set(m_ecld, on_message_wrapper);
	eecloud_subscribe_callback_set(m_ecld, on_subscribe_wrapper);
	eecloud_unsubscribe_callback_set(m_ecld, on_unsubscribe_wrapper);
	eecloud_log_callback_set(m_ecld, on_log_wrapper);
}

eecloudpp::~eecloudpp()
{
	eecloud_destroy(m_ecld);
}

int eecloudpp::reinitialise(const char *id, bool clean_session)
{
	int rc;
	rc = eecloud_reinitialise(m_ecld, id, clean_session, this);
	if(rc == ECLD_ERR_SUCCESS){
		eecloud_connect_callback_set(m_ecld, on_connect_wrapper);
		eecloud_disconnect_callback_set(m_ecld, on_disconnect_wrapper);
		eecloud_publish_callback_set(m_ecld, on_publish_wrapper);
		eecloud_message_callback_set(m_ecld, on_message_wrapper);
		eecloud_subscribe_callback_set(m_ecld, on_subscribe_wrapper);
		eecloud_unsubscribe_callback_set(m_ecld, on_unsubscribe_wrapper);
		eecloud_log_callback_set(m_ecld, on_log_wrapper);
	}
	return rc;
}

int eecloudpp::connect(const char *host, int port, int keepalive)
{
	return eecloud_connect(m_ecld, host, port, keepalive);
}

int eecloudpp::connect(const char *host, int port, int keepalive, const char *bind_address)
{
	return eecloud_connect_bind(m_ecld, host, port, keepalive, bind_address);
}

int eecloudpp::connect_async(const char *host, int port, int keepalive)
{
	return eecloud_connect_async(m_ecld, host, port, keepalive);
}

int eecloudpp::connect_async(const char *host, int port, int keepalive, const char *bind_address)
{
	return eecloud_connect_bind_async(m_ecld, host, port, keepalive, bind_address);
}

int eecloudpp::reconnect()
{
	return eecloud_reconnect(m_ecld);
}

int eecloudpp::reconnect_async()
{
	return eecloud_reconnect_async(m_ecld);
}

int eecloudpp::disconnect()
{
	return eecloud_disconnect(m_ecld);
}

int eecloudpp::socket()
{
	return eecloud_socket(m_ecld);
}

int eecloudpp::will_set(const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
	return eecloud_will_set(m_ecld, topic, payloadlen, payload, qos, retain);
}

int eecloudpp::will_clear()
{
	return eecloud_will_clear(m_ecld);
}

int eecloudpp::username_pw_set(const char *username, const char *password)
{
	return eecloud_username_pw_set(m_ecld, username, password);
}

int eecloudpp::publish(int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
	return eecloud_publish(m_ecld, mid, topic, payloadlen, payload, qos, retain);
}

void eecloudpp::reconnect_delay_set(unsigned int reconnect_delay, unsigned int reconnect_delay_max, bool reconnect_exponential_backoff)
{
	eecloud_reconnect_delay_set(m_ecld, reconnect_delay, reconnect_delay_max, reconnect_exponential_backoff);
}

int eecloudpp::max_inflight_messages_set(unsigned int max_inflight_messages)
{
	return eecloud_max_inflight_messages_set(m_ecld, max_inflight_messages);
}

void eecloudpp::message_retry_set(unsigned int message_retry)
{
	eecloud_message_retry_set(m_ecld, message_retry);
}

int eecloudpp::subscribe(int *mid, const char *sub, int qos)
{
	return eecloud_subscribe(m_ecld, mid, sub, qos);
}

int eecloudpp::unsubscribe(int *mid, const char *sub)
{
	return eecloud_unsubscribe(m_ecld, mid, sub);
}

int eecloudpp::loop(int timeout, int max_packets)
{
	return eecloud_loop(m_ecld, timeout, max_packets);
}

int eecloudpp::loop_misc()
{
	return eecloud_loop_misc(m_ecld);
}

int eecloudpp::loop_read(int max_packets)
{
	return eecloud_loop_read(m_ecld, max_packets);
}

int eecloudpp::loop_write(int max_packets)
{
	return eecloud_loop_write(m_ecld, max_packets);
}

int eecloudpp::loop_forever(int timeout, int max_packets)
{
	return eecloud_loop_forever(m_ecld, timeout, max_packets);
}

int eecloudpp::loop_start()
{
	return eecloud_loop_start(m_ecld);
}

int eecloudpp::loop_stop(bool force)
{
	return eecloud_loop_stop(m_ecld, force);
}

bool eecloudpp::want_write()
{
	return eecloud_want_write(m_ecld);
}

int eecloudpp::opts_set(enum ecld_opt_t option, void *value)
{
	return eecloud_opts_set(m_ecld, option, value);
}

int eecloudpp::threaded_set(bool threaded)
{
	return eecloud_threaded_set(m_ecld, threaded);
}

void eecloudpp::user_data_set(void *userdata)
{
	eecloud_user_data_set(m_ecld, userdata);
}

int eecloudpp::socks5_set(const char *host, int port, const char *username, const char *password)
{
#ifdef WITH_SOCKS
	return eecloud_socks5_set(m_ecld, host, port, username, password);
#else
	return ECLD_ERR_NOT_SUPPORTED;
#endif
}


int eecloudpp::tls_set(const char *cafile, const char *capath, const char *certfile, const char *keyfile, int (*pw_callback)(char *buf, int size, int rwflag, void *userdata))
{
	return eecloud_tls_set(m_ecld, cafile, capath, certfile, keyfile, pw_callback);
}

int eecloudpp::tls_opts_set(int cert_reqs, const char *tls_version, const char *ciphers)
{
	return eecloud_tls_opts_set(m_ecld, cert_reqs, tls_version, ciphers);
}

int eecloudpp::tls_insecure_set(bool value)
{
	return eecloud_tls_insecure_set(m_ecld, value);
}

int eecloudpp::tls_psk_set(const char *psk, const char *identity, const char *ciphers)
{
	return eecloud_tls_psk_set(m_ecld, psk, identity, ciphers);
}

}
