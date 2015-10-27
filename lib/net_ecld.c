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
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef __ANDROID__
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/endian.h>
#endif

#ifdef __FreeBSD__
#  include <netinet/in.h>
#endif

#ifdef __SYMBIAN32__
#include <netinet/in.h>
#endif

#ifdef __QNX__
#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG 0
#endif
#include <net/netbyte.h>
#include <netinet/in.h>
#endif

#ifdef WITH_TLS
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <tls_ecld.h>
#endif

#ifdef WITH_BROKER
#  include <eecloud_broker.h>
#  ifdef WITH_SYS_TREE
   extern uint64_t g_bytes_received;
   extern uint64_t g_bytes_sent;
   extern unsigned long g_msgs_received;
   extern unsigned long g_msgs_sent;
   extern unsigned long g_pub_msgs_received;
   extern unsigned long g_pub_msgs_sent;
#  endif
#  ifdef WITH_WEBSOCKETS
#    include <libwebsockets.h>
#  endif
#else
#  include <read_handle.h>
#endif

#include <logging_ecld.h>
#include <memory_ecld.h>
#include <mqtt3_protocol.h>
#include <net_ecld.h>
#include <time_ecld.h>
#include <util_ecld.h>

#include "config.h"

#ifdef WITH_TLS
int tls_ex_index_ecld = -1;
#endif

void _eecloud_net_init(void)
{
#ifdef WIN32
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2,2), &wsaData);
#endif

#ifdef WITH_SRV
	ares_library_init(ARES_LIB_INIT_ALL);
#endif

#ifdef WITH_TLS
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	if(tls_ex_index_ecld == -1){
		tls_ex_index_ecld = SSL_get_ex_new_index(0, "client context", NULL, NULL, NULL);
	}
#endif
}

void _eecloud_net_cleanup(void)
{
#ifdef WITH_TLS
	ERR_remove_state(0);
	ENGINE_cleanup();
	CONF_modules_unload(1);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
#endif

#ifdef WITH_SRV
	ares_library_cleanup();
#endif

#ifdef WIN32
	WSACleanup();
#endif
}

void _eecloud_packet_cleanup(struct _eecloud_packet *packet)
{
	if(!packet) return;

	/* Free data and reset values */
	packet->command = 0;
	packet->remaining_count = 0;
	packet->remaining_mult = 1;
	packet->remaining_length = 0;
	if(packet->payload) _eecloud_free(packet->payload);
	packet->payload = NULL;
	packet->to_process = 0;
	packet->pos = 0;
}

int _eecloud_packet_queue(struct eecloud *ecld, struct _eecloud_packet *packet)
{
#ifndef WITH_BROKER
	char sockpair_data = 0;
#endif
	assert(ecld);
	assert(packet);

	packet->pos = 0;
	packet->to_process = packet->packet_length;

	packet->next = NULL;
	pthread_mutex_lock(&ecld->out_packet_mutex);
	if(ecld->out_packet){
		ecld->out_packet_last->next = packet;
	}else{
		ecld->out_packet = packet;
	}
	ecld->out_packet_last = packet;
	pthread_mutex_unlock(&ecld->out_packet_mutex);
#ifdef WITH_BROKER
#  ifdef WITH_WEBSOCKETS
	if(ecld->wsi){
		libwebsocket_callback_on_writable(ecld->ws_context, ecld->wsi);
		return 0;
	}else{
		return _eecloud_packet_write(ecld);
	}
#  else
	return _eecloud_packet_write(ecld);
#  endif
#else

	/* Write a single byte to sockpairW (connected to sockpairR) to break out
	 * of select() if in threaded mode. */
	if(ecld->sockpairW != INVALID_SOCKET){
#ifndef WIN32
		if(write(ecld->sockpairW, &sockpair_data, 1)){
		}
#else
		send(ecld->sockpairW, &sockpair_data, 1, 0);
#endif
	}

	if(ecld->in_callback == false && ecld->threaded == false){
		return _eecloud_packet_write(ecld);
	}else{
		return MOSQ_ERR_SUCCESS;
	}
#endif
}

/* Close a socket associated with a context and set it to -1.
 * Returns 1 on failure (context is NULL)
 * Returns 0 on success.
 */
#ifdef WITH_BROKER
int _eecloud_socket_close(struct eecloud_db *db, struct eecloud *ecld)
#else
int _eecloud_socket_close(struct eecloud *ecld)
#endif
{
	int rc = 0;

	assert(ecld);
#ifdef WITH_TLS
	if(ecld->ssl){
		SSL_shutdown(ecld->ssl);
		SSL_free(ecld->ssl);
		ecld->ssl = NULL;
	}
	if(ecld->ssl_ctx){
		SSL_CTX_free(ecld->ssl_ctx);
		ecld->ssl_ctx = NULL;
	}
#endif

	if((int)ecld->sock >= 0){
#ifdef WITH_BROKER
		HASH_DELETE(hh_sock, db->contexts_by_sock, ecld);
#endif
		rc = COMPAT_CLOSE(ecld->sock);
		ecld->sock = INVALID_SOCKET;
#ifdef WITH_WEBSOCKETS
	}else if(ecld->sock == WEBSOCKET_CLIENT){
		if(ecld->state != ecld_cs_disconnecting){
			ecld->state = ecld_cs_disconnect_ws;
		}
		if(ecld->wsi){
			libwebsocket_callback_on_writable(ecld->ws_context, ecld->wsi);
		}
		ecld->sock = INVALID_SOCKET;
#endif
	}

#ifdef WITH_BROKER
	if(ecld->listener){
		ecld->listener->client_count--;
		assert(ecld->listener->client_count >= 0);
		ecld->listener = NULL;
	}
#endif

	return rc;
}

#ifdef REAL_WITH_TLS_PSK
static unsigned int psk_client_callback(SSL *ssl, const char *hint,
		char *identity, unsigned int max_identity_len,
		unsigned char *psk, unsigned int max_psk_len)
{
	struct eecloud *ecld;
	int len;

	ecld = SSL_get_ex_data(ssl, tls_ex_index_ecld);
	if(!ecld) return 0;

	snprintf(identity, max_identity_len, "%s", ecld->tls_psk_identity);

	len = _eecloud_hex2bin(ecld->tls_psk, psk, max_psk_len);
	if (len < 0) return 0;
	return len;
}
#endif

int _eecloud_try_connect(struct eecloud *ecld, const char *host, uint16_t port, ecld_sock_t *sock, const char *bind_address, bool blocking)
{
	struct addrinfo hints;
	struct addrinfo *ainfo, *rp;
	struct addrinfo *ainfo_bind, *rp_bind;
	int s;
	int rc = MOSQ_ERR_SUCCESS;
#ifdef WIN32
	uint32_t val = 1;
#endif

	*sock = INVALID_SOCKET;
	memset(&hints, 0, sizeof(struct addrinfo));
#ifdef WITH_TLS
	if(ecld->tls_cafile || ecld->tls_capath || ecld->tls_psk){
		hints.ai_family = PF_INET;
	}else
#endif
	{
		hints.ai_family = PF_UNSPEC;
	}
	hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_STREAM;

	s = getaddrinfo(host, NULL, &hints, &ainfo);
	if(s){
		errno = s;
		return MOSQ_ERR_EAI;
	}

	if(bind_address){
		s = getaddrinfo(bind_address, NULL, &hints, &ainfo_bind);
		if(s){
			freeaddrinfo(ainfo);
			errno = s;
			return MOSQ_ERR_EAI;
		}
	}

	for(rp = ainfo; rp != NULL; rp = rp->ai_next){
		*sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(*sock == INVALID_SOCKET) continue;
		
		if(rp->ai_family == PF_INET){
			((struct sockaddr_in *)rp->ai_addr)->sin_port = htons(port);
		}else if(rp->ai_family == PF_INET6){
			((struct sockaddr_in6 *)rp->ai_addr)->sin6_port = htons(port);
		}else{
			COMPAT_CLOSE(*sock);
			continue;
		}

		if(bind_address){
			for(rp_bind = ainfo_bind; rp_bind != NULL; rp_bind = rp_bind->ai_next){
				if(bind(*sock, rp_bind->ai_addr, rp_bind->ai_addrlen) == 0){
					break;
				}
			}
			if(!rp_bind){
				COMPAT_CLOSE(*sock);
				continue;
			}
		}

		if(!blocking){
			/* Set non-blocking */
			if(_eecloud_socket_nonblock(*sock)){
				COMPAT_CLOSE(*sock);
				continue;
			}
		}

		rc = connect(*sock, rp->ai_addr, rp->ai_addrlen);
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		if(rc == 0 || errno == EINPROGRESS || errno == COMPAT_EWOULDBLOCK){
			if(rc < 0 && (errno == EINPROGRESS || errno == COMPAT_EWOULDBLOCK)){
				rc = MOSQ_ERR_CONN_PENDING;
			}

			if(blocking){
				/* Set non-blocking */
				if(_eecloud_socket_nonblock(*sock)){
					COMPAT_CLOSE(*sock);
					continue;
				}
			}
			break;
		}

		COMPAT_CLOSE(*sock);
		*sock = INVALID_SOCKET;
	}
	freeaddrinfo(ainfo);
	if(bind_address){
		freeaddrinfo(ainfo_bind);
	}
	if(!rp){
		return MOSQ_ERR_ERRNO;
	}
	return rc;
}

#ifdef WITH_TLS
int eecloud__socket_connect_tls(struct eecloud *ecld)
{
	int ret;

	ret = SSL_connect(ecld->ssl);
	if(ret != 1){
		ret = SSL_get_error(ecld->ssl, ret);
		if(ret == SSL_ERROR_WANT_READ){
			ecld->want_connect = true;
			/* We always try to read anyway */
		}else if(ret == SSL_ERROR_WANT_WRITE){
			ecld->want_write = true;
			ecld->want_connect = true;
		}else{
			COMPAT_CLOSE(ecld->sock);
			ecld->sock = INVALID_SOCKET;
			return MOSQ_ERR_TLS;
		}
	}else{
		ecld->want_connect = false;
	}
	return MOSQ_ERR_SUCCESS;
}
#endif

/* Create a socket and connect it to 'ip' on port 'port'.
 * Returns -1 on failure (ip is NULL, socket creation/connection error)
 * Returns sock number on success.
 */
int _eecloud_socket_connect(struct eecloud *ecld, const char *host, uint16_t port, const char *bind_address, bool blocking)
{
	ecld_sock_t sock = INVALID_SOCKET;
	int rc;
#ifdef WITH_TLS
	int ret;
	BIO *bio;
#endif

	if(!ecld || !host || !port) return MOSQ_ERR_INVAL;

	rc = _eecloud_try_connect(ecld, host, port, &sock, bind_address, blocking);
	if(rc > 0) return rc;

#ifdef WITH_TLS
	if(ecld->tls_cafile || ecld->tls_capath || ecld->tls_psk){
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
		if(!ecld->tls_version || !strcmp(ecld->tls_version, "tlsv1.2")){
			ecld->ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
		}else if(!strcmp(ecld->tls_version, "tlsv1.1")){
			ecld->ssl_ctx = SSL_CTX_new(TLSv1_1_client_method());
		}else if(!strcmp(ecld->tls_version, "tlsv1")){
			ecld->ssl_ctx = SSL_CTX_new(TLSv1_client_method());
		}else{
			_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Protocol %s not supported.", ecld->tls_version);
			COMPAT_CLOSE(sock);
			return MOSQ_ERR_INVAL;
		}
#else
		if(!ecld->tls_version || !strcmp(ecld->tls_version, "tlsv1")){
			ecld->ssl_ctx = SSL_CTX_new(TLSv1_client_method());
		}else{
			_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Protocol %s not supported.", ecld->tls_version);
			COMPAT_CLOSE(sock);
			return MOSQ_ERR_INVAL;
		}
#endif
		if(!ecld->ssl_ctx){
			_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Unable to create TLS context.");
			COMPAT_CLOSE(sock);
			return MOSQ_ERR_TLS;
		}

#if OPENSSL_VERSION_NUMBER >= 0x10000000
		/* Disable compression */
		SSL_CTX_set_options(ecld->ssl_ctx, SSL_OP_NO_COMPRESSION);
#endif
#ifdef SSL_MODE_RELEASE_BUFFERS
			/* Use even less memory per SSL connection. */
			SSL_CTX_set_mode(ecld->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

		if(ecld->tls_ciphers){
			ret = SSL_CTX_set_cipher_list(ecld->ssl_ctx, ecld->tls_ciphers);
			if(ret == 0){
				_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Unable to set TLS ciphers. Check cipher list \"%s\".", ecld->tls_ciphers);
				COMPAT_CLOSE(sock);
				return MOSQ_ERR_TLS;
			}
		}
		if(ecld->tls_cafile || ecld->tls_capath){
			ret = SSL_CTX_load_verify_locations(ecld->ssl_ctx, ecld->tls_cafile, ecld->tls_capath);
			if(ret == 0){
#ifdef WITH_BROKER
				if(ecld->tls_cafile && ecld->tls_capath){
					_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check bridge_cafile \"%s\" and bridge_capath \"%s\".", ecld->tls_cafile, ecld->tls_capath);
				}else if(ecld->tls_cafile){
					_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check bridge_cafile \"%s\".", ecld->tls_cafile);
				}else{
					_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check bridge_capath \"%s\".", ecld->tls_capath);
				}
#else
				if(ecld->tls_cafile && ecld->tls_capath){
					_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check cafile \"%s\" and capath \"%s\".", ecld->tls_cafile, ecld->tls_capath);
				}else if(ecld->tls_cafile){
					_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check cafile \"%s\".", ecld->tls_cafile);
				}else{
					_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check capath \"%s\".", ecld->tls_capath);
				}
#endif
				COMPAT_CLOSE(sock);
				return MOSQ_ERR_TLS;
			}
			if(ecld->tls_cert_reqs == 0){
				SSL_CTX_set_verify(ecld->ssl_ctx, SSL_VERIFY_NONE, NULL);
			}else{
				SSL_CTX_set_verify(ecld->ssl_ctx, SSL_VERIFY_PEER, _eecloud_server_certificate_verify);
			}

			if(ecld->tls_pw_callback){
				SSL_CTX_set_default_passwd_cb(ecld->ssl_ctx, ecld->tls_pw_callback);
				SSL_CTX_set_default_passwd_cb_userdata(ecld->ssl_ctx, ecld);
			}

			if(ecld->tls_certfile){
				ret = SSL_CTX_use_certificate_chain_file(ecld->ssl_ctx, ecld->tls_certfile);
				if(ret != 1){
#ifdef WITH_BROKER
					_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Unable to load client certificate, check bridge_certfile \"%s\".", ecld->tls_certfile);
#else
					_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Unable to load client certificate \"%s\".", ecld->tls_certfile);
#endif
					COMPAT_CLOSE(sock);
					return MOSQ_ERR_TLS;
				}
			}
			if(ecld->tls_keyfile){
				ret = SSL_CTX_use_PrivateKey_file(ecld->ssl_ctx, ecld->tls_keyfile, SSL_FILETYPE_PEM);
				if(ret != 1){
#ifdef WITH_BROKER
					_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Unable to load client key file, check bridge_keyfile \"%s\".", ecld->tls_keyfile);
#else
					_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Unable to load client key file \"%s\".", ecld->tls_keyfile);
#endif
					COMPAT_CLOSE(sock);
					return MOSQ_ERR_TLS;
				}
				ret = SSL_CTX_check_private_key(ecld->ssl_ctx);
				if(ret != 1){
					_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "Error: Client certificate/key are inconsistent.");
					COMPAT_CLOSE(sock);
					return MOSQ_ERR_TLS;
				}
			}
#ifdef REAL_WITH_TLS_PSK
		}else if(ecld->tls_psk){
			SSL_CTX_set_psk_client_callback(ecld->ssl_ctx, psk_client_callback);
#endif
		}

		ecld->ssl = SSL_new(ecld->ssl_ctx);
		if(!ecld->ssl){
			COMPAT_CLOSE(sock);
			return MOSQ_ERR_TLS;
		}
		SSL_set_ex_data(ecld->ssl, tls_ex_index_ecld, ecld);
		bio = BIO_new_socket(sock, BIO_NOCLOSE);
		if(!bio){
			COMPAT_CLOSE(sock);
			return MOSQ_ERR_TLS;
		}
		SSL_set_bio(ecld->ssl, bio, bio);

		ecld->sock = sock;
		if(eecloud__socket_connect_tls(ecld)){
			return MOSQ_ERR_TLS;
		}

	}
#endif

	ecld->sock = sock;

	return rc;
}

int _eecloud_read_byte(struct _eecloud_packet *packet, uint8_t *byte)
{
	assert(packet);
	if(packet->pos+1 > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	*byte = packet->payload[packet->pos];
	packet->pos++;

	return MOSQ_ERR_SUCCESS;
}

void _eecloud_write_byte(struct _eecloud_packet *packet, uint8_t byte)
{
	assert(packet);
	assert(packet->pos+1 <= packet->packet_length);

	packet->payload[packet->pos] = byte;
	packet->pos++;
}

int _eecloud_read_bytes(struct _eecloud_packet *packet, void *bytes, uint32_t count)
{
	assert(packet);
	if(packet->pos+count > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	memcpy(bytes, &(packet->payload[packet->pos]), count);
	packet->pos += count;

	return MOSQ_ERR_SUCCESS;
}

void _eecloud_write_bytes(struct _eecloud_packet *packet, const void *bytes, uint32_t count)
{
	assert(packet);
	assert(packet->pos+count <= packet->packet_length);

	memcpy(&(packet->payload[packet->pos]), bytes, count);
	packet->pos += count;
}

int _eecloud_read_string(struct _eecloud_packet *packet, char **str)
{
	uint16_t len;
	int rc;

	assert(packet);
	rc = _eecloud_read_uint16(packet, &len);
	if(rc) return rc;

	if(packet->pos+len > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	*str = _eecloud_malloc(len+1);
	if(*str){
		memcpy(*str, &(packet->payload[packet->pos]), len);
		(*str)[len] = '\0';
		packet->pos += len;
	}else{
		return MOSQ_ERR_NOMEM;
	}

	return MOSQ_ERR_SUCCESS;
}

void _eecloud_write_string(struct _eecloud_packet *packet, const char *str, uint16_t length)
{
	assert(packet);
	_eecloud_write_uint16(packet, length);
	_eecloud_write_bytes(packet, str, length);
}

int _eecloud_read_uint16(struct _eecloud_packet *packet, uint16_t *word)
{
	uint8_t msb, lsb;

	assert(packet);
	if(packet->pos+2 > packet->remaining_length) return MOSQ_ERR_PROTOCOL;

	msb = packet->payload[packet->pos];
	packet->pos++;
	lsb = packet->payload[packet->pos];
	packet->pos++;

	*word = (msb<<8) + lsb;

	return MOSQ_ERR_SUCCESS;
}

void _eecloud_write_uint16(struct _eecloud_packet *packet, uint16_t word)
{
	_eecloud_write_byte(packet, MOSQ_MSB(word));
	_eecloud_write_byte(packet, MOSQ_LSB(word));
}

ssize_t _eecloud_net_read(struct eecloud *ecld, void *buf, size_t count)
{
#ifdef WITH_TLS
	int ret;
	int err;
	char ebuf[256];
	unsigned long e;
#endif
	assert(ecld);
	errno = 0;
#ifdef WITH_TLS
	if(ecld->ssl){
		ret = SSL_read(ecld->ssl, buf, count);
		if(ret <= 0){
			err = SSL_get_error(ecld->ssl, ret);
			if(err == SSL_ERROR_WANT_READ){
				ret = -1;
				errno = EAGAIN;
			}else if(err == SSL_ERROR_WANT_WRITE){
				ret = -1;
				ecld->want_write = true;
				errno = EAGAIN;
			}else{
				e = ERR_get_error();
				while(e){
					_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "OpenSSL Error: %s", ERR_error_string(e, ebuf));
					e = ERR_get_error();
				}
				errno = EPROTO;
			}
		}
		return (ssize_t )ret;
	}else{
		/* Call normal read/recv */

#endif

#ifndef WIN32
	return read(ecld->sock, buf, count);
#else
	return recv(ecld->sock, buf, count, 0);
#endif

#ifdef WITH_TLS
	}
#endif
}

ssize_t _eecloud_net_write(struct eecloud *ecld, void *buf, size_t count)
{
#ifdef WITH_TLS
	int ret;
	int err;
	char ebuf[256];
	unsigned long e;
#endif
	assert(ecld);

	errno = 0;
#ifdef WITH_TLS
	if(ecld->ssl){
		ret = SSL_write(ecld->ssl, buf, count);
		if(ret < 0){
			err = SSL_get_error(ecld->ssl, ret);
			if(err == SSL_ERROR_WANT_READ){
				ret = -1;
				errno = EAGAIN;
			}else if(err == SSL_ERROR_WANT_WRITE){
				ret = -1;
				ecld->want_write = true;
				errno = EAGAIN;
			}else{
				e = ERR_get_error();
				while(e){
					_eecloud_log_printf(ecld, MOSQ_LOG_ERR, "OpenSSL Error: %s", ERR_error_string(e, ebuf));
					e = ERR_get_error();
				}
				errno = EPROTO;
			}
		}
		return (ssize_t )ret;
	}else{
		/* Call normal write/send */
#endif

#ifndef WIN32
	return write(ecld->sock, buf, count);
#else
	return send(ecld->sock, buf, count, 0);
#endif

#ifdef WITH_TLS
	}
#endif
}

int _eecloud_packet_write(struct eecloud *ecld)
{
	ssize_t write_length;
	struct _eecloud_packet *packet;

	if(!ecld) return MOSQ_ERR_INVAL;
	if(ecld->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;

	pthread_mutex_lock(&ecld->current_out_packet_mutex);
	pthread_mutex_lock(&ecld->out_packet_mutex);
	if(ecld->out_packet && !ecld->current_out_packet){
		ecld->current_out_packet = ecld->out_packet;
		ecld->out_packet = ecld->out_packet->next;
		if(!ecld->out_packet){
			ecld->out_packet_last = NULL;
		}
	}
	pthread_mutex_unlock(&ecld->out_packet_mutex);

	if(ecld->state == ecld_cs_connect_pending){
		pthread_mutex_unlock(&ecld->current_out_packet_mutex);
		return MOSQ_ERR_SUCCESS;
	}

	while(ecld->current_out_packet){
		packet = ecld->current_out_packet;

		while(packet->to_process > 0){
			write_length = _eecloud_net_write(ecld, &(packet->payload[packet->pos]), packet->to_process);
			if(write_length > 0){
#if defined(WITH_BROKER) && defined(WITH_SYS_TREE)
				g_bytes_sent += write_length;
#endif
				packet->to_process -= write_length;
				packet->pos += write_length;
			}else{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					pthread_mutex_unlock(&ecld->current_out_packet_mutex);
					return MOSQ_ERR_SUCCESS;
				}else{
					pthread_mutex_unlock(&ecld->current_out_packet_mutex);
					switch(errno){
						case COMPAT_ECONNRESET:
							return MOSQ_ERR_CONN_LOST;
						default:
							return MOSQ_ERR_ERRNO;
					}
				}
			}
		}

#ifdef WITH_BROKER
#  ifdef WITH_SYS_TREE
		g_msgs_sent++;
		if(((packet->command)&0xF6) == PUBLISH){
			g_pub_msgs_sent++;
		}
#  endif
#else
		if(((packet->command)&0xF6) == PUBLISH){
			pthread_mutex_lock(&ecld->callback_mutex);
			if(ecld->on_publish){
				/* This is a QoS=0 message */
				ecld->in_callback = true;
				ecld->on_publish(ecld, ecld->userdata, packet->mid);
				ecld->in_callback = false;
			}
			pthread_mutex_unlock(&ecld->callback_mutex);
		}else if(((packet->command)&0xF0) == DISCONNECT){
			/* FIXME what cleanup needs doing here? 
			 * incoming/outgoing messages? */
			_eecloud_socket_close(ecld);

			/* Start of duplicate, possibly unnecessary code.
			 * This does leave things in a consistent state at least. */
			/* Free data and reset values */
			pthread_mutex_lock(&ecld->out_packet_mutex);
			ecld->current_out_packet = ecld->out_packet;
			if(ecld->out_packet){
				ecld->out_packet = ecld->out_packet->next;
				if(!ecld->out_packet){
					ecld->out_packet_last = NULL;
				}
			}
			pthread_mutex_unlock(&ecld->out_packet_mutex);

			_eecloud_packet_cleanup(packet);
			_eecloud_free(packet);

			pthread_mutex_lock(&ecld->msgtime_mutex);
			ecld->last_msg_out = eecloud_time();
			pthread_mutex_unlock(&ecld->msgtime_mutex);
			/* End of duplicate, possibly unnecessary code */

			pthread_mutex_lock(&ecld->callback_mutex);
			if(ecld->on_disconnect){
				ecld->in_callback = true;
				ecld->on_disconnect(ecld, ecld->userdata, 0);
				ecld->in_callback = false;
			}
			pthread_mutex_unlock(&ecld->callback_mutex);
			pthread_mutex_unlock(&ecld->current_out_packet_mutex);
			return MOSQ_ERR_SUCCESS;
		}
#endif

		/* Free data and reset values */
		pthread_mutex_lock(&ecld->out_packet_mutex);
		ecld->current_out_packet = ecld->out_packet;
		if(ecld->out_packet){
			ecld->out_packet = ecld->out_packet->next;
			if(!ecld->out_packet){
				ecld->out_packet_last = NULL;
			}
		}
		pthread_mutex_unlock(&ecld->out_packet_mutex);

		_eecloud_packet_cleanup(packet);
		_eecloud_free(packet);

		pthread_mutex_lock(&ecld->msgtime_mutex);
		ecld->last_msg_out = eecloud_time();
		pthread_mutex_unlock(&ecld->msgtime_mutex);
	}
	pthread_mutex_unlock(&ecld->current_out_packet_mutex);
	return MOSQ_ERR_SUCCESS;
}

#ifdef WITH_BROKER
int _eecloud_packet_read(struct eecloud_db *db, struct eecloud *ecld)
#else
int _eecloud_packet_read(struct eecloud *ecld)
#endif
{
	uint8_t byte;
	ssize_t read_length;
	int rc = 0;

	if(!ecld) return MOSQ_ERR_INVAL;
	if(ecld->sock == INVALID_SOCKET) return MOSQ_ERR_NO_CONN;
	if(ecld->state == ecld_cs_connect_pending){
		return MOSQ_ERR_SUCCESS;
	}

	/* This gets called if pselect() indicates that there is network data
	 * available - ie. at least one byte.  What we do depends on what data we
	 * already have.
	 * If we've not got a command, attempt to read one and save it. This should
	 * always work because it's only a single byte.
	 * Then try to read the remaining length. This may fail because it is may
	 * be more than one byte - will need to save data pending next read if it
	 * does fail.
	 * Then try to read the remaining payload, where 'payload' here means the
	 * combined variable header and actual payload. This is the most likely to
	 * fail due to longer length, so save current data and current position.
	 * After all data is read, send to _eecloud_handle_packet() to deal with.
	 * Finally, free the memory and reset everything to starting conditions.
	 */
	if(!ecld->in_packet.command){
		read_length = _eecloud_net_read(ecld, &byte, 1);
		if(read_length == 1){
			ecld->in_packet.command = byte;
#ifdef WITH_BROKER
#  ifdef WITH_SYS_TREE
			g_bytes_received++;
#  endif
			/* Clients must send CONNECT as their first command. */
			if(!(ecld->bridge) && ecld->state == ecld_cs_new && (byte&0xF0) != CONNECT) return MOSQ_ERR_PROTOCOL;
#endif
		}else{
			if(read_length == 0) return MOSQ_ERR_CONN_LOST; /* EOF */
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
				return MOSQ_ERR_SUCCESS;
			}else{
				switch(errno){
					case COMPAT_ECONNRESET:
						return MOSQ_ERR_CONN_LOST;
					default:
						return MOSQ_ERR_ERRNO;
				}
			}
		}
	}
	/* remaining_count is the number of bytes that the remaining_length
	 * parameter occupied in this incoming packet. We don't use it here as such
	 * (it is used when allocating an outgoing packet), but we must be able to
	 * determine whether all of the remaining_length parameter has been read.
	 * remaining_count has three states here:
	 *   0 means that we haven't read any remaining_length bytes
	 *   <0 means we have read some remaining_length bytes but haven't finished
	 *   >0 means we have finished reading the remaining_length bytes.
	 */
	if(ecld->in_packet.remaining_count <= 0){
		do{
			read_length = _eecloud_net_read(ecld, &byte, 1);
			if(read_length == 1){
				ecld->in_packet.remaining_count--;
				/* Max 4 bytes length for remaining length as defined by protocol.
				 * Anything more likely means a broken/malicious client.
				 */
				if(ecld->in_packet.remaining_count < -4) return MOSQ_ERR_PROTOCOL;

#if defined(WITH_BROKER) && defined(WITH_SYS_TREE)
				g_bytes_received++;
#endif
				ecld->in_packet.remaining_length += (byte & 127) * ecld->in_packet.remaining_mult;
				ecld->in_packet.remaining_mult *= 128;
			}else{
				if(read_length == 0) return MOSQ_ERR_CONN_LOST; /* EOF */
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					return MOSQ_ERR_SUCCESS;
				}else{
					switch(errno){
						case COMPAT_ECONNRESET:
							return MOSQ_ERR_CONN_LOST;
						default:
							return MOSQ_ERR_ERRNO;
					}
				}
			}
		}while((byte & 128) != 0);
		/* We have finished reading remaining_length, so make remaining_count
		 * positive. */
		ecld->in_packet.remaining_count *= -1;

		if(ecld->in_packet.remaining_length > 0){
			ecld->in_packet.payload = _eecloud_malloc(ecld->in_packet.remaining_length*sizeof(uint8_t));
			if(!ecld->in_packet.payload) return MOSQ_ERR_NOMEM;
			ecld->in_packet.to_process = ecld->in_packet.remaining_length;
		}
	}
	while(ecld->in_packet.to_process>0){
		read_length = _eecloud_net_read(ecld, &(ecld->in_packet.payload[ecld->in_packet.pos]), ecld->in_packet.to_process);
		if(read_length > 0){
#if defined(WITH_BROKER) && defined(WITH_SYS_TREE)
			g_bytes_received += read_length;
#endif
			ecld->in_packet.to_process -= read_length;
			ecld->in_packet.pos += read_length;
		}else{
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
				if(ecld->in_packet.to_process > 1000){
					/* Update last_msg_in time if more than 1000 bytes left to
					 * receive. Helps when receiving large messages.
					 * This is an arbitrary limit, but with some consideration.
					 * If a client can't send 1000 bytes in a second it
					 * probably shouldn't be using a 1 second keep alive. */
					pthread_mutex_lock(&ecld->msgtime_mutex);
					ecld->last_msg_in = eecloud_time();
					pthread_mutex_unlock(&ecld->msgtime_mutex);
				}
				return MOSQ_ERR_SUCCESS;
			}else{
				switch(errno){
					case COMPAT_ECONNRESET:
						return MOSQ_ERR_CONN_LOST;
					default:
						return MOSQ_ERR_ERRNO;
				}
			}
		}
	}

	/* All data for this packet is read. */
	ecld->in_packet.pos = 0;
#ifdef WITH_BROKER
#  ifdef WITH_SYS_TREE
	g_msgs_received++;
	if(((ecld->in_packet.command)&0xF5) == PUBLISH){
		g_pub_msgs_received++;
	}
#  endif
	rc = mqtt3_packet_handle(db, ecld);
#else
	rc = _eecloud_packet_handle(ecld);
#endif

	/* Free data and reset values */
	_eecloud_packet_cleanup(&ecld->in_packet);

	pthread_mutex_lock(&ecld->msgtime_mutex);
	ecld->last_msg_in = eecloud_time();
	pthread_mutex_unlock(&ecld->msgtime_mutex);
	return rc;
}

int _eecloud_socket_nonblock(ecld_sock_t sock)
{
#ifndef WIN32
	int opt;
	/* Set non-blocking */
	opt = fcntl(sock, F_GETFL, 0);
	if(opt == -1){
		COMPAT_CLOSE(sock);
		return 1;
	}
	if(fcntl(sock, F_SETFL, opt | O_NONBLOCK) == -1){
		/* If either fcntl fails, don't want to allow this client to connect. */
		COMPAT_CLOSE(sock);
		return 1;
	}
#else
	unsigned long opt = 1;
	if(ioctlsocket(sock, FIONBIO, &opt)){
		COMPAT_CLOSE(sock);
		return 1;
	}
#endif
	return 0;
}


#ifndef WITH_BROKER
int _eecloud_socketpair(ecld_sock_t *pairR, ecld_sock_t *pairW)
{
#ifdef WIN32
	int family[2] = {AF_INET, AF_INET6};
	int i;
	struct sockaddr_storage ss;
	struct sockaddr_in *sa = (struct sockaddr_in *)&ss;
	struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&ss;
	socklen_t ss_len;
	ecld_sock_t spR, spW;

	ecld_sock_t listensock;

	*pairR = INVALID_SOCKET;
	*pairW = INVALID_SOCKET;

	for(i=0; i<2; i++){
		memset(&ss, 0, sizeof(ss));
		if(family[i] == AF_INET){
			sa->sin_family = family[i];
			sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			sa->sin_port = 0;
			ss_len = sizeof(struct sockaddr_in);
		}else if(family[i] == AF_INET6){
			sa6->sin6_family = family[i];
			sa6->sin6_addr = in6addr_loopback;
			sa6->sin6_port = 0;
			ss_len = sizeof(struct sockaddr_in6);
		}else{
			return MOSQ_ERR_INVAL;
		}

		listensock = socket(family[i], SOCK_STREAM, IPPROTO_TCP);
		if(listensock == -1){
			continue;
		}

		if(bind(listensock, (struct sockaddr *)&ss, ss_len) == -1){
			COMPAT_CLOSE(listensock);
			continue;
		}

		if(listen(listensock, 1) == -1){
			COMPAT_CLOSE(listensock);
			continue;
		}
		memset(&ss, 0, sizeof(ss));
		ss_len = sizeof(ss);
		if(getsockname(listensock, (struct sockaddr *)&ss, &ss_len) < 0){
			COMPAT_CLOSE(listensock);
			continue;
		}

		if(_eecloud_socket_nonblock(listensock)){
			continue;
		}

		if(family[i] == AF_INET){
			sa->sin_family = family[i];
			sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			ss_len = sizeof(struct sockaddr_in);
		}else if(family[i] == AF_INET6){
			sa6->sin6_family = family[i];
			sa6->sin6_addr = in6addr_loopback;
			ss_len = sizeof(struct sockaddr_in6);
		}

		spR = socket(family[i], SOCK_STREAM, IPPROTO_TCP);
		if(spR == -1){
			COMPAT_CLOSE(listensock);
			continue;
		}
		if(_eecloud_socket_nonblock(spR)){
			COMPAT_CLOSE(listensock);
			continue;
		}
		if(connect(spR, (struct sockaddr *)&ss, ss_len) < 0){
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			if(errno != EINPROGRESS && errno != COMPAT_EWOULDBLOCK){
				COMPAT_CLOSE(spR);
				COMPAT_CLOSE(listensock);
				continue;
			}
		}
		spW = accept(listensock, NULL, 0);
		if(spW == -1){
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			if(errno != EINPROGRESS && errno != COMPAT_EWOULDBLOCK){
				COMPAT_CLOSE(spR);
				COMPAT_CLOSE(listensock);
				continue;
			}
		}

		if(_eecloud_socket_nonblock(spW)){
			COMPAT_CLOSE(spR);
			COMPAT_CLOSE(listensock);
			continue;
		}
		COMPAT_CLOSE(listensock);

		*pairR = spR;
		*pairW = spW;
		return MOSQ_ERR_SUCCESS;
	}
	return MOSQ_ERR_UNKNOWN;
#else
	int sv[2];

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1){
		return MOSQ_ERR_ERRNO;
	}
	if(_eecloud_socket_nonblock(sv[0])){
		COMPAT_CLOSE(sv[0]);
		COMPAT_CLOSE(sv[1]);
		return MOSQ_ERR_ERRNO;
	}
	if(_eecloud_socket_nonblock(sv[1])){
		COMPAT_CLOSE(sv[0]);
		COMPAT_CLOSE(sv[1]);
		return MOSQ_ERR_ERRNO;
	}
	*pairR = sv[0];
	*pairW = sv[1];
	return MOSQ_ERR_SUCCESS;
#endif
}
#endif
