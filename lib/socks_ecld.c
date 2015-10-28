/*
Copyright (c) 2014 Roger Light <roger@atchoo.org>

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

#include <errno.h>
#include <string.h>

#include "eecloud_internal.h"
#include "memory_ecld.h"
#include "net_ecld.h"
#include "send_ecld.h"

#define SOCKS_AUTH_NONE 0x00
#define SOCKS_AUTH_GSS 0x01
#define SOCKS_AUTH_USERPASS 0x02
#define SOCKS_AUTH_NO_ACCEPTABLE 0xFF

#define SOCKS_ATYPE_IP_V4 1 /* four bytes */
#define SOCKS_ATYPE_DOMAINNAME 3 /* one byte length, followed by fqdn no null, 256 max chars */
#define SOCKS_ATYPE_IP_V6 4 /* 16 bytes */

#define SOCKS_REPLY_SUCCEEDED 0x00
#define SOCKS_REPLY_GENERAL_FAILURE 0x01
#define SOCKS_REPLY_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS_REPLY_NETWORK_UNREACHABLE 0x03
#define SOCKS_REPLY_HOST_UNREACHABLE 0x04
#define SOCKS_REPLY_CONNECTION_REFUSED 0x05
#define SOCKS_REPLY_TTL_EXPIRED 0x06
#define SOCKS_REPLY_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED 0x08

int eecloud_socks5_set(struct eecloud *ecld, const char *host, int port, const char *username, const char *password)
{
#ifdef WITH_SOCKS
	if(!ecld) return ECLD_ERR_INVAL;
	if(!host || strlen(host) > 256) return ECLD_ERR_INVAL;
	if(port < 1 || port > 65535) return ECLD_ERR_INVAL;

	if(ecld->socks5_host){
		_eecloud_free(ecld->socks5_host);
	}

	ecld->socks5_host = _eecloud_strdup(host);
	if(!ecld->socks5_host){
		return ECLD_ERR_NOMEM;
	}

	ecld->socks5_port = port;

	if(ecld->socks5_username){
		_eecloud_free(ecld->socks5_username);
	}
	if(ecld->socks5_password){
		_eecloud_free(ecld->socks5_password);
	}

	if(username){
		ecld->socks5_username = _eecloud_strdup(username);
		if(!ecld->socks5_username){
			return ECLD_ERR_NOMEM;
		}

		if(password){
			ecld->socks5_password = _eecloud_strdup(password);
			if(!ecld->socks5_password){
				_eecloud_free(ecld->socks5_username);
				return ECLD_ERR_NOMEM;
			}
		}
	}

	return ECLD_ERR_SUCCESS;
#else
	return ECLD_ERR_NOT_SUPPORTED;
#endif
}

#ifdef WITH_SOCKS
int eecloud__socks5_send(struct eecloud *ecld)
{
	struct _eecloud_packet *packet;
	int slen;
	int ulen, plen;

	if(ecld->state == ecld_cs_socks5_new){
		packet = _eecloud_calloc(1, sizeof(struct _eecloud_packet));
		if(!packet) return ECLD_ERR_NOMEM;

		if(ecld->socks5_username){
			packet->packet_length = 4;
		}else{
			packet->packet_length = 3;
		}
		packet->payload = _eecloud_malloc(sizeof(uint8_t)*packet->packet_length);

		packet->payload[0] = 0x05;
		if(ecld->socks5_username){
			packet->payload[1] = 2;
			packet->payload[2] = SOCKS_AUTH_NONE;
			packet->payload[3] = SOCKS_AUTH_USERPASS;
		}else{
			packet->payload[1] = 1;
			packet->payload[2] = SOCKS_AUTH_NONE;
		}

		pthread_mutex_lock(&ecld->state_mutex);
		ecld->state = ecld_cs_socks5_start;
		pthread_mutex_unlock(&ecld->state_mutex);

		ecld->in_packet.pos = 0;
		ecld->in_packet.packet_length = 2;
		ecld->in_packet.to_process = 2;
		ecld->in_packet.payload = _eecloud_malloc(sizeof(uint8_t)*2);
		if(!ecld->in_packet.payload){
			_eecloud_free(packet->payload);
			_eecloud_free(packet);
			return ECLD_ERR_NOMEM;
		}

		return _eecloud_packet_queue(ecld, packet);
	}else if(ecld->state == ecld_cs_socks5_auth_ok){
		packet = _eecloud_calloc(1, sizeof(struct _eecloud_packet));
		if(!packet) return ECLD_ERR_NOMEM;

		packet->packet_length = 7+strlen(ecld->host);
		packet->payload = _eecloud_malloc(sizeof(uint8_t)*packet->packet_length);

		slen = strlen(ecld->host);

		packet->payload[0] = 0x05;
		packet->payload[1] = 1;
		packet->payload[2] = 0;
		packet->payload[3] = SOCKS_ATYPE_DOMAINNAME;
		packet->payload[4] = slen;
		memcpy(&(packet->payload[5]), ecld->host, slen);
		packet->payload[5+slen] = ECLD_MSB(ecld->port);
		packet->payload[6+slen] = ECLD_LSB(ecld->port);

		pthread_mutex_lock(&ecld->state_mutex);
		ecld->state = ecld_cs_socks5_request;
		pthread_mutex_unlock(&ecld->state_mutex);

		ecld->in_packet.pos = 0;
		ecld->in_packet.packet_length = 5;
		ecld->in_packet.to_process = 5;
		ecld->in_packet.payload = _eecloud_malloc(sizeof(uint8_t)*5);
		if(!ecld->in_packet.payload){
			_eecloud_free(packet->payload);
			_eecloud_free(packet);
			return ECLD_ERR_NOMEM;
		}

		return _eecloud_packet_queue(ecld, packet);
	}else if(ecld->state == ecld_cs_socks5_send_userpass){
		packet = _eecloud_calloc(1, sizeof(struct _eecloud_packet));
		if(!packet) return ECLD_ERR_NOMEM;

		ulen = strlen(ecld->socks5_username);
		plen = strlen(ecld->socks5_password);
		packet->packet_length = 3 + ulen + plen;
		packet->payload = _eecloud_malloc(sizeof(uint8_t)*packet->packet_length);


		packet->payload[0] = 0x01;
		packet->payload[1] = ulen;
		memcpy(&(packet->payload[2]), ecld->socks5_username, ulen);
		packet->payload[2+ulen] = plen;
		memcpy(&(packet->payload[3+ulen]), ecld->socks5_password, plen);

		pthread_mutex_lock(&ecld->state_mutex);
		ecld->state = ecld_cs_socks5_userpass_reply;
		pthread_mutex_unlock(&ecld->state_mutex);

		ecld->in_packet.pos = 0;
		ecld->in_packet.packet_length = 2;
		ecld->in_packet.to_process = 2;
		ecld->in_packet.payload = _eecloud_malloc(sizeof(uint8_t)*2);
		if(!ecld->in_packet.payload){
			_eecloud_free(packet->payload);
			_eecloud_free(packet);
			return ECLD_ERR_NOMEM;
		}

		return _eecloud_packet_queue(ecld, packet);
	}
	return ECLD_ERR_SUCCESS;
}

int eecloud__socks5_read(struct eecloud *ecld)
{
	ssize_t len;
	uint8_t *payload;
	uint8_t i;

	if(ecld->state == ecld_cs_socks5_start){
		while(ecld->in_packet.to_process > 0){
			len = _eecloud_net_read(ecld, &(ecld->in_packet.payload[ecld->in_packet.pos]), ecld->in_packet.to_process);
			if(len > 0){
				ecld->in_packet.pos += len;
				ecld->in_packet.to_process -= len;
			}else{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					return ECLD_ERR_SUCCESS;
				}else{
					_eecloud_packet_cleanup(&ecld->in_packet);
					switch(errno){
						case 0:
							return ECLD_ERR_PROXY;
						case COMPAT_ECONNRESET:
							return ECLD_ERR_CONN_LOST;
						default:
							return ECLD_ERR_ERRNO;
					}
				}
			}
		}
		if(ecld->in_packet.payload[0] != 5){
			_eecloud_packet_cleanup(&ecld->in_packet);
			return ECLD_ERR_PROXY;
		}
		switch(ecld->in_packet.payload[1]){
			case SOCKS_AUTH_NONE:
				_eecloud_packet_cleanup(&ecld->in_packet);
				ecld->state = ecld_cs_socks5_auth_ok;
				return eecloud__socks5_send(ecld);
			case SOCKS_AUTH_USERPASS:
				_eecloud_packet_cleanup(&ecld->in_packet);
				ecld->state = ecld_cs_socks5_send_userpass;
				return eecloud__socks5_send(ecld);
			default:
				_eecloud_packet_cleanup(&ecld->in_packet);
				return ECLD_ERR_AUTH;
		}
	}else if(ecld->state == ecld_cs_socks5_userpass_reply){
		while(ecld->in_packet.to_process > 0){
			len = _eecloud_net_read(ecld, &(ecld->in_packet.payload[ecld->in_packet.pos]), ecld->in_packet.to_process);
			if(len > 0){
				ecld->in_packet.pos += len;
				ecld->in_packet.to_process -= len;
			}else{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					return ECLD_ERR_SUCCESS;
				}else{
					_eecloud_packet_cleanup(&ecld->in_packet);
					switch(errno){
						case 0:
							return ECLD_ERR_PROXY;
						case COMPAT_ECONNRESET:
							return ECLD_ERR_CONN_LOST;
						default:
							return ECLD_ERR_ERRNO;
					}
				}
			}
		}
		if(ecld->in_packet.payload[0] != 1){
			_eecloud_packet_cleanup(&ecld->in_packet);
			return ECLD_ERR_PROXY;
		}
		if(ecld->in_packet.payload[1] == 0){
			_eecloud_packet_cleanup(&ecld->in_packet);
			ecld->state = ecld_cs_socks5_auth_ok;
			return eecloud__socks5_send(ecld);
		}else{
			i = ecld->in_packet.payload[1];
			_eecloud_packet_cleanup(&ecld->in_packet);
			switch(i){
				case SOCKS_REPLY_CONNECTION_NOT_ALLOWED:
					return ECLD_ERR_AUTH;

				case SOCKS_REPLY_NETWORK_UNREACHABLE:
				case SOCKS_REPLY_HOST_UNREACHABLE:
				case SOCKS_REPLY_CONNECTION_REFUSED:
					return ECLD_ERR_NO_CONN;

				case SOCKS_REPLY_GENERAL_FAILURE:
				case SOCKS_REPLY_TTL_EXPIRED:
				case SOCKS_REPLY_COMMAND_NOT_SUPPORTED:
				case SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED:
					return ECLD_ERR_PROXY;

				default:
					return ECLD_ERR_INVAL;
			}
			return ECLD_ERR_PROXY;
		}
	}else if(ecld->state == ecld_cs_socks5_request){
		while(ecld->in_packet.to_process > 0){
			len = _eecloud_net_read(ecld, &(ecld->in_packet.payload[ecld->in_packet.pos]), ecld->in_packet.to_process);
			if(len > 0){
				ecld->in_packet.pos += len;
				ecld->in_packet.to_process -= len;
			}else{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					return ECLD_ERR_SUCCESS;
				}else{
					_eecloud_packet_cleanup(&ecld->in_packet);
					switch(errno){
						case 0:
							return ECLD_ERR_PROXY;
						case COMPAT_ECONNRESET:
							return ECLD_ERR_CONN_LOST;
						default:
							return ECLD_ERR_ERRNO;
					}
				}
			}
		}

		if(ecld->in_packet.packet_length == 5){
			/* First part of the packet has been received, we now know what else to expect. */
			if(ecld->in_packet.payload[3] == SOCKS_ATYPE_IP_V4){
				ecld->in_packet.to_process += 4+2-1; /* 4 bytes IPv4, 2 bytes port, -1 byte because we've already read the first byte */
				ecld->in_packet.packet_length += 4+2-1;
			}else if(ecld->in_packet.payload[3] == SOCKS_ATYPE_IP_V6){
				ecld->in_packet.to_process += 16+2-1; /* 16 bytes IPv6, 2 bytes port, -1 byte because we've already read the first byte */
				ecld->in_packet.packet_length += 16+2-1;
			}else if(ecld->in_packet.payload[3] == SOCKS_ATYPE_DOMAINNAME){
				if(ecld->in_packet.payload[4] > 0 && ecld->in_packet.payload[4] <= 255){
					ecld->in_packet.to_process += ecld->in_packet.payload[4];
					ecld->in_packet.packet_length += ecld->in_packet.payload[4];
				}
			}else{
				_eecloud_packet_cleanup(&ecld->in_packet);
				return ECLD_ERR_PROTOCOL;
			}
			payload = _eecloud_realloc(ecld->in_packet.payload, ecld->in_packet.packet_length);
			if(payload){
				ecld->in_packet.payload = payload;
			}else{
				_eecloud_packet_cleanup(&ecld->in_packet);
				return ECLD_ERR_NOMEM;
			}
			payload = _eecloud_realloc(ecld->in_packet.payload, ecld->in_packet.packet_length);
			if(payload){
				ecld->in_packet.payload = payload;
			}else{
				_eecloud_packet_cleanup(&ecld->in_packet);
				return ECLD_ERR_NOMEM;
			}
			return ECLD_ERR_SUCCESS;
		}

		/* Entire packet is now read. */
		if(ecld->in_packet.payload[0] != 5){
			_eecloud_packet_cleanup(&ecld->in_packet);
			return ECLD_ERR_PROXY;
		}
		if(ecld->in_packet.payload[1] == 0){
			/* Auth passed */
			_eecloud_packet_cleanup(&ecld->in_packet);
			ecld->state = ecld_cs_new;
			return _eecloud_send_connect(ecld, ecld->keepalive, ecld->clean_session);
		}else{
			i = ecld->in_packet.payload[1];
			_eecloud_packet_cleanup(&ecld->in_packet);
			ecld->state = ecld_cs_socks5_new;
			switch(i){
				case SOCKS_REPLY_CONNECTION_NOT_ALLOWED:
					return ECLD_ERR_AUTH;

				case SOCKS_REPLY_NETWORK_UNREACHABLE:
				case SOCKS_REPLY_HOST_UNREACHABLE:
				case SOCKS_REPLY_CONNECTION_REFUSED:
					return ECLD_ERR_NO_CONN;

				case SOCKS_REPLY_GENERAL_FAILURE:
				case SOCKS_REPLY_TTL_EXPIRED:
				case SOCKS_REPLY_COMMAND_NOT_SUPPORTED:
				case SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED:
					return ECLD_ERR_PROXY;

				default:
					return ECLD_ERR_INVAL;
			}
		}
	}else{
		return _eecloud_packet_read(ecld);
	}
	return ECLD_ERR_SUCCESS;
}
#endif
