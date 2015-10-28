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
#ifndef _NET_ECLD_H_
#define _NET_ECLD_H_

#ifndef WIN32
#include <unistd.h>
#else
#include <winsock2.h>
typedef int ssize_t;
#endif

#include <eecloud_internal.h>
#include <eecloud.h>

#ifdef WITH_BROKER
struct eecloud_db;
#endif

#ifdef WIN32
#  define COMPAT_CLOSE(a) closesocket(a)
#  define COMPAT_ECONNRESET WSAECONNRESET
#  define COMPAT_EWOULDBLOCK WSAEWOULDBLOCK
#else
#  define COMPAT_CLOSE(a) close(a)
#  define COMPAT_ECONNRESET ECONNRESET
#  define COMPAT_EWOULDBLOCK EWOULDBLOCK
#endif

/* For when not using winsock libraries. */
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

/* Macros for accessing the MSB and LSB of a uint16_t */
#define ECLD_MSB(A) (uint8_t)((A & 0xFF00) >> 8)
#define ECLD_LSB(A) (uint8_t)(A & 0x00FF)

void _eecloud_net_init(void);
void _eecloud_net_cleanup(void);

void _eecloud_packet_cleanup(struct _eecloud_packet *packet);
int _eecloud_packet_queue(struct eecloud *ecld, struct _eecloud_packet *packet);
int _eecloud_socket_connect(struct eecloud *ecld, const char *host, uint16_t port, const char *bind_address, bool blocking);
#ifdef WITH_BROKER
int _eecloud_socket_close(struct eecloud_db *db, struct eecloud *ecld);
#else
int _eecloud_socket_close(struct eecloud *ecld);
#endif
int _eecloud_try_connect(struct eecloud *ecld, const char *host, uint16_t port, ecld_sock_t *sock, const char *bind_address, bool blocking);
int _eecloud_socket_nonblock(ecld_sock_t sock);
int _eecloud_socketpair(ecld_sock_t *sp1, ecld_sock_t *sp2);

int _eecloud_read_byte(struct _eecloud_packet *packet, uint8_t *byte);
int _eecloud_read_bytes(struct _eecloud_packet *packet, void *bytes, uint32_t count);
int _eecloud_read_string(struct _eecloud_packet *packet, char **str);
int _eecloud_read_uint16(struct _eecloud_packet *packet, uint16_t *word);

void _eecloud_write_byte(struct _eecloud_packet *packet, uint8_t byte);
void _eecloud_write_bytes(struct _eecloud_packet *packet, const void *bytes, uint32_t count);
void _eecloud_write_string(struct _eecloud_packet *packet, const char *str, uint16_t length);
void _eecloud_write_uint16(struct _eecloud_packet *packet, uint16_t word);

ssize_t _eecloud_net_read(struct eecloud *ecld, void *buf, size_t count);
ssize_t _eecloud_net_write(struct eecloud *ecld, void *buf, size_t count);

int _eecloud_packet_write(struct eecloud *ecld);
#ifdef WITH_BROKER
int _eecloud_packet_read(struct eecloud_db *db, struct eecloud *ecld);
#else
int _eecloud_packet_read(struct eecloud *ecld);
#endif

#ifdef WITH_TLS
int _eecloud_socket_apply_tls(struct eecloud *ecld);
int eecloud__socket_connect_tls(struct eecloud *ecld);
#endif

#endif
