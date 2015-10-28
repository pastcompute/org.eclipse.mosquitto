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
#ifndef _UTIL_ECLD_H_
#define _UTIL_ECLD_H_

#include <stdio.h>

#include "tls_ecld.h"
#include "eecloud.h"
#include "eecloud_internal.h"
#ifdef WITH_BROKER
#  include "eecloud_broker.h"
#endif

int _eecloud_packet_alloc(struct _eecloud_packet *packet);
#ifdef WITH_BROKER
void _eecloud_check_keepalive(struct eecloud_db *db, struct eecloud *ecld);
#else
void _eecloud_check_keepalive(struct eecloud *ecld);
#endif
uint16_t _eecloud_mid_generate(struct eecloud *ecld);
FILE *_eecloud_fopen(const char *path, const char *mode);

#ifdef REAL_WITH_TLS_PSK
int _eecloud_hex2bin(const char *hex, unsigned char *bin, int bin_max_len);
#endif

#endif
