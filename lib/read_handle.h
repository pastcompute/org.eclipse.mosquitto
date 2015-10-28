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
#ifndef _READ_HANDLE_H_
#define _READ_HANDLE_H_

#include <eecloud.h>
struct eecloud_db;

int _eecloud_packet_handle(struct eecloud *ecld);
int _eecloud_handle_connack(struct eecloud *ecld);
int _eecloud_handle_pingreq(struct eecloud *ecld);
int _eecloud_handle_pingresp(struct eecloud *ecld);
#ifdef WITH_BROKER
int _eecloud_handle_pubackcomp(struct eecloud_db *db, struct eecloud *ecld, const char *type);
#else
int _eecloud_handle_pubackcomp(struct eecloud *ecld, const char *type);
#endif
int _eecloud_handle_publish(struct eecloud *ecld);
int _eecloud_handle_pubrec(struct eecloud *ecld);
int _eecloud_handle_pubrel(struct eecloud_db *db, struct eecloud *ecld);
int _eecloud_handle_suback(struct eecloud *ecld);
int _eecloud_handle_unsuback(struct eecloud *ecld);


#endif
