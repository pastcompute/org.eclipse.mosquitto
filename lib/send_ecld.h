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
#ifndef _SEND_MOSQ_H_
#define _SEND_MOSQ_H_

#include <eecloud.h>

int _eecloud_send_simple_command(struct eecloud *ecld, uint8_t command);
int _eecloud_send_command_with_mid(struct eecloud *ecld, uint8_t command, uint16_t mid, bool dup);
int _eecloud_send_real_publish(struct eecloud *ecld, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, int qos, bool retain, bool dup);

int _eecloud_send_connect(struct eecloud *ecld, uint16_t keepalive, bool clean_session);
int _eecloud_send_disconnect(struct eecloud *ecld);
int _eecloud_send_pingreq(struct eecloud *ecld);
int _eecloud_send_pingresp(struct eecloud *ecld);
int _eecloud_send_puback(struct eecloud *ecld, uint16_t mid);
int _eecloud_send_pubcomp(struct eecloud *ecld, uint16_t mid);
int _eecloud_send_publish(struct eecloud *ecld, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, int qos, bool retain, bool dup);
int _eecloud_send_pubrec(struct eecloud *ecld, uint16_t mid);
int _eecloud_send_pubrel(struct eecloud *ecld, uint16_t mid);
int _eecloud_send_subscribe(struct eecloud *ecld, int *mid, const char *topic, uint8_t topic_qos);
int _eecloud_send_unsubscribe(struct eecloud *ecld, int *mid, const char *topic);

#endif
