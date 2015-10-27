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
#ifndef _MESSAGES_MOSQ_H_
#define _MESSAGES_MOSQ_H_

#include <eecloud_internal.h>
#include <eecloud.h>

void _eecloud_message_cleanup_all(struct eecloud *ecld);
void _eecloud_message_cleanup(struct eecloud_message_all **message);
int _eecloud_message_delete(struct eecloud *ecld, uint16_t mid, enum eecloud_msg_direction dir);
void _eecloud_message_queue(struct eecloud *ecld, struct eecloud_message_all *message, enum eecloud_msg_direction dir);
void _eecloud_messages_reconnect_reset(struct eecloud *ecld);
int _eecloud_message_remove(struct eecloud *ecld, uint16_t mid, enum eecloud_msg_direction dir, struct eecloud_message_all **message);
void _eecloud_message_retry_check(struct eecloud *ecld);
int _eecloud_message_out_update(struct eecloud *ecld, uint16_t mid, enum eecloud_msg_state state);

#endif
