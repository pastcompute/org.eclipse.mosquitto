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

#ifndef _WILL_ECLD_H_
#define _WILL_ECLD_H_

#include <eecloud.h>
#include <eecloud_internal.h>

int _eecloud_will_set(struct eecloud *ecld, const char *topic, int payloadlen, const void *payload, int qos, bool retain);
int _eecloud_will_clear(struct eecloud *ecld);

#endif
