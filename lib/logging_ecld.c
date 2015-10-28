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
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <eecloud_internal.h>
#include <eecloud.h>
#include <memory_ecld.h>

int _eecloud_log_printf(struct eecloud *ecld, int priority, const char *fmt, ...)
{
	va_list va;
	char *s;
	int len;

	assert(ecld);
	assert(fmt);

	pthread_mutex_lock(&ecld->log_callback_mutex);
	if(ecld->on_log){
		len = strlen(fmt) + 500;
		s = _eecloud_malloc(len*sizeof(char));
		if(!s){
			pthread_mutex_unlock(&ecld->log_callback_mutex);
			return ECLD_ERR_NOMEM;
		}

		va_start(va, fmt);
		vsnprintf(s, len, fmt, va);
		va_end(va);
		s[len-1] = '\0'; /* Ensure string is null terminated. */

		ecld->on_log(ecld, ecld->userdata, priority, s);

		_eecloud_free(s);
	}
	pthread_mutex_unlock(&ecld->log_callback_mutex);

	return ECLD_ERR_SUCCESS;
}

