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

#include <stdio.h>
#include <string.h>

#include <eecloud_internal.h>
#include <memory_ecld.h>
#include <mqtt3_protocol.h>

int _eecloud_will_set(struct eecloud *ecld, const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
	int rc = ECLD_ERR_SUCCESS;

	if(!ecld || !topic) return ECLD_ERR_INVAL;
	if(payloadlen < 0 || payloadlen > MQTT_MAX_PAYLOAD) return ECLD_ERR_PAYLOAD_SIZE;
	if(payloadlen > 0 && !payload) return ECLD_ERR_INVAL;

	if(eecloud_pub_topic_check(topic)) return ECLD_ERR_INVAL;

	if(ecld->will){
		if(ecld->will->topic){
			_eecloud_free(ecld->will->topic);
			ecld->will->topic = NULL;
		}
		if(ecld->will->payload){
			_eecloud_free(ecld->will->payload);
			ecld->will->payload = NULL;
		}
		_eecloud_free(ecld->will);
		ecld->will = NULL;
	}

	ecld->will = _eecloud_calloc(1, sizeof(struct eecloud_message));
	if(!ecld->will) return ECLD_ERR_NOMEM;
	ecld->will->topic = _eecloud_strdup(topic);
	if(!ecld->will->topic){
		rc = ECLD_ERR_NOMEM;
		goto cleanup;
	}
	ecld->will->payloadlen = payloadlen;
	if(ecld->will->payloadlen > 0){
		if(!payload){
			rc = ECLD_ERR_INVAL;
			goto cleanup;
		}
		ecld->will->payload = _eecloud_malloc(sizeof(char)*ecld->will->payloadlen);
		if(!ecld->will->payload){
			rc = ECLD_ERR_NOMEM;
			goto cleanup;
		}

		memcpy(ecld->will->payload, payload, payloadlen);
	}
	ecld->will->qos = qos;
	ecld->will->retain = retain;

	return ECLD_ERR_SUCCESS;

cleanup:
	if(ecld->will){
		if(ecld->will->topic) _eecloud_free(ecld->will->topic);
		if(ecld->will->payload) _eecloud_free(ecld->will->payload);
	}
	_eecloud_free(ecld->will);
	ecld->will = NULL;

	return rc;
}

int _eecloud_will_clear(struct eecloud *ecld)
{
	if(!ecld->will) return ECLD_ERR_SUCCESS;

	if(ecld->will->topic){
		_eecloud_free(ecld->will->topic);
		ecld->will->topic = NULL;
	}
	if(ecld->will->payload){
		_eecloud_free(ecld->will->payload);
		ecld->will->payload = NULL;
	}
	_eecloud_free(ecld->will);
	ecld->will = NULL;

	return ECLD_ERR_SUCCESS;
}

