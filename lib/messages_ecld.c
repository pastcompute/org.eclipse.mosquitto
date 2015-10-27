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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <eecloud_internal.h>
#include <eecloud.h>
#include <memory_ecld.h>
#include <messages_ecld.h>
#include <send_ecld.h>
#include <time_ecld.h>

void _eecloud_message_cleanup(struct eecloud_message_all **message)
{
	struct eecloud_message_all *msg;

	if(!message || !*message) return;

	msg = *message;

	if(msg->msg.topic) _eecloud_free(msg->msg.topic);
	if(msg->msg.payload) _eecloud_free(msg->msg.payload);
	_eecloud_free(msg);
}

void _eecloud_message_cleanup_all(struct eecloud *ecld)
{
	struct eecloud_message_all *tmp;

	assert(ecld);

	while(ecld->in_messages){
		tmp = ecld->in_messages->next;
		_eecloud_message_cleanup(&ecld->in_messages);
		ecld->in_messages = tmp;
	}
	while(ecld->out_messages){
		tmp = ecld->out_messages->next;
		_eecloud_message_cleanup(&ecld->out_messages);
		ecld->out_messages = tmp;
	}
}

int eecloud_message_copy(struct eecloud_message *dst, const struct eecloud_message *src)
{
	if(!dst || !src) return MOSQ_ERR_INVAL;

	dst->mid = src->mid;
	dst->topic = _eecloud_strdup(src->topic);
	if(!dst->topic) return MOSQ_ERR_NOMEM;
	dst->qos = src->qos;
	dst->retain = src->retain;
	if(src->payloadlen){
		dst->payload = _eecloud_malloc(src->payloadlen);
		if(!dst->payload){
			_eecloud_free(dst->topic);
			return MOSQ_ERR_NOMEM;
		}
		memcpy(dst->payload, src->payload, src->payloadlen);
		dst->payloadlen = src->payloadlen;
	}else{
		dst->payloadlen = 0;
		dst->payload = NULL;
	}
	return MOSQ_ERR_SUCCESS;
}

int _eecloud_message_delete(struct eecloud *ecld, uint16_t mid, enum eecloud_msg_direction dir)
{
	struct eecloud_message_all *message;
	int rc;
	assert(ecld);

	rc = _eecloud_message_remove(ecld, mid, dir, &message);
	if(rc == MOSQ_ERR_SUCCESS){
		_eecloud_message_cleanup(&message);
	}
	return rc;
}

void eecloud_message_free(struct eecloud_message **message)
{
	struct eecloud_message *msg;

	if(!message || !*message) return;

	msg = *message;

	if(msg->topic) _eecloud_free(msg->topic);
	if(msg->payload) _eecloud_free(msg->payload);
	_eecloud_free(msg);
}

void _eecloud_message_queue(struct eecloud *ecld, struct eecloud_message_all *message, enum eecloud_msg_direction dir)
{
	/* ecld->*_message_mutex should be locked before entering this function */
	assert(ecld);
	assert(message);

	if(dir == ecld_md_out){
		ecld->out_queue_len++;
		message->next = NULL;
		if(ecld->out_messages_last){
			ecld->out_messages_last->next = message;
		}else{
			ecld->out_messages = message;
		}
		ecld->out_messages_last = message;
		if(message->msg.qos > 0 && (ecld->max_inflight_messages == 0 || ecld->inflight_messages < ecld->max_inflight_messages)){
			ecld->inflight_messages++;
		}
	}else{
		ecld->in_queue_len++;
		message->next = NULL;
		if(ecld->in_messages_last){
			ecld->in_messages_last->next = message;
		}else{
			ecld->in_messages = message;
		}
		ecld->in_messages_last = message;
	}
}

void _eecloud_messages_reconnect_reset(struct eecloud *ecld)
{
	struct eecloud_message_all *message;
	struct eecloud_message_all *prev = NULL;
	assert(ecld);

	pthread_mutex_lock(&ecld->in_message_mutex);
	message = ecld->in_messages;
	ecld->in_queue_len = 0;
	while(message){
		ecld->in_queue_len++;
		message->timestamp = 0;
		if(message->msg.qos != 2){
			if(prev){
				prev->next = message->next;
				_eecloud_message_cleanup(&message);
				message = prev;
			}else{
				ecld->in_messages = message->next;
				_eecloud_message_cleanup(&message);
				message = ecld->in_messages;
			}
		}else{
			/* Message state can be preserved here because it should match
			* whatever the client has got. */
		}
		prev = message;
		message = message->next;
	}
	ecld->in_messages_last = prev;
	pthread_mutex_unlock(&ecld->in_message_mutex);


	pthread_mutex_lock(&ecld->out_message_mutex);
	ecld->inflight_messages = 0;
	message = ecld->out_messages;
	ecld->out_queue_len = 0;
	while(message){
		ecld->out_queue_len++;
		message->timestamp = 0;

		if(message->msg.qos > 0){
			ecld->inflight_messages++;
		}
		if(ecld->max_inflight_messages == 0 || ecld->inflight_messages < ecld->max_inflight_messages){
			if(message->msg.qos == 1){
				message->state = ecld_ms_wait_for_puback;
			}else if(message->msg.qos == 2){
				/* Should be able to preserve state. */
			}
		}else{
			message->state = ecld_ms_invalid;
		}
		prev = message;
		message = message->next;
	}
	ecld->out_messages_last = prev;
	pthread_mutex_unlock(&ecld->out_message_mutex);
}

int _eecloud_message_remove(struct eecloud *ecld, uint16_t mid, enum eecloud_msg_direction dir, struct eecloud_message_all **message)
{
	struct eecloud_message_all *cur, *prev = NULL;
	bool found = false;
	int rc;
	assert(ecld);
	assert(message);

	if(dir == ecld_md_out){
		pthread_mutex_lock(&ecld->out_message_mutex);
		cur = ecld->out_messages;
		while(cur){
			if(cur->msg.mid == mid){
				if(prev){
					prev->next = cur->next;
				}else{
					ecld->out_messages = cur->next;
				}
				*message = cur;
				ecld->out_queue_len--;
				if(cur->next == NULL){
					ecld->out_messages_last = prev;
				}else if(!ecld->out_messages){
					ecld->out_messages_last = NULL;
				}
				if(cur->msg.qos > 0){
					ecld->inflight_messages--;
				}
				found = true;
				break;
			}
			prev = cur;
			cur = cur->next;
		}

		if(found){
			cur = ecld->out_messages;
			while(cur){
				if(ecld->max_inflight_messages == 0 || ecld->inflight_messages < ecld->max_inflight_messages){
					if(cur->msg.qos > 0 && cur->state == ecld_ms_invalid){
						ecld->inflight_messages++;
						if(cur->msg.qos == 1){
							cur->state = ecld_ms_wait_for_puback;
						}else if(cur->msg.qos == 2){
							cur->state = ecld_ms_wait_for_pubrec;
						}
						rc = _eecloud_send_publish(ecld, cur->msg.mid, cur->msg.topic, cur->msg.payloadlen, cur->msg.payload, cur->msg.qos, cur->msg.retain, cur->dup);
						if(rc){
							pthread_mutex_unlock(&ecld->out_message_mutex);
							return rc;
						}
					}
				}else{
					pthread_mutex_unlock(&ecld->out_message_mutex);
					return MOSQ_ERR_SUCCESS;
				}
				cur = cur->next;
			}
			pthread_mutex_unlock(&ecld->out_message_mutex);
			return MOSQ_ERR_SUCCESS;
		}else{
			pthread_mutex_unlock(&ecld->out_message_mutex);
			return MOSQ_ERR_NOT_FOUND;
		}
	}else{
		pthread_mutex_lock(&ecld->in_message_mutex);
		cur = ecld->in_messages;
		while(cur){
			if(cur->msg.mid == mid){
				if(prev){
					prev->next = cur->next;
				}else{
					ecld->in_messages = cur->next;
				}
				*message = cur;
				ecld->in_queue_len--;
				if(cur->next == NULL){
					ecld->in_messages_last = prev;
				}else if(!ecld->in_messages){
					ecld->in_messages_last = NULL;
				}
				found = true;
				break;
			}
			prev = cur;
			cur = cur->next;
		}

		pthread_mutex_unlock(&ecld->in_message_mutex);
		if(found){
			return MOSQ_ERR_SUCCESS;
		}else{
			return MOSQ_ERR_NOT_FOUND;
		}
	}
}

#ifdef WITH_THREADING
void _eecloud_message_retry_check_actual(struct eecloud *ecld, struct eecloud_message_all *messages, pthread_mutex_t *mutex)
#else
void _eecloud_message_retry_check_actual(struct eecloud *ecld, struct eecloud_message_all *messages)
#endif
{
	time_t now = eecloud_time();
	assert(ecld);

#ifdef WITH_THREADING
	pthread_mutex_lock(mutex);
#endif

	while(messages){
		if(messages->timestamp + ecld->message_retry < now){
			switch(messages->state){
				case ecld_ms_wait_for_puback:
				case ecld_ms_wait_for_pubrec:
					messages->timestamp = now;
					messages->dup = true;
					_eecloud_send_publish(ecld, messages->msg.mid, messages->msg.topic, messages->msg.payloadlen, messages->msg.payload, messages->msg.qos, messages->msg.retain, messages->dup);
					break;
				case ecld_ms_wait_for_pubrel:
					messages->timestamp = now;
					messages->dup = true;
					_eecloud_send_pubrec(ecld, messages->msg.mid);
					break;
				case ecld_ms_wait_for_pubcomp:
					messages->timestamp = now;
					messages->dup = true;
					_eecloud_send_pubrel(ecld, messages->msg.mid);
					break;
				default:
					break;
			}
		}
		messages = messages->next;
	}
#ifdef WITH_THREADING
	pthread_mutex_unlock(mutex);
#endif
}

void _eecloud_message_retry_check(struct eecloud *ecld)
{
#ifdef WITH_THREADING
	_eecloud_message_retry_check_actual(ecld, ecld->out_messages, &ecld->out_message_mutex);
	_eecloud_message_retry_check_actual(ecld, ecld->in_messages, &ecld->in_message_mutex);
#else
	_eecloud_message_retry_check_actual(ecld, ecld->out_messages);
	_eecloud_message_retry_check_actual(ecld, ecld->in_messages);
#endif
}

void eecloud_message_retry_set(struct eecloud *ecld, unsigned int message_retry)
{
	assert(ecld);
	if(ecld) ecld->message_retry = message_retry;
}

int _eecloud_message_out_update(struct eecloud *ecld, uint16_t mid, enum eecloud_msg_state state)
{
	struct eecloud_message_all *message;
	assert(ecld);

	pthread_mutex_lock(&ecld->out_message_mutex);
	message = ecld->out_messages;
	while(message){
		if(message->msg.mid == mid){
			message->state = state;
			message->timestamp = eecloud_time();
			pthread_mutex_unlock(&ecld->out_message_mutex);
			return MOSQ_ERR_SUCCESS;
		}
		message = message->next;
	}
	pthread_mutex_unlock(&ecld->out_message_mutex);
	return MOSQ_ERR_NOT_FOUND;
}

int eecloud_max_inflight_messages_set(struct eecloud *ecld, unsigned int max_inflight_messages)
{
	if(!ecld) return MOSQ_ERR_INVAL;

	ecld->max_inflight_messages = max_inflight_messages;

	return MOSQ_ERR_SUCCESS;
}

