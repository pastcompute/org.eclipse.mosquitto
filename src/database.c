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
#include <stdio.h>

#include <config.h>

#include <eecloud_broker.h>
#include <memory_ecld.h>
#include <send_ecld.h>
#include <time_ecld.h>

static int max_inflight = 20;
static int max_queued = 100;
#ifdef WITH_SYS_TREE
extern unsigned long g_msgs_dropped;
#endif

int mqtt3_db_open(struct mqtt3_config *config, struct eecloud_db *db)
{
	int rc = 0;
	struct _eecloud_subhier *child;

	if(!config || !db) return MOSQ_ERR_INVAL;

	db->last_db_id = 0;

	db->contexts_by_id = NULL;
	db->contexts_by_sock = NULL;
	db->contexts_for_free = NULL;
#ifdef WITH_BRIDGE
	db->bridges = NULL;
	db->bridge_count = 0;
#endif

	// Initialize the hashtable
	db->clientid_index_hash = NULL;

	db->subs.next = NULL;
	db->subs.subs = NULL;
	db->subs.topic = "";

	child = _eecloud_malloc(sizeof(struct _eecloud_subhier));
	if(!child){
		_eecloud_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	child->next = NULL;
	child->topic = _eecloud_strdup("");
	if(!child->topic){
		_eecloud_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	child->subs = NULL;
	child->children = NULL;
	child->retained = NULL;
	db->subs.children = child;

	child = _eecloud_malloc(sizeof(struct _eecloud_subhier));
	if(!child){
		_eecloud_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	child->next = NULL;
	child->topic = _eecloud_strdup("$SYS");
	if(!child->topic){
		_eecloud_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	child->subs = NULL;
	child->children = NULL;
	child->retained = NULL;
	db->subs.children->next = child;

	db->unpwd = NULL;

#ifdef WITH_PERSISTENCE
	if(config->persistence && config->persistence_filepath){
		if(mqtt3_db_restore(db)) return 1;
	}
#endif

	return rc;
}

static void subhier_clean(struct eecloud_db *db, struct _eecloud_subhier *subhier)
{
	struct _eecloud_subhier *next;
	struct _eecloud_subleaf *leaf, *nextleaf;

	while(subhier){
		next = subhier->next;
		leaf = subhier->subs;
		while(leaf){
			nextleaf = leaf->next;
			_eecloud_free(leaf);
			leaf = nextleaf;
		}
		if(subhier->retained){
			eecloud__db_msg_store_deref(db, &subhier->retained);
		}
		subhier_clean(db, subhier->children);
		if(subhier->topic) _eecloud_free(subhier->topic);

		_eecloud_free(subhier);
		subhier = next;
	}
}

int mqtt3_db_close(struct eecloud_db *db)
{
	subhier_clean(db, db->subs.children);
	eecloud__db_msg_store_clean(db);

	return MOSQ_ERR_SUCCESS;
}


void eecloud__db_msg_store_add(struct eecloud_db *db, struct eecloud_msg_store *store)
{
	store->next = db->msg_store;
	store->prev = NULL;
	if(db->msg_store){
		db->msg_store->prev = store;
	}
	db->msg_store = store;
}


void eecloud__db_msg_store_remove(struct eecloud_db *db, struct eecloud_msg_store *store)
{
	int i;

	if(store->prev){
		store->prev->next = store->next;
		if(store->next){
			store->next->prev = store->prev;
		}
	}else{
		db->msg_store = store->next;
		if(store->next){
			store->next->prev = NULL;
		}
	}
	db->msg_store_count--;

	if(store->source_id) _eecloud_free(store->source_id);
	if(store->dest_ids){
		for(i=0; i<store->dest_id_count; i++){
			if(store->dest_ids[i]) _eecloud_free(store->dest_ids[i]);
		}
		_eecloud_free(store->dest_ids);
	}
	if(store->topic) _eecloud_free(store->topic);
	if(store->payload) _eecloud_free(store->payload);
	_eecloud_free(store);
}


void eecloud__db_msg_store_clean(struct eecloud_db *db)
{
	struct eecloud_msg_store *store, *next;;

	store = db->msg_store;
	while(store){
		next = store->next;
		eecloud__db_msg_store_remove(db, store);
		store = next;
	}
}

void eecloud__db_msg_store_deref(struct eecloud_db *db, struct eecloud_msg_store **store)
{
	(*store)->ref_count--;
	if((*store)->ref_count == 0){
		eecloud__db_msg_store_remove(db, *store);
		*store = NULL;
	}
}


static void _message_remove(struct eecloud_db *db, struct eecloud *context, struct eecloud_client_msg **msg, struct eecloud_client_msg *last)
{
	if(!context || !msg || !(*msg)){
		return;
	}

	if((*msg)->store){
		eecloud__db_msg_store_deref(db, &(*msg)->store);
	}
	if(last){
		last->next = (*msg)->next;
		if(!last->next){
			context->last_msg = last;
		}
	}else{
		context->msgs = (*msg)->next;
		if(!context->msgs){
			context->last_msg = NULL;
		}
	}
	context->msg_count--;
	if((*msg)->qos > 0){
		context->msg_count12--;
	}
	_eecloud_free(*msg);
	if(last){
		*msg = last->next;
	}else{
		*msg = context->msgs;
	}
}

int mqtt3_db_message_delete(struct eecloud_db *db, struct eecloud *context, uint16_t mid, enum eecloud_msg_direction dir)
{
	struct eecloud_client_msg *tail, *last = NULL;
	int msg_index = 0;
	bool deleted = false;

	if(!context) return MOSQ_ERR_INVAL;

	tail = context->msgs;
	while(tail){
		msg_index++;
		if(tail->state == ecld_ms_queued && msg_index <= max_inflight){
			tail->timestamp = eecloud_time();
			if(tail->direction == ecld_md_out){
				switch(tail->qos){
					case 0:
						tail->state = ecld_ms_publish_qos0;
						break;
					case 1:
						tail->state = ecld_ms_publish_qos1;
						break;
					case 2:
						tail->state = ecld_ms_publish_qos2;
						break;
				}
			}else{
				if(tail->qos == 2){
					tail->state = ecld_ms_wait_for_pubrel;
				}
			}
		}
		if(tail->mid == mid && tail->direction == dir){
			msg_index--;
			_message_remove(db, context, &tail, last);
			deleted = true;
		}else{
			last = tail;
			tail = tail->next;
		}
		if(msg_index > max_inflight && deleted){
			return MOSQ_ERR_SUCCESS;
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int mqtt3_db_message_insert(struct eecloud_db *db, struct eecloud *context, uint16_t mid, enum eecloud_msg_direction dir, int qos, bool retain, struct eecloud_msg_store *stored)
{
	struct eecloud_client_msg *msg;
	enum eecloud_msg_state state = ecld_ms_invalid;
	int rc = 0;
	int i;
	char **dest_ids;

	assert(stored);
	if(!context) return MOSQ_ERR_INVAL;
	if(!context->id) return MOSQ_ERR_SUCCESS; /* Protect against unlikely "client is disconnected but not entirely freed" scenario */

	/* Check whether we've already sent this message to this client
	 * for outgoing messages only.
	 * If retain==true then this is a stale retained message and so should be
	 * sent regardless. FIXME - this does mean retained messages will received
	 * multiple times for overlapping subscriptions, although this is only the
	 * case for SUBSCRIPTION with multiple subs in so is a minor concern.
	 */
	if(db->config->allow_duplicate_messages == false
			&& dir == ecld_md_out && retain == false && stored->dest_ids){

		for(i=0; i<stored->dest_id_count; i++){
			if(!strcmp(stored->dest_ids[i], context->id)){
				/* We have already sent this message to this client. */
				return MOSQ_ERR_SUCCESS;
			}
		}
	}
	if(context->sock == INVALID_SOCKET){
		/* Client is not connected only queue messages with QoS>0. */
		if(qos == 0 && !db->config->queue_qos0_messages){
			if(!context->bridge){
				return 2;
			}else{
				if(context->bridge->start_type != bst_lazy){
					return 2;
				}
			}
		}
	}

	if(context->sock != INVALID_SOCKET){
		if(qos == 0 || max_inflight == 0 || context->msg_count12 < max_inflight){
			if(dir == ecld_md_out){
				switch(qos){
					case 0:
						state = ecld_ms_publish_qos0;
						break;
					case 1:
						state = ecld_ms_publish_qos1;
						break;
					case 2:
						state = ecld_ms_publish_qos2;
						break;
				}
			}else{
				if(qos == 2){
					state = ecld_ms_wait_for_pubrel;
				}else{
					return 1;
				}
			}
		}else if(max_queued == 0 || context->msg_count12-max_inflight < max_queued){
			state = ecld_ms_queued;
			rc = 2;
		}else{
			/* Dropping message due to full queue. */
			if(context->is_dropping == false){
				context->is_dropping = true;
				_eecloud_log_printf(NULL, MOSQ_LOG_NOTICE,
						"Outgoing messages are being dropped for client %s.",
						context->id);
			}
#ifdef WITH_SYS_TREE
			g_msgs_dropped++;
#endif
			return 2;
		}
	}else{
		if(max_queued > 0 && context->msg_count12 >= max_queued){
#ifdef WITH_SYS_TREE
			g_msgs_dropped++;
#endif
			if(context->is_dropping == false){
				context->is_dropping = true;
				_eecloud_log_printf(NULL, MOSQ_LOG_NOTICE,
						"Outgoing messages are being dropped for client %s.",
						context->id);
			}
			return 2;
		}else{
			state = ecld_ms_queued;
		}
	}
	assert(state != ecld_ms_invalid);

#ifdef WITH_PERSISTENCE
	if(state == ecld_ms_queued){
		db->persistence_changes++;
	}
#endif

	msg = _eecloud_malloc(sizeof(struct eecloud_client_msg));
	if(!msg) return MOSQ_ERR_NOMEM;
	msg->next = NULL;
	msg->store = stored;
	msg->store->ref_count++;
	msg->mid = mid;
	msg->timestamp = eecloud_time();
	msg->direction = dir;
	msg->state = state;
	msg->dup = false;
	msg->qos = qos;
	msg->retain = retain;
	if(context->last_msg){
		context->last_msg->next = msg;
		context->last_msg = msg;
	}else{
		context->msgs = msg;
		context->last_msg = msg;
	}
	context->msg_count++;
	if(qos > 0){
		context->msg_count12++;
	}

	if(db->config->allow_duplicate_messages == false && dir == ecld_md_out && retain == false){
		/* Record which client ids this message has been sent to so we can avoid duplicates.
		 * Outgoing messages only.
		 * If retain==true then this is a stale retained message and so should be
		 * sent regardless. FIXME - this does mean retained messages will received
		 * multiple times for overlapping subscriptions, although this is only the
		 * case for SUBSCRIPTION with multiple subs in so is a minor concern.
		 */
		dest_ids = _eecloud_realloc(stored->dest_ids, sizeof(char *)*(stored->dest_id_count+1));
		if(dest_ids){
			stored->dest_ids = dest_ids;
			stored->dest_id_count++;
			stored->dest_ids[stored->dest_id_count-1] = _eecloud_strdup(context->id);
			if(!stored->dest_ids[stored->dest_id_count-1]){
				return MOSQ_ERR_NOMEM;
			}
		}else{
			return MOSQ_ERR_NOMEM;
		}
	}
#ifdef WITH_BRIDGE
	if(context->bridge && context->bridge->start_type == bst_lazy
			&& context->sock == INVALID_SOCKET
			&& context->msg_count >= context->bridge->threshold){

		context->bridge->lazy_reconnect = true;
	}
#endif

#ifdef WITH_WEBSOCKETS
	if(context->wsi && rc == 0){
		return mqtt3_db_message_write(db, context);
	}else{
		return rc;
	}
#else
	return rc;
#endif
}

int mqtt3_db_message_update(struct eecloud *context, uint16_t mid, enum eecloud_msg_direction dir, enum eecloud_msg_state state)
{
	struct eecloud_client_msg *tail;

	tail = context->msgs;
	while(tail){
		if(tail->mid == mid && tail->direction == dir){
			tail->state = state;
			tail->timestamp = eecloud_time();
			return MOSQ_ERR_SUCCESS;
		}
		tail = tail->next;
	}
	return 1;
}

int mqtt3_db_messages_delete(struct eecloud_db *db, struct eecloud *context)
{
	struct eecloud_client_msg *tail, *next;

	if(!context) return MOSQ_ERR_INVAL;

	tail = context->msgs;
	while(tail){
		eecloud__db_msg_store_deref(db, &tail->store);
		next = tail->next;
		_eecloud_free(tail);
		tail = next;
	}
	context->msgs = NULL;
	context->last_msg = NULL;
	context->msg_count = 0;
	context->msg_count12 = 0;

	return MOSQ_ERR_SUCCESS;
}

int mqtt3_db_messages_easy_queue(struct eecloud_db *db, struct eecloud *context, const char *topic, int qos, uint32_t payloadlen, const void *payload, int retain)
{
	struct eecloud_msg_store *stored;
	char *source_id;

	assert(db);

	if(!topic) return MOSQ_ERR_INVAL;

	if(context && context->id){
		source_id = context->id;
	}else{
		source_id = "";
	}
	if(mqtt3_db_message_store(db, source_id, 0, topic, qos, payloadlen, payload, retain, &stored, 0)) return 1;

	return mqtt3_db_messages_queue(db, source_id, topic, qos, retain, &stored);
}

int mqtt3_db_message_store(struct eecloud_db *db, const char *source, uint16_t source_mid, const char *topic, int qos, uint32_t payloadlen, const void *payload, int retain, struct eecloud_msg_store **stored, dbid_t store_id)
{
	struct eecloud_msg_store *temp;

	assert(db);
	assert(stored);

	temp = _eecloud_malloc(sizeof(struct eecloud_msg_store));
	if(!temp) return MOSQ_ERR_NOMEM;

	temp->ref_count = 0;
	if(source){
		temp->source_id = _eecloud_strdup(source);
	}else{
		temp->source_id = _eecloud_strdup("");
	}
	if(!temp->source_id){
		_eecloud_free(temp);
		_eecloud_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	temp->source_mid = source_mid;
	temp->mid = 0;
	temp->qos = qos;
	temp->retain = retain;
	if(topic){
		temp->topic = _eecloud_strdup(topic);
		if(!temp->topic){
			_eecloud_free(temp->source_id);
			_eecloud_free(temp);
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
	}else{
		temp->topic = NULL;
	}
	temp->payloadlen = payloadlen;
	if(payloadlen){
		temp->payload = _eecloud_malloc(sizeof(char)*payloadlen);
		if(!temp->payload){
			if(temp->source_id) _eecloud_free(temp->source_id);
			if(temp->topic) _eecloud_free(temp->topic);
			if(temp->payload) _eecloud_free(temp->payload);
			_eecloud_free(temp);
			return MOSQ_ERR_NOMEM;
		}
		memcpy(temp->payload, payload, sizeof(char)*payloadlen);
	}else{
		temp->payload = NULL;
	}

	if(!temp->source_id || (payloadlen && !temp->payload)){
		if(temp->source_id) _eecloud_free(temp->source_id);
		if(temp->topic) _eecloud_free(temp->topic);
		if(temp->payload) _eecloud_free(temp->payload);
		_eecloud_free(temp);
		return 1;
	}
	temp->dest_ids = NULL;
	temp->dest_id_count = 0;
	db->msg_store_count++;
	(*stored) = temp;

	if(!store_id){
		temp->db_id = ++db->last_db_id;
	}else{
		temp->db_id = store_id;
	}

	eecloud__db_msg_store_add(db, temp);

	return MOSQ_ERR_SUCCESS;
}

int mqtt3_db_message_store_find(struct eecloud *context, uint16_t mid, struct eecloud_msg_store **stored)
{
	struct eecloud_client_msg *tail;

	if(!context) return MOSQ_ERR_INVAL;

	*stored = NULL;
	tail = context->msgs;
	while(tail){
		if(tail->store->source_mid == mid && tail->direction == ecld_md_in){
			*stored = tail->store;
			return MOSQ_ERR_SUCCESS;
		}
		tail = tail->next;
	}

	return 1;
}

/* Called on reconnect to set outgoing messages to a sensible state and force a
 * retry, and to set incoming messages to expect an appropriate retry. */
int mqtt3_db_message_reconnect_reset(struct eecloud_db *db, struct eecloud *context)
{
	struct eecloud_client_msg *msg;
	struct eecloud_client_msg *prev = NULL;
	int count;

	msg = context->msgs;
	context->msg_count = 0;
	context->msg_count12 = 0;
	while(msg){
		context->last_msg = msg;

		context->msg_count++;
		if(msg->qos > 0){
			context->msg_count12++;
		}

		if(msg->direction == ecld_md_out){
			if(msg->state != ecld_ms_queued){
				switch(msg->qos){
					case 0:
						msg->state = ecld_ms_publish_qos0;
						break;
					case 1:
						msg->state = ecld_ms_publish_qos1;
						break;
					case 2:
						if(msg->state == ecld_ms_wait_for_pubcomp){
							msg->state = ecld_ms_resend_pubrel;
						}else{
							msg->state = ecld_ms_publish_qos2;
						}
						break;
				}
			}
		}else{
			if(msg->qos != 2){
				/* Anything <QoS 2 can be completely retried by the client at
				 * no harm. */
				_message_remove(db, context, &msg, prev);
			}else{
				/* Message state can be preserved here because it should match
				 * whatever the client has got. */
			}
		}
		prev = msg;
		if(msg) msg = msg->next;
	}
	/* Messages received when the client was disconnected are put
	 * in the ecld_ms_queued state. If we don't change them to the
	 * appropriate "publish" state, then the queued messages won't
	 * get sent until the client next receives a message - and they
	 * will be sent out of order.
	 */
	if(context->msgs){
		count = 0;
		msg = context->msgs;
		while(msg && (max_inflight == 0 || count < max_inflight)){
			if(msg->state == ecld_ms_queued){
				switch(msg->qos){
					case 0:
						msg->state = ecld_ms_publish_qos0;
						break;
					case 1:
						msg->state = ecld_ms_publish_qos1;
						break;
					case 2:
						msg->state = ecld_ms_publish_qos2;
						break;
				}
			}
			msg = msg->next;
			count++;
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int mqtt3_db_message_timeout_check(struct eecloud_db *db, unsigned int timeout)
{
	time_t threshold;
	enum eecloud_msg_state new_state;
	struct eecloud *context, *ctxt_tmp;
	struct eecloud_client_msg *msg;

	threshold = eecloud_time() - timeout;

	HASH_ITER(hh_sock, db->contexts_by_sock, context, ctxt_tmp){
		msg = context->msgs;
		while(msg){
			new_state = ecld_ms_invalid;
			if(msg->timestamp < threshold && msg->state != ecld_ms_queued){
				switch(msg->state){
					case ecld_ms_wait_for_puback:
						new_state = ecld_ms_publish_qos1;
						break;
					case ecld_ms_wait_for_pubrec:
						new_state = ecld_ms_publish_qos2;
						break;
					case ecld_ms_wait_for_pubrel:
						new_state = ecld_ms_send_pubrec;
						break;
					case ecld_ms_wait_for_pubcomp:
						new_state = ecld_ms_resend_pubrel;
						break;
					default:
						break;
				}
				if(new_state != ecld_ms_invalid){
					msg->timestamp = eecloud_time();
					msg->state = new_state;
					msg->dup = true;
				}
			}
			msg = msg->next;
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int mqtt3_db_message_release(struct eecloud_db *db, struct eecloud *context, uint16_t mid, enum eecloud_msg_direction dir)
{
	struct eecloud_client_msg *tail, *last = NULL;
	int qos;
	int retain;
	char *topic;
	char *source_id;
	int msg_index = 0;
	bool deleted = false;

	if(!context) return MOSQ_ERR_INVAL;

	tail = context->msgs;
	while(tail){
		msg_index++;
		if(tail->state == ecld_ms_queued && msg_index <= max_inflight){
			tail->timestamp = eecloud_time();
			if(tail->direction == ecld_md_out){
				switch(tail->qos){
					case 0:
						tail->state = ecld_ms_publish_qos0;
						break;
					case 1:
						tail->state = ecld_ms_publish_qos1;
						break;
					case 2:
						tail->state = ecld_ms_publish_qos2;
						break;
				}
			}else{
				if(tail->qos == 2){
					_eecloud_send_pubrec(context, tail->mid);
					tail->state = ecld_ms_wait_for_pubrel;
				}
			}
		}
		if(tail->mid == mid && tail->direction == dir){
			qos = tail->store->qos;
			topic = tail->store->topic;
			retain = tail->retain;
			source_id = tail->store->source_id;

			/* topic==NULL should be a QoS 2 message that was
			 * denied/dropped and is being processed so the client doesn't
			 * keep resending it. That means we don't send it to other
			 * clients. */
			if(!topic || !mqtt3_db_messages_queue(db, source_id, topic, qos, retain, &tail->store)){
				_message_remove(db, context, &tail, last);
				deleted = true;
			}else{
				return 1;
			}
		}else{
			last = tail;
			tail = tail->next;
		}
		if(msg_index > max_inflight && deleted){
			return MOSQ_ERR_SUCCESS;
		}
	}
	if(deleted){
		return MOSQ_ERR_SUCCESS;
	}else{
		return 1;
	}
}

int mqtt3_db_message_write(struct eecloud_db *db, struct eecloud *context)
{
	int rc;
	struct eecloud_client_msg *tail, *last = NULL;
	uint16_t mid;
	int retries;
	int retain;
	const char *topic;
	int qos;
	uint32_t payloadlen;
	const void *payload;
	int msg_count = 0;

	if(!context || context->sock == INVALID_SOCKET
			|| (context->state == ecld_cs_connected && !context->id)){
		return MOSQ_ERR_INVAL;
	}

	if(context->state != ecld_cs_connected){
		return MOSQ_ERR_SUCCESS;
	}

	tail = context->msgs;
	while(tail){
		if(tail->direction == ecld_md_in){
			msg_count++;
		}
		if(tail->state != ecld_ms_queued){
			mid = tail->mid;
			retries = tail->dup;
			retain = tail->retain;
			topic = tail->store->topic;
			qos = tail->qos;
			payloadlen = tail->store->payloadlen;
			payload = tail->store->payload;

			switch(tail->state){
				case ecld_ms_publish_qos0:
					rc = _eecloud_send_publish(context, mid, topic, payloadlen, payload, qos, retain, retries);
					if(!rc){
						_message_remove(db, context, &tail, last);
					}else{
						return rc;
					}
					break;

				case ecld_ms_publish_qos1:
					rc = _eecloud_send_publish(context, mid, topic, payloadlen, payload, qos, retain, retries);
					if(!rc){
						tail->timestamp = eecloud_time();
						tail->dup = 1; /* Any retry attempts are a duplicate. */
						tail->state = ecld_ms_wait_for_puback;
					}else{
						return rc;
					}
					last = tail;
					tail = tail->next;
					break;

				case ecld_ms_publish_qos2:
					rc = _eecloud_send_publish(context, mid, topic, payloadlen, payload, qos, retain, retries);
					if(!rc){
						tail->timestamp = eecloud_time();
						tail->dup = 1; /* Any retry attempts are a duplicate. */
						tail->state = ecld_ms_wait_for_pubrec;
					}else{
						return rc;
					}
					last = tail;
					tail = tail->next;
					break;
				
				case ecld_ms_send_pubrec:
					rc = _eecloud_send_pubrec(context, mid);
					if(!rc){
						tail->state = ecld_ms_wait_for_pubrel;
					}else{
						return rc;
					}
					last = tail;
					tail = tail->next;
					break;

				case ecld_ms_resend_pubrel:
					rc = _eecloud_send_pubrel(context, mid);
					if(!rc){
						tail->state = ecld_ms_wait_for_pubcomp;
					}else{
						return rc;
					}
					last = tail;
					tail = tail->next;
					break;

				case ecld_ms_resend_pubcomp:
					rc = _eecloud_send_pubcomp(context, mid);
					if(!rc){
						tail->state = ecld_ms_wait_for_pubrel;
					}else{
						return rc;
					}
					last = tail;
					tail = tail->next;
					break;

				default:
					last = tail;
					tail = tail->next;
					break;
			}
		}else{
			/* state == ecld_ms_queued */
			if(tail->direction == ecld_md_in && (max_inflight == 0 || msg_count < max_inflight)){
				if(tail->qos == 2){
					tail->state = ecld_ms_send_pubrec;
				}
			}else{
				last = tail;
				tail = tail->next;
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
}

void mqtt3_db_limits_set(int inflight, int queued)
{
	max_inflight = inflight;
	max_queued = queued;
}

void mqtt3_db_vacuum(void)
{
	/* FIXME - reimplement? */
}

