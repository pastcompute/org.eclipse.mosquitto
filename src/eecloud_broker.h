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

#ifndef MQTT3_H
#define MQTT3_H

#include <config.h>
#include <stdio.h>

#include <eecloud_internal.h>
#include <eecloud_plugin.h>
#include <eecloud.h>
#include "tls_ecld.h"
#include "uthash.h"

#ifndef __GNUC__
#define __attribute__(attrib)
#endif

/* Log destinations */
#define MQTT3_LOG_NONE 0x00
#define MQTT3_LOG_SYSLOG 0x01
#define MQTT3_LOG_FILE 0x02
#define MQTT3_LOG_STDOUT 0x04
#define MQTT3_LOG_STDERR 0x08
#define MQTT3_LOG_TOPIC 0x10
#define MQTT3_LOG_ALL 0xFF

#define WEBSOCKET_CLIENT -2

enum eecloud_protocol {
	mp_mqtt,
	mp_mqttsn,
	mp_websockets
};

typedef uint64_t dbid_t;

struct _mqtt3_listener {
	int fd;
	char *host;
	uint16_t port;
	int max_connections;
	char *mount_point;
	ecld_sock_t *socks;
	int sock_count;
	int client_count;
	enum eecloud_protocol protocol;
	bool use_username_as_clientid;
#ifdef WITH_TLS
	char *cafile;
	char *capath;
	char *certfile;
	char *keyfile;
	char *ciphers;
	char *psk_hint;
	bool require_certificate;
	SSL_CTX *ssl_ctx;
	char *crlfile;
	bool use_identity_as_username;
	char *tls_version;
#endif
#ifdef WITH_WEBSOCKETS
	struct libwebsocket_context *ws_context;
	char *http_dir;
	struct libwebsocket_protocols *ws_protocol;
#endif
};

struct mqtt3_config {
	char *config_file;
	char *acl_file;
	bool allow_anonymous;
	bool allow_duplicate_messages;
	bool allow_zero_length_clientid;
	char *auto_id_prefix;
	int auto_id_prefix_len;
	int autosave_interval;
	bool autosave_on_changes;
	char *clientid_prefixes;
	bool connection_messages;
	bool daemon;
	struct _mqtt3_listener default_listener;
	struct _mqtt3_listener *listeners;
	int listener_count;
	int log_dest;
	int log_facility;
	int log_type;
	bool log_timestamp;
	char *log_file;
	FILE *log_fptr;
	uint32_t message_size_limit;
	char *password_file;
	bool persistence;
	char *persistence_location;
	char *persistence_file;
	char *persistence_filepath;
	time_t persistent_client_expiration;
	char *pid_file;
	char *psk_file;
	bool queue_qos0_messages;
	int retry_interval;
	int sys_interval;
	bool upgrade_outgoing_qos;
	char *user;
	bool verbose;
#ifdef WITH_WEBSOCKETS
	int websockets_log_level;
	bool have_websockets_listener;
#endif
#ifdef WITH_BRIDGE
	struct _mqtt3_bridge *bridges;
	int bridge_count;
#endif
	char *auth_plugin;
	struct eecloud_auth_opt *auth_options;
	int auth_option_count;
};

struct _eecloud_subleaf {
	struct _eecloud_subleaf *prev;
	struct _eecloud_subleaf *next;
	struct eecloud *context;
	int qos;
};

struct _eecloud_subhier {
	struct _eecloud_subhier *children;
	struct _eecloud_subhier *next;
	struct _eecloud_subleaf *subs;
	char *topic;
	struct eecloud_msg_store *retained;
};

struct eecloud_msg_store_load{
	UT_hash_handle hh;
	dbid_t db_id;
	struct eecloud_msg_store *store;
};

struct eecloud_msg_store{
	struct eecloud_msg_store *next;
	struct eecloud_msg_store *prev;
	dbid_t db_id;
	char *source_id;
	char **dest_ids;
	int dest_id_count;
	int ref_count;
	char *topic;
	void *payload;
	uint32_t payloadlen;
	uint16_t source_mid;
	uint16_t mid;
	uint8_t qos;
	bool retain;
};

struct eecloud_client_msg{
	struct eecloud_client_msg *next;
	struct eecloud_msg_store *store;
	time_t timestamp;
	uint16_t mid;
	uint8_t qos;
	bool retain;
	enum eecloud_msg_direction direction;
	enum eecloud_msg_state state;
	bool dup;
};

struct _eecloud_unpwd{
	char *username;
	char *password;
#ifdef WITH_TLS
	unsigned int password_len;
	unsigned int salt_len;
	unsigned char *salt;
#endif
	UT_hash_handle hh;
};

struct _eecloud_acl{
	struct _eecloud_acl *next;
	char *topic;
	int access;
	int ucount;
	int ccount;
};

struct _eecloud_acl_user{
	struct _eecloud_acl_user *next;
	char *username;
	struct _eecloud_acl *acl;
};

struct _eecloud_auth_plugin{
	void *lib;
	void *user_data;
	int (*plugin_version)(void);
	int (*plugin_init)(void **user_data, struct eecloud_auth_opt *auth_opts, int auth_opt_count);
	int (*plugin_cleanup)(void *user_data, struct eecloud_auth_opt *auth_opts, int auth_opt_count);
	int (*security_init)(void *user_data, struct eecloud_auth_opt *auth_opts, int auth_opt_count, bool reload);
	int (*security_cleanup)(void *user_data, struct eecloud_auth_opt *auth_opts, int auth_opt_count, bool reload);
	int (*acl_check)(void *user_data, const char *clientid, const char *username, const char *topic, int access);
	int (*unpwd_check)(void *user_data, const char *username, const char *password);
	int (*psk_key_get)(void *user_data, const char *hint, const char *identity, char *key, int max_key_len);
};

struct eecloud_db{
	dbid_t last_db_id;
	struct _eecloud_subhier subs;
	struct _eecloud_unpwd *unpwd;
	struct _eecloud_acl_user *acl_list;
	struct _eecloud_acl *acl_patterns;
	struct _eecloud_unpwd *psk_id;
	struct eecloud *contexts_by_id;
	struct eecloud *contexts_by_sock;
	struct eecloud *contexts_for_free;
#ifdef WITH_BRIDGE
	struct eecloud **bridges;
#endif
	struct _clientid_index_hash *clientid_index_hash;
	struct eecloud_msg_store *msg_store;
	struct eecloud_msg_store_load *msg_store_load;
#ifdef WITH_BRIDGE
	int bridge_count;
#endif
	int msg_store_count;
	struct mqtt3_config *config;
	int persistence_changes;
	struct _eecloud_auth_plugin auth_plugin;
#ifdef WITH_SYS_TREE
	int subscription_count;
	int retained_count;
#endif
	struct eecloud *ll_for_free;
};

enum mqtt3_bridge_direction{
	bd_out = 0,
	bd_in = 1,
	bd_both = 2
};

enum eecloud_bridge_start_type{
	bst_automatic = 0,
	bst_lazy = 1,
	bst_manual = 2,
	bst_once = 3
};

struct _mqtt3_bridge_topic{
	char *topic;
	int qos;
	enum mqtt3_bridge_direction direction;
	char *local_prefix;
	char *remote_prefix;
	char *local_topic; /* topic prefixed with local_prefix */
	char *remote_topic; /* topic prefixed with remote_prefix */
};

struct bridge_address{
	char *address;
	int port;
};

struct _mqtt3_bridge{
	char *name;
	struct bridge_address *addresses;
	int cur_address;
	int address_count;
	time_t primary_retry;
	bool round_robin;
	bool try_private;
	bool try_private_accepted;
	bool clean_session;
	int keepalive;
	struct _mqtt3_bridge_topic *topics;
	int topic_count;
	bool topic_remapping;
	enum _eecloud_protocol protocol_version;
	time_t restart_t;
	char *remote_clientid;
	char *remote_username;
	char *remote_password;
	char *local_clientid;
	char *local_username;
	char *local_password;
	bool notifications;
	char *notification_topic;
	enum eecloud_bridge_start_type start_type;
	int idle_timeout;
	int restart_timeout;
	int threshold;
	bool lazy_reconnect;
	bool attempt_unsubscribe;
	bool initial_notification_done;
#ifdef WITH_TLS
	char *tls_cafile;
	char *tls_capath;
	char *tls_certfile;
	char *tls_keyfile;
	bool tls_insecure;
	char *tls_version;
#  ifdef REAL_WITH_TLS_PSK
	char *tls_psk_identity;
	char *tls_psk;
#  endif
#endif
};

#ifdef WITH_WEBSOCKETS
struct libws_mqtt_hack {
	char *http_dir;
};

struct libws_mqtt_data {
	struct eecloud *ecld;
};
#endif

#include <net_ecld.h>

/* ============================================================
 * Main functions
 * ============================================================ */
int eecloud_main_loop(struct eecloud_db *db, ecld_sock_t *listensock, int listensock_count, int listener_max);
struct eecloud_db *_eecloud_get_db(void);

/* ============================================================
 * Config functions
 * ============================================================ */
/* Initialise config struct to default values. */
void mqtt3_config_init(struct mqtt3_config *config);
/* Parse command line options into config. */
int mqtt3_config_parse_args(struct mqtt3_config *config, int argc, char *argv[]);
/* Read configuration data from config->config_file into config.
 * If reload is true, don't process config options that shouldn't be reloaded (listeners etc)
 * Returns 0 on success, 1 if there is a configuration error or if a file cannot be opened.
 */
int mqtt3_config_read(struct mqtt3_config *config, bool reload);
/* Free all config data. */
void mqtt3_config_cleanup(struct mqtt3_config *config);

int drop_privileges(struct mqtt3_config *config, bool temporary);
int restore_privileges(void);

/* ============================================================
 * Server send functions
 * ============================================================ */
int _eecloud_send_connack(struct eecloud *context, int ack, int result);
int _eecloud_send_suback(struct eecloud *context, uint16_t mid, uint32_t payloadlen, const void *payload);

/* ============================================================
 * Network functions
 * ============================================================ */
int mqtt3_socket_accept(struct eecloud_db *db, ecld_sock_t listensock);
int mqtt3_socket_listen(struct _mqtt3_listener *listener);
int _eecloud_socket_get_address(ecld_sock_t sock, char *buf, int len);

/* ============================================================
 * Read handling functions
 * ============================================================ */
int mqtt3_packet_handle(struct eecloud_db *db, struct eecloud *context);
int mqtt3_handle_connack(struct eecloud_db *db, struct eecloud *context);
int mqtt3_handle_connect(struct eecloud_db *db, struct eecloud *context);
int mqtt3_handle_disconnect(struct eecloud_db *db, struct eecloud *context);
int mqtt3_handle_publish(struct eecloud_db *db, struct eecloud *context);
int mqtt3_handle_subscribe(struct eecloud_db *db, struct eecloud *context);
int mqtt3_handle_unsubscribe(struct eecloud_db *db, struct eecloud *context);

/* ============================================================
 * Database handling
 * ============================================================ */
int mqtt3_db_open(struct mqtt3_config *config, struct eecloud_db *db);
int mqtt3_db_close(struct eecloud_db *db);
#ifdef WITH_PERSISTENCE
int mqtt3_db_backup(struct eecloud_db *db, bool shutdown);
int mqtt3_db_restore(struct eecloud_db *db);
#endif
void mqtt3_db_limits_set(int inflight, int queued);
/* Return the number of in-flight messages in count. */
int mqtt3_db_message_count(int *count);
int mqtt3_db_message_delete(struct eecloud_db *db, struct eecloud *context, uint16_t mid, enum eecloud_msg_direction dir);
int mqtt3_db_message_insert(struct eecloud_db *db, struct eecloud *context, uint16_t mid, enum eecloud_msg_direction dir, int qos, bool retain, struct eecloud_msg_store *stored);
int mqtt3_db_message_release(struct eecloud_db *db, struct eecloud *context, uint16_t mid, enum eecloud_msg_direction dir);
int mqtt3_db_message_update(struct eecloud *context, uint16_t mid, enum eecloud_msg_direction dir, enum eecloud_msg_state state);
int mqtt3_db_message_write(struct eecloud_db *db, struct eecloud *context);
int mqtt3_db_messages_delete(struct eecloud_db *db, struct eecloud *context);
int mqtt3_db_messages_easy_queue(struct eecloud_db *db, struct eecloud *context, const char *topic, int qos, uint32_t payloadlen, const void *payload, int retain);
int mqtt3_db_messages_queue(struct eecloud_db *db, const char *source_id, const char *topic, int qos, int retain, struct eecloud_msg_store **stored);
int mqtt3_db_message_store(struct eecloud_db *db, const char *source, uint16_t source_mid, const char *topic, int qos, uint32_t payloadlen, const void *payload, int retain, struct eecloud_msg_store **stored, dbid_t store_id);
int mqtt3_db_message_store_find(struct eecloud *context, uint16_t mid, struct eecloud_msg_store **stored);
void eecloud__db_msg_store_add(struct eecloud_db *db, struct eecloud_msg_store *store);
void eecloud__db_msg_store_remove(struct eecloud_db *db, struct eecloud_msg_store *store);
void eecloud__db_msg_store_deref(struct eecloud_db *db, struct eecloud_msg_store **store);
void eecloud__db_msg_store_clean(struct eecloud_db *db);
/* Check all messages waiting on a client reply and resend if timeout has been exceeded. */
int mqtt3_db_message_timeout_check(struct eecloud_db *db, unsigned int timeout);
int mqtt3_db_message_reconnect_reset(struct eecloud_db *db, struct eecloud *context);
int mqtt3_retain_queue(struct eecloud_db *db, struct eecloud *context, const char *sub, int sub_qos);
void mqtt3_db_sys_update(struct eecloud_db *db, int interval, time_t start_time);
void mqtt3_db_vacuum(void);

/* ============================================================
 * Subscription functions
 * ============================================================ */
int mqtt3_sub_add(struct eecloud_db *db, struct eecloud *context, const char *sub, int qos, struct _eecloud_subhier *root);
int mqtt3_sub_remove(struct eecloud_db *db, struct eecloud *context, const char *sub, struct _eecloud_subhier *root);
int mqtt3_sub_search(struct eecloud_db *db, struct _eecloud_subhier *root, const char *source_id, const char *topic, int qos, int retain, struct eecloud_msg_store *stored);
void mqtt3_sub_tree_print(struct _eecloud_subhier *root, int level);
int mqtt3_subs_clean_session(struct eecloud_db *db, struct eecloud *context);

/* ============================================================
 * Context functions
 * ============================================================ */
struct eecloud *mqtt3_context_init(struct eecloud_db *db, ecld_sock_t sock);
void mqtt3_context_cleanup(struct eecloud_db *db, struct eecloud *context, bool do_free);
void mqtt3_context_disconnect(struct eecloud_db *db, struct eecloud *context);
void eecloud__add_context_to_disused(struct eecloud_db *db, struct eecloud *context);
void eecloud__free_disused_contexts(struct eecloud_db *db);

/* ============================================================
 * Logging functions
 * ============================================================ */
int mqtt3_log_init(struct mqtt3_config *config);
int mqtt3_log_close(struct mqtt3_config *config);
int _eecloud_log_printf(struct eecloud *ecld, int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

/* ============================================================
 * Bridge functions
 * ============================================================ */
#ifdef WITH_BRIDGE
int mqtt3_bridge_new(struct eecloud_db *db, struct _mqtt3_bridge *bridge);
int mqtt3_bridge_connect(struct eecloud_db *db, struct eecloud *context);
void mqtt3_bridge_packet_cleanup(struct eecloud *context);
#endif

/* ============================================================
 * Security related functions
 * ============================================================ */
int eecloud_security_module_init(struct eecloud_db *db);
int eecloud_security_module_cleanup(struct eecloud_db *db);

int eecloud_security_init(struct eecloud_db *db, bool reload);
int eecloud_security_apply(struct eecloud_db *db);
int eecloud_security_cleanup(struct eecloud_db *db, bool reload);
int eecloud_acl_check(struct eecloud_db *db, struct eecloud *context, const char *topic, int access);
int eecloud_unpwd_check(struct eecloud_db *db, const char *username, const char *password);
int eecloud_psk_key_get(struct eecloud_db *db, const char *hint, const char *identity, char *key, int max_key_len);

int eecloud_security_init_default(struct eecloud_db *db, bool reload);
int eecloud_security_apply_default(struct eecloud_db *db);
int eecloud_security_cleanup_default(struct eecloud_db *db, bool reload);
int eecloud_acl_check_default(struct eecloud_db *db, struct eecloud *context, const char *topic, int access);
int eecloud_unpwd_check_default(struct eecloud_db *db, const char *username, const char *password);
int eecloud_psk_key_get_default(struct eecloud_db *db, const char *hint, const char *identity, char *key, int max_key_len);

/* ============================================================
 * Window service related functions
 * ============================================================ */
#if defined(WIN32) || defined(__CYGWIN__)
void service_install(void);
void service_uninstall(void);
void service_run(void);
#endif

/* ============================================================
 * Websockets related functions
 * ============================================================ */
#ifdef WITH_WEBSOCKETS
struct libwebsocket_context *ecld_websockets_init(struct _mqtt3_listener *listener, int log_level);
#endif
void do_disconnect(struct eecloud_db *db, struct eecloud *context);

#endif
