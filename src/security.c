/*
Copyright (c) 2011-2014 Roger Light <roger@atchoo.org>

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

#include <config.h>

#include <stdio.h>
#include <string.h>

#include <eecloud_broker.h>
#include "eecloud_plugin.h"
#include <memory_ecld.h>
#include "lib_load.h"

typedef int (*FUNC_auth_plugin_version)(void);
typedef int (*FUNC_auth_plugin_init)(void **, struct eecloud_auth_opt *, int);
typedef int (*FUNC_auth_plugin_cleanup)(void *, struct eecloud_auth_opt *, int);
typedef int (*FUNC_auth_plugin_security_init)(void *, struct eecloud_auth_opt *, int, bool);
typedef int (*FUNC_auth_plugin_security_cleanup)(void *, struct eecloud_auth_opt *, int, bool);
typedef int (*FUNC_auth_plugin_acl_check)(void *, const char *, const char *, const char *, int);
typedef int (*FUNC_auth_plugin_unpwd_check)(void *, const char *, const char *);
typedef int (*FUNC_auth_plugin_psk_key_get)(void *, const char *, const char *, char *, int);

void LIB_ERROR(void)
{
#ifdef WIN32
	char *buf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING,
			NULL, GetLastError(), LANG_NEUTRAL, &buf, 0, NULL);
	_eecloud_log_printf(NULL, MOSQ_LOG_ERR, "Load error: %s", buf);
	LocalFree(buf);
#else
	_eecloud_log_printf(NULL, MOSQ_LOG_ERR, "Load error: %s", dlerror());
#endif
}

int eecloud_security_module_init(struct eecloud_db *db)
{
	void *lib;
	int (*plugin_version)(void) = NULL;
	int version;
	int rc;
	if(db->config->auth_plugin){
		lib = LIB_LOAD(db->config->auth_plugin);
		if(!lib){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR, 
					"Error: Unable to load auth plugin \"%s\".", db->config->auth_plugin);
			LIB_ERROR();
			return 1;
		}

		db->auth_plugin.lib = NULL;
		if(!(plugin_version = (FUNC_auth_plugin_version)LIB_SYM(lib, "eecloud_auth_plugin_version"))){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR,
					"Error: Unable to load auth plugin function eecloud_auth_plugin_version().");
			LIB_ERROR();
			LIB_CLOSE(lib);
			return 1;
		}
		version = plugin_version();
		if(version != MOSQ_AUTH_PLUGIN_VERSION){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR,
					"Error: Incorrect auth plugin version (got %d, expected %d).",
					version, MOSQ_AUTH_PLUGIN_VERSION);
			LIB_ERROR();

			LIB_CLOSE(lib);
			return 1;
		}
		if(!(db->auth_plugin.plugin_init = (FUNC_auth_plugin_init)LIB_SYM(lib, "eecloud_auth_plugin_init"))){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR,
					"Error: Unable to load auth plugin function eecloud_auth_plugin_init().");
			LIB_ERROR();
			LIB_CLOSE(lib);
			return 1;
		}
		if(!(db->auth_plugin.plugin_cleanup = (FUNC_auth_plugin_cleanup)LIB_SYM(lib, "eecloud_auth_plugin_cleanup"))){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR,
					"Error: Unable to load auth plugin function eecloud_auth_plugin_cleanup().");
			LIB_ERROR();
			LIB_CLOSE(lib);
			return 1;
		}

		if(!(db->auth_plugin.security_init = (FUNC_auth_plugin_security_init)LIB_SYM(lib, "eecloud_auth_security_init"))){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR,
					"Error: Unable to load auth plugin function eecloud_auth_security_init().");
			LIB_ERROR();
			LIB_CLOSE(lib);
			return 1;
		}

		if(!(db->auth_plugin.security_cleanup = (FUNC_auth_plugin_security_cleanup)LIB_SYM(lib, "eecloud_auth_security_cleanup"))){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR,
					"Error: Unable to load auth plugin function eecloud_auth_security_cleanup().");
			LIB_ERROR();
			LIB_CLOSE(lib);
			return 1;
		}

		if(!(db->auth_plugin.acl_check = (FUNC_auth_plugin_acl_check)LIB_SYM(lib, "eecloud_auth_acl_check"))){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR,
					"Error: Unable to load auth plugin function eecloud_auth_acl_check().");
			LIB_ERROR();
			LIB_CLOSE(lib);
			return 1;
		}

		if(!(db->auth_plugin.unpwd_check = (FUNC_auth_plugin_unpwd_check)LIB_SYM(lib, "eecloud_auth_unpwd_check"))){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR,
					"Error: Unable to load auth plugin function eecloud_auth_unpwd_check().");
			LIB_ERROR();
			LIB_CLOSE(lib);
			return 1;
		}

		if(!(db->auth_plugin.psk_key_get = (FUNC_auth_plugin_psk_key_get)LIB_SYM(lib, "eecloud_auth_psk_key_get"))){
			_eecloud_log_printf(NULL, MOSQ_LOG_ERR,
					"Error: Unable to load auth plugin function eecloud_auth_psk_key_get().");
			LIB_ERROR();
			LIB_CLOSE(lib);
			return 1;
		}

		db->auth_plugin.lib = lib;
		db->auth_plugin.user_data = NULL;
		if(db->auth_plugin.plugin_init){
			rc = db->auth_plugin.plugin_init(&db->auth_plugin.user_data, db->config->auth_options, db->config->auth_option_count);
			if(rc){
				_eecloud_log_printf(NULL, MOSQ_LOG_ERR,
						"Error: Authentication plugin returned %d when initialising.", rc);
			}
			return rc;
		}
	}else{
		db->auth_plugin.lib = NULL;
		db->auth_plugin.plugin_init = NULL;
		db->auth_plugin.plugin_cleanup = NULL;
		db->auth_plugin.security_init = NULL;
		db->auth_plugin.security_cleanup = NULL;
		db->auth_plugin.acl_check = NULL;
		db->auth_plugin.unpwd_check = NULL;
		db->auth_plugin.psk_key_get = NULL;
	}

	return MOSQ_ERR_SUCCESS;
}

int eecloud_security_module_cleanup(struct eecloud_db *db)
{
	eecloud_security_cleanup(db, false);

	if(db->auth_plugin.plugin_cleanup){
		db->auth_plugin.plugin_cleanup(db->auth_plugin.user_data, db->config->auth_options, db->config->auth_option_count);
	}

	if(db->config->auth_plugin){
		if(db->auth_plugin.lib){
			LIB_CLOSE(db->auth_plugin.lib);
		}
	}
	db->auth_plugin.lib = NULL;
	db->auth_plugin.plugin_init = NULL;
	db->auth_plugin.plugin_cleanup = NULL;
	db->auth_plugin.security_init = NULL;
	db->auth_plugin.security_cleanup = NULL;
	db->auth_plugin.acl_check = NULL;
	db->auth_plugin.unpwd_check = NULL;
	db->auth_plugin.psk_key_get = NULL;

	return MOSQ_ERR_SUCCESS;
}

int eecloud_security_init(struct eecloud_db *db, bool reload)
{
	if(!db->auth_plugin.lib){
		return eecloud_security_init_default(db, reload);
	}else{
		return db->auth_plugin.security_init(db->auth_plugin.user_data, db->config->auth_options, db->config->auth_option_count, reload);
	}
}

/* Apply security settings after a reload.
 * Includes:
 * - Disconnecting anonymous users if appropriate
 * - Disconnecting users with invalid passwords
 * - Reapplying ACLs
 */
int eecloud_security_apply(struct eecloud_db *db)
{
	if(!db->auth_plugin.lib){
		return eecloud_security_apply_default(db);
	}
	return MOSQ_ERR_SUCCESS;
}

int eecloud_security_cleanup(struct eecloud_db *db, bool reload)
{
	if(!db->auth_plugin.lib){
		return eecloud_security_cleanup_default(db, reload);
	}else{
		return db->auth_plugin.security_cleanup(db->auth_plugin.user_data, db->config->auth_options, db->config->auth_option_count, reload);
	}
}

int eecloud_acl_check(struct eecloud_db *db, struct eecloud *context, const char *topic, int access)
{
	char *username;

	if(!context->id){
		return MOSQ_ERR_ACL_DENIED;
	}
	if(!db->auth_plugin.lib){
		return eecloud_acl_check_default(db, context, topic, access);
	}else{
#ifdef WITH_BRIDGE
		if(context->bridge){
			username = context->bridge->local_username;
		}else
#endif
		{
			username = context->username;
		}
		return db->auth_plugin.acl_check(db->auth_plugin.user_data, context->id, username, topic, access);
	}
}

int eecloud_unpwd_check(struct eecloud_db *db, const char *username, const char *password)
{
	if(!db->auth_plugin.lib){
		return eecloud_unpwd_check_default(db, username, password);
	}else{
		return db->auth_plugin.unpwd_check(db->auth_plugin.user_data, username, password);
	}
}

int eecloud_psk_key_get(struct eecloud_db *db, const char *hint, const char *identity, char *key, int max_key_len)
{
	if(!db->auth_plugin.lib){
		return eecloud_psk_key_get_default(db, hint, identity, key, max_key_len);
	}else{
		return db->auth_plugin.psk_key_get(db->auth_plugin.user_data, hint, identity, key, max_key_len);
	}
}

