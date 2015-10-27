#include <string.h>
#include <string.h>
#include <eecloud.h>
#include <eecloud_plugin.h>

int eecloud_auth_plugin_version(void)
{
	return MOSQ_AUTH_PLUGIN_VERSION;
}

int eecloud_auth_plugin_init(void **user_data, struct eecloud_auth_opt *auth_opts, int auth_opt_count)
{
	return MOSQ_ERR_SUCCESS;
}

int eecloud_auth_plugin_cleanup(void *user_data, struct eecloud_auth_opt *auth_opts, int auth_opt_count)
{
	return MOSQ_ERR_SUCCESS;
}

int eecloud_auth_security_init(void *user_data, struct eecloud_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int eecloud_auth_security_cleanup(void *user_data, struct eecloud_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int eecloud_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access)
{
	if(!strcmp(username, "readonly") && access == MOSQ_ACL_READ){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_ACL_DENIED;
	}
}

int eecloud_auth_unpwd_check(void *user_data, const char *username, const char *password)
{
	if(!strcmp(username, "test-username") && password && !strcmp(password, "cnwTICONIURW")){
		return MOSQ_ERR_SUCCESS;
	}else if(!strcmp(username, "readonly")){
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_AUTH;
	}
}

int eecloud_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len)
{
	return MOSQ_ERR_AUTH;
}

