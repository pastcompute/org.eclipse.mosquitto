#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <eecloud.h>

static int run = -1;
static int sent_mid;

void on_connect(struct eecloud *ecld, void *obj, int rc)
{
	if(rc){
		exit(1);
	}else{
		eecloud_publish(ecld, &sent_mid, "psk/test", strlen("message"), "message", 0, false);
	}
}

void on_publish(struct eecloud *ecld, void *obj, int mid)
{
	if(mid == sent_mid){
		eecloud_disconnect(ecld);
		run = 0;
	}else{
		exit(1);
	}
}

void on_disconnect(struct eecloud *ecld, void *obj, int rc)
{
	run = rc;
}

int main(int argc, char *argv[])
{
	int rc;
	struct eecloud *ecld;

	eecloud_lib_init();

	ecld = eecloud_new("08-tls-psk-pub", true, NULL);
	eecloud_tls_opts_set(ecld, 1, "tlsv1", NULL);
	rc = eecloud_tls_psk_set(ecld, "deadbeef", "psk-id", NULL);
	if(rc){
		eecloud_destroy(ecld);
		return rc;
	}
	eecloud_connect_callback_set(ecld, on_connect);
	eecloud_disconnect_callback_set(ecld, on_disconnect);
	eecloud_publish_callback_set(ecld, on_publish);

	rc = eecloud_connect(ecld, "localhost", 1888, 60);
	if(rc){
		eecloud_destroy(ecld);
		return rc;
	}

	while(run == -1){
		eecloud_loop(ecld, -1, 1);
	}

	eecloud_destroy(ecld);

	eecloud_lib_cleanup();
	return run;
}
