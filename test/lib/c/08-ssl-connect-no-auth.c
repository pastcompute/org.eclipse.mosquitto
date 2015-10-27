#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <eecloud.h>

static int run = -1;

void on_connect(struct eecloud *ecld, void *obj, int rc)
{
	if(rc){
		exit(1);
	}else{
		eecloud_disconnect(ecld);
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

	ecld = eecloud_new("08-ssl-connect-no-auth", true, NULL);
	eecloud_tls_opts_set(ecld, 1, "tlsv1", NULL);
	//eecloud_tls_set(ecld, "../ssl/test-root-ca.crt", NULL, NULL, NULL, NULL);
	eecloud_tls_set(ecld, "../ssl/all-ca.crt", NULL, NULL, NULL, NULL);
	eecloud_connect_callback_set(ecld, on_connect);
	eecloud_disconnect_callback_set(ecld, on_disconnect);

	rc = eecloud_connect(ecld, "localhost", 1888, 60);

	while(run == -1){
		eecloud_loop(ecld, -1, 1);
	}

	eecloud_lib_cleanup();
	return run;
}
