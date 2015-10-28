#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <eecloud.h>

static int run = -1;

void on_connect(struct eecloud *ecld, void *obj, int rc)
{
	exit(1);
}

int main(int argc, char *argv[])
{
	int rc;
	struct eecloud *ecld;

	eecloud_lib_init();

	ecld = eecloud_new("08-ssl-connect-crt-auth", true, NULL);
	eecloud_tls_opts_set(ecld, 1, "tlsv1", NULL);
	eecloud_tls_set(ecld, "../ssl/test-fake-root-ca.crt", NULL, "../ssl/client.crt", "../ssl/client.key", NULL);
	eecloud_connect_callback_set(ecld, on_connect);

	rc = eecloud_connect(ecld, "localhost", 1888, 60);

	rc = eecloud_loop_forever(ecld, -1, 1);
	if(rc == ECLD_ERR_ERRNO && errno == EPROTO){
		return 0;
	}else{
		return 1;
	}
}

