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
		eecloud_subscribe(ecld, NULL, "qos2/test", 2);
	}
}

void on_disconnect(struct eecloud *ecld, void *obj, int rc)
{
	run = rc;
}

void on_subscribe(struct eecloud *ecld, void *obj, int mid, int qos_count, const int *granted_qos)
{
	eecloud_disconnect(ecld);
}

int main(int argc, char *argv[])
{
	int rc;
	struct eecloud *ecld;

	eecloud_lib_init();

	ecld = eecloud_new("subscribe-qos2-test", true, NULL);
	eecloud_connect_callback_set(ecld, on_connect);
	eecloud_disconnect_callback_set(ecld, on_disconnect);
	eecloud_subscribe_callback_set(ecld, on_subscribe);

	rc = eecloud_connect(ecld, "localhost", 1888, 60);

	while(run == -1){
		eecloud_loop(ecld, -1, 1);
	}

	eecloud_lib_cleanup();
	return run;
}
