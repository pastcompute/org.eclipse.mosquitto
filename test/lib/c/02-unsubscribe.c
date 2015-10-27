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
		eecloud_unsubscribe(ecld, NULL, "unsubscribe/test");
	}
}

void on_disconnect(struct eecloud *ecld, void *obj, int rc)
{
	run = rc;
}

void on_unsubscribe(struct eecloud *ecld, void *obj, int mid)
{
	eecloud_disconnect(ecld);
}

int main(int argc, char *argv[])
{
	int rc;
	struct eecloud *ecld;

	eecloud_lib_init();

	ecld = eecloud_new("unsubscribe-test", true, NULL);
	eecloud_connect_callback_set(ecld, on_connect);
	eecloud_disconnect_callback_set(ecld, on_disconnect);
	eecloud_unsubscribe_callback_set(ecld, on_unsubscribe);

	rc = eecloud_connect(ecld, "localhost", 1888, 60);

	while(run == -1){
		eecloud_loop(ecld, -1, 1);
	}

	eecloud_lib_cleanup();
	return run;
}
