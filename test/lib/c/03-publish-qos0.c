#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <eecloud.h>

static int run = -1;
static int sent_mid = -1;

void on_connect(struct eecloud *ecld, void *obj, int rc)
{
	if(rc){
		exit(1);
	}else{
		eecloud_publish(ecld, &sent_mid, "pub/qos0/test", strlen("message"), "message", 0, false);
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

int main(int argc, char *argv[])
{
	int rc;
	struct eecloud *ecld;

	eecloud_lib_init();

	ecld = eecloud_new("publish-qos0-test", true, NULL);
	eecloud_connect_callback_set(ecld, on_connect);
	eecloud_publish_callback_set(ecld, on_publish);

	rc = eecloud_connect(ecld, "localhost", 1888, 60);

	while(run == -1){
		eecloud_loop(ecld, -1, 1);
	}

	eecloud_lib_cleanup();
	return run;
}
