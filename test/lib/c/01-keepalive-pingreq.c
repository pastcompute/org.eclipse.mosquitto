#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <eecloud.h>

static int run = -1;

void on_connect(struct eecloud *ecld, void *obj, int rc)
{
	if(rc){
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	int rc;
	struct eecloud *ecld;

	eecloud_lib_init();

	ecld = eecloud_new("01-keepalive-pingreq", true, NULL);
	eecloud_connect_callback_set(ecld, on_connect);

	rc = eecloud_connect(ecld, "localhost", 1888, 4);

	while(run == -1){
		eecloud_loop(ecld, -1, 1);
	}

	eecloud_lib_cleanup();
	return run;
}
