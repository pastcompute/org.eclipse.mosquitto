#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <eecloud.h>

static int run = -1;
int main(int argc, char *argv[])
{
	int rc;
	struct eecloud *ecld;

	eecloud_lib_init();

	ecld = eecloud_new("01-will-unpwd-set", true, NULL);
	eecloud_username_pw_set(ecld, "oibvvwqw", "#'^2hg9a&nm38*us");
	eecloud_will_set(ecld, "will-topic", strlen("will message"), "will message", 2, false);

	rc = eecloud_connect(ecld, "localhost", 1888, 60);

	while(run == -1){
		eecloud_loop(ecld, -1, 1);
	}

	eecloud_lib_cleanup();
	return run;
}
