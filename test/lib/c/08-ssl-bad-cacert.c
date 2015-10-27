#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <eecloud.h>

int main(int argc, char *argv[])
{
	int rc = 1;
	struct eecloud *ecld;

	eecloud_lib_init();

	ecld = eecloud_new("08-ssl-bad-cacert", true, NULL);
	eecloud_tls_opts_set(ecld, 1, "tlsv1", NULL);
	if(eecloud_tls_set(ecld, "this/file/doesnt/exist", NULL, NULL, NULL, NULL) == MOSQ_ERR_INVAL){
		rc = 0;
	}
	eecloud_lib_cleanup();
	return rc;
}
