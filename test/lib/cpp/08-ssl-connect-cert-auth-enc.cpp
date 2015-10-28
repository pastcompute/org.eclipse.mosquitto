#include <cstring>
#include <eecloudpp.h>

static int run = -1;

static int password_callback(char* buf, int size, int rwflag, void* userdata)
{
	strncpy(buf, "password", size);
	buf[size-1] = '\0';

	return strlen(buf);
}

class eecloudpp_test : public ecldpp::eecloudpp
{
	public:
		eecloudpp_test(const char *id);

		void on_connect(int rc);
		void on_disconnect(int rc);
};

eecloudpp_test::eecloudpp_test(const char *id) : ecldpp::eecloudpp(id)
{
}

void eecloudpp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}else{
		disconnect();
	}
}

void eecloudpp_test::on_disconnect(int rc)
{
	run = rc;
}


int main(int argc, char *argv[])
{
	struct eecloudpp_test *ecld;

	ecldpp::lib_init();

	ecld = new eecloudpp_test("08-ssl-connect-crt-auth-enc");

	ecld->tls_opts_set(1, "tlsv1", NULL);
	//ecld->tls_set("../ssl/test-ca.crt", NULL, "../ssl/client.crt", "../ssl/client.key");
	ecld->tls_set("../ssl/all-ca.crt", NULL, "../ssl/client-encrypted.crt", "../ssl/client-encrypted.key", password_callback);
	ecld->connect("localhost", 1888, 60);

	while(run == -1){
		ecld->loop();
	}

	ecldpp::lib_cleanup();

	return run;
}
