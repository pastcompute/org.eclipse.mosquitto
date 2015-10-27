#include <errno.h>
#include <eecloudpp.h>

static int run = -1;

class eecloudpp_test : public ecldpp::eecloudpp
{
	public:
		eecloudpp_test(const char *id);

		void on_connect(int rc);
};

eecloudpp_test::eecloudpp_test(const char *id) : ecldpp::eecloudpp(id)
{
}

void eecloudpp_test::on_connect(int rc)
{
	exit(1);
}

int main(int argc, char *argv[])
{
	struct eecloudpp_test *ecld;
	int rc;

	ecldpp::lib_init();

	ecld = new eecloudpp_test("08-ssl-fake-cacert");

	ecld->tls_opts_set(1, "tlsv1", NULL);
	ecld->tls_set("../ssl/test-fake-root-ca.crt", NULL, "../ssl/client.crt", "../ssl/client.key");
	ecld->connect("localhost", 1888, 60);

	rc = ecld->loop_forever();
	if(rc == MOSQ_ERR_ERRNO && errno == EPROTO){
		return 0;
	}else{
		return 1;
	}
}
