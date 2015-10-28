#include <eecloudpp.h>

static int run = -1;

class eecloudpp_test : public ecldpp::eecloudpp
{
	public:
		eecloudpp_test(const char *id);
};

eecloudpp_test::eecloudpp_test(const char *id) : ecldpp::eecloudpp(id)
{
}

int main(int argc, char *argv[])
{
	struct eecloudpp_test *ecld;
	int rc = 1;

	ecldpp::lib_init();

	ecld = new eecloudpp_test("08-ssl-bad-cacert");

	ecld->tls_opts_set(1, "tlsv1", NULL);
	if(ecld->tls_set("this/file/doesnt/exist") == ECLD_ERR_INVAL){
		rc = 0;
	}
	ecldpp::lib_cleanup();

	return rc;
}
