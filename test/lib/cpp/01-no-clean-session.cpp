#include <cstring>
#include <eecloudpp.h>

static int run = -1;

class eecloudpp_test : public ecldpp::eecloudpp
{
	public:
		eecloudpp_test(const char *id, bool clean_session);
};

eecloudpp_test::eecloudpp_test(const char *id, bool clean_session) : ecldpp::eecloudpp(id, clean_session)
{
}

int main(int argc, char *argv[])
{
	struct eecloudpp_test *ecld;

	ecldpp::lib_init();

	ecld = new eecloudpp_test("01-no-clean-session", false);

	ecld->connect("localhost", 1888, 60);

	while(run == -1){
		ecld->loop();
	}

	ecldpp::lib_cleanup();

	return run;
}
