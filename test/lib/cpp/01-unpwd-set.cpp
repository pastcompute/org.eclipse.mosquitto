#include <cstring>
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

	ecldpp::lib_init();

	ecld = new eecloudpp_test("01-unpwd-set");
	ecld->username_pw_set("uname", ";'[08gn=#");

	ecld->connect("localhost", 1888, 60);

	while(run == -1){
		ecld->loop();
	}

	ecldpp::lib_cleanup();

	return run;
}
