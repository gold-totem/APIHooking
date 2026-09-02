#include "includes/injector.h"
#include "includes/config.h"


int main(int argc, char* argv[]) {

	auto config = Config::Config::getConfig("./config");

	if (!config) {
		return EXIT_FAILURE;
	}


	auto injector = Injector::Injector::get(config.value());

	if (!injector) {
		return EXIT_FAILURE;
	}

	injector.value().run();
	

}