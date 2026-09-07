#include "includes/injector.h"
#include "includes/config.h"

#include <iostream>

int main(int argc, char* argv[]) {


	if (argc < 3 || (std::strcmp(argv[1], "-c") != 0)) {
		std::cerr << "Usage:\n\t" << argv[0] << " -c <config_path>\n";
		return EXIT_FAILURE;
	}

	auto config = Config::Config::getConfig(argv[2]);

	if (!config) {
		return EXIT_FAILURE;
	}


	auto injector = Injector::Injector::get(config.value());

	if (!injector) {
		return EXIT_FAILURE;
	}

	injector.value().run();
	

}