#include "includes/injector.h"
#include "includes/config.h"

#include <iostream>

int main(int argc, char* argv[]) {

	std::string_view configPath{ "./config" };

	if ((std::strcmp(argv[1], "-c") == 0) ||
		(std::strcmp(argv[1], "--config") == 0)) {
		configPath = argv[2];
	}
	auto config = Config::Config::getConfig(configPath);

	if (!config) {
		std::cerr << "Unable to load config\n";
		return EXIT_FAILURE;
	}


	auto injector = Injector::Injector::get(config.value());

	if (!injector) {
		return EXIT_FAILURE;
	}

	injector.value().run();
	

}