#include "includes/injector.h"
#include "includes/config.h"

int main(int argc, char* argv[]) {

	auto config = Config::getConfig("./config");

	if (!config) {
		return EXIT_FAILURE;
	}

	
}