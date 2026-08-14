#include "includes/injector.h"
#include "includes/config.h"

namespace {
	void modeOnce(const Injector::Injector& injector) {

	}

	void modeContinuous(const Injector::Injector& injector) {

	}

	void modeCreate(const Injector::Injector& injector) {

	}
}
int main(int argc, char* argv[]) {

	auto config = Config::getConfig("./config");

	if (!config) {
		return EXIT_FAILURE;
	}


	auto optInject = Injector::Injector::get(config.value());

	if (!optInject) {
		return EXIT_FAILURE;
	}
	auto injector = optInject.value();

	switch (config.value().injectorMode) {

	case Config::InjectorMode::INJECT_ONCE:
		modeOnce(injector);
		break;

	case Config::InjectorMode::INJECT_CREATE:
		modeContinuous(injector);
		break;
	case Config::InjectorMode::INJECT_CONT:
		modeCreate(injector);
		break;
	
	}

}