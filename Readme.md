requirments:

visual studio 2026

cmake

vcpkg



build steps:
clone

cmake -B build -G "Visual Studio 18 2026" .

cmake --build build --config Release



cmake -B build32 -G "Visual Studio 18 2026" -A Win32 .

cmake --build build32 --config Release --target Sensor SensorStartup

