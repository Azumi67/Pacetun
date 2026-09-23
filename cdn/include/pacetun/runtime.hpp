#pragma once
#include "pacetun/config.hpp"
#include <string>
namespace pacetun {
int run(const Config& cfg);
int control_command(const std::string& socket_path, const std::string& command);
}
