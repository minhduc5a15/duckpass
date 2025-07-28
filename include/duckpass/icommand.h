#pragma once

#include <memory>

namespace CLI {
    class App;
}

class i_command {
public:
    virtual ~i_command() = default;

    virtual void execute() = 0;
};
