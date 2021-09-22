#include <iostream>
#include "argparse.hpp"

#include "Program.h"

int main(int argc, char* argv[])
{

    Program program("deserter", argc, argv);

    std::cout << program.GetArgs().targetIP.toString() << std::endl;

    return 0;
}