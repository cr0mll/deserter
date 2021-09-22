#include <iostream>
#include "argparse.hpp"

#include "Program.h"

int main(int argc, char* argv[])
{

    Program program("deserter", argc, argv);
    program.Run();

    return 0;
}