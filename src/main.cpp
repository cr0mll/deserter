#include <iostream>
#include <condition_variable>

#include "argparse.hpp"

#include "Program.h"
#include "Screen.h"

int main(int argc, char* argv[])
{

    Program program("deserter", argc, argv);
    program.Run();

    return 0;
}