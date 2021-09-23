#include "Screen.h"

#include <iostream>

void Screen::Clear()
{
	std::cout << "\033[2J\033[1;1H"; // Magic I found for clearing the screen in a platform-agnostic way
}

void Screen::EraseCharacters(uint32_t count)
{
	
}