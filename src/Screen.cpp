#include "Screen.h"

#include <iostream>

void Screen::Clear()
{
	std::cout << "\033[2J\033[1;1H"; // Magic I found for clearing the screen in a platform-agnostic way
}

void Screen::EraseCharacters(uint32_t count)
{
	
}

void Screen::PrintBanner()
{
	std::cout << "    ____                      __           " << std::endl;
    std::cout << "   / __ \\___  ________  _____/ /____  _____" << std::endl;
    std::cout << "  / / / / _ \\/ ___/ _ \\/ ___/ __/ _ \\/ ___/" << std::endl;
    std::cout << " / /_/ /  __(__  )  __/ /  / /_/  __/ /    " << std::endl;
    std::cout << "/_____/\\___/____/\\___/_/   \\__/\\___/_/     " << std::endl;
    std::cout << "                                           " << std::endl;

}

void Screen::Reset()
{
	std::cout << "\033[m" << std::flush;
}

void Screen::SetColour(Screen::ForegroundColour colour)
{
	std::string colourStr = "\033[" + std::to_string(static_cast<uint8_t>(colour)) + "m";
	std::cout << colourStr << std::flush;
}