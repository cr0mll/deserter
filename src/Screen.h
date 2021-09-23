#pragma once

#include <cstdint>

// A class for doing printing manipulations on the screen
class Screen
{
public:
	static void Clear();
	// Erases the last [count] characters
	static void EraseCharacters(uint32_t count = 1);
};