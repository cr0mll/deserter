#pragma once

#include <cstdint>

// A class for doing printing manipulations on the screen
class Screen
{
public:
	enum class ForegroundColour : uint8_t
	{
		Black = 30,
		Red = 31,
		Green = 32,
		Yellow = 33,
		Blue = 34,
		Magenta = 35,
		Cyan = 36,
		White = 37
	};

public:
	static void Clear();
	// Erases the last [count] characters
	static void EraseCharacters(uint32_t count = 1);

	static void SetColour(ForegroundColour colour);
	static void Reset();

	static void PrintBanner();
};