#include "encryption.h"

char key[4] = { 'l', 'z', 'E', 'p' };

std::string XOR(std::string data)
{
	std::string buffer = data;
	for (int i = 0; i < buffer.size(); i++)
	{
		buffer[i] = data[i] ^ key[i % (sizeof(key) / sizeof(char))];
	}

	return buffer;
}