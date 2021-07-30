#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <map>

#include "encryption.h"

std::vector<std::string> blacklisted_modules =
{
	XOR("snxhk.dll"), /* Avast Sandbox's module name */
	XOR("SbieDll.dll"), /* Sandboxie's module name */
	XOR("cmdvrt32.dll"), /* Comodo Sandbox's module name */
	XOR("SxIn.dll") /* Qihoo360 Sandbox's module name  */
};

std::map<std::string, HMODULE> modules_map;

/* create a map of all the loaded modules in the current process */
void create_modules_map()
{
	HMODULE modules[1024];
	DWORD needed;

	/* open a handle to our current process */
	HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());

	/* validate the handle */
	if (process_handle == INVALID_HANDLE_VALUE)
		return;

	/* get a list of the process modules */
	if (EnumProcessModules(process_handle, modules, sizeof(modules), &needed))
	{
		/* iterate through the modules */
		for (unsigned int i = 0; i < (needed / sizeof(HMODULE)); i++)
		{
			TCHAR module_name[MAX_PATH];

			/* get the module base name aswell as the module handle and insert it to the module map */
			if (GetModuleBaseName(process_handle, modules[i], module_name, sizeof(module_name) / sizeof(TCHAR)))
				modules_map.insert(std::pair<std::string, HMODULE>(module_name, modules[i]));
		}
	}

	/* close our process handle as it is no longer needed */
	CloseHandle(process_handle);
}

/* parse the loaded modules and check if they are blacklisted */
int detect_environment()
{
	for (auto module : modules_map)
	{
		/* iterate through blacklisted modules */
		for (auto blm : blacklisted_modules)
		{
			/* decrypt the name of the blacklisted module */
			std::string bl_module_name = XOR(blm);

			/* check if the module is blacklisted */
			if (bl_module_name == module.first)
			{
				std::cout << "[-] blacklisted module detected!" << std::endl << "\tName : " << module.first << " (0x" << std::hex << module.second << ')' << std::endl;

				/* return exit failure */
				return 1;
			}
		}
	}

	/* return exit success */
	return 0;
}

int main()
{
	create_modules_map();

	/* check if process is sandboxed */
	if (detect_environment() == 1)
	{
		std::cout << "[-] sandbox detected!" << std::endl;
		Sleep(5000);

		return 1;
	}

	std::cout << "Hello World!" << std::endl;
	Sleep(5000);

	return 0;
}