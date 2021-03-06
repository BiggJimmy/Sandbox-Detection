#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <map>

std::vector<std::string> blacklisted_modules =
{
	"snxhk.dll", /* Avast Sandbox's module name */
	"SbieDll.dll", /* Sandboxie's module name */
	"cmdvrt32.dll", /* Comodo Sandbox's module name */
	"SxIn.dll" /* Qihoo360 Sandbox's module name  */
};

std::map<std::string, HMODULE> modules_map;
std::map<std::string, HMODULE>::iterator iterator;

/* unloads a module from memory */
void unload_module(std::pair<std::string, HMODULE> module)
{
	/* find the blacklisted module */
	iterator = modules_map.find(module.first);

	/* remove the blacklisted module from the map */
	modules_map.erase(iterator);

	/* unload the module from memory */
	FreeLibraryAndExitThread(module.second, 1);
}

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
bool detect_environment()
{
	/* set exit status to success */
	bool success = true;

	/* iterate through process modules */
	for (auto module : modules_map)
	{
		/* iterate through blacklisted modules */
		for (auto blm : blacklisted_modules)
		{
			/* check if the module is blacklisted */
			if (blm == module.first)
			{
				/* print some stuff in the console */
				std::cout << "[-] blacklisted module detected!" << std::endl << "\tName : " << module.first << " (0x" << std::hex << module.second << ')' << std::endl;

				/* attempt to unload the module */
				unload_module(module);

				/* set exit status to failure */
				success = false;
			}
		}
	}

	/* return exit status */
	return success;
}

int main()
{
	/* create a map of all the loaded modules */
	create_modules_map();

	/* check for blacklisted modules */
	if (!detect_environment())
		return 1;

	std::cout << "Hello World!" << std::endl;
	Sleep(5000);

	return 0;
}