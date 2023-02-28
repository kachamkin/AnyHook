// Test.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include <string>
#include <Windows.h>
#include <winternl.h>

using namespace std;

__declspec(dllimport) extern BOOL SetRemoteHook(LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, DWORD);
__declspec(dllimport) extern void WINAPI RemoveRemoteHook(LPCWSTR, DWORD);
__declspec(dllimport) extern BOOL UseStealth;

__kernel_entry NTSTATUS NtQuerySystemInformationShadow(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, // What info to be retrieved. 
    PVOID                    SystemInformation,     // A buffer that receives the requested information.
    ULONG                    SystemInformationLength, // The size of the buffer pointed to by the SystemInformation parameter, in bytes.
    PULONG                   ReturnLength // Optional.
)
{
    // Calling og function (Trampoline)
    //NTSTATUS status = qsi(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (SystemProcessInformation == SystemInformationClass)
    {
        SYSTEM_PROCESS_INFORMATION* pCurrent;
        SYSTEM_PROCESS_INFORMATION* pNext = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;

        do
        {
            pCurrent = pNext;
            pNext = (SYSTEM_PROCESS_INFORMATION*)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

            if (wcsncmp(pNext->ImageName.Buffer, L"Test.exe", pNext->ImageName.Length) == 0)
            {
                if (pNext->NextEntryOffset == 0)
                    pCurrent->NextEntryOffset = 0;
                else
                    pCurrent->NextEntryOffset += pNext->NextEntryOffset;
            }

        } while (pCurrent->NextEntryOffset != 0);

    }

    return 0;
}

int wmain()
{
    //UseStealth = FALSE;
    BOOL res = SetRemoteHook(L"ntdll.dll", L"NtQuerySystemInformation", L"C:\\Users\\kacha\\source\\repos\\AnyHook\\x64\\Debug\\Shadow.dll", L"NtQuerySystemInformationShadow", 8280);
    //Sleep(1);
    //RemoveRemoteHook(L"TerminateProcess", 31428);
    //TerminateProcess(GetCurrentProcess(), 0);
    WaitForSingleObject(GetCurrentProcess(), INFINITE);
    return 0;
}

// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
