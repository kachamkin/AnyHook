﻿// Test.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include <string>
#include <Windows.h>

using namespace std;

__declspec(dllimport) extern BOOL SetRemoteHook(LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, DWORD);
__declspec(dllimport) extern void WINAPI RemoveRemoteHook(LPCWSTR, DWORD);
__declspec(dllimport) extern BOOL UseStealth;

int wmain()
{
    UseStealth = TRUE;
    SetRemoteHook(L"kernel32.dll", L"TerminateProcess", L"C:\\Users\\kacha\\source\\repos\\AnyHook\\ManagedShadow\\bin\\Debug\\ManagedShadow.dll", L"ShadowTerminateProcess", 8780);
    TerminateProcess(GetCurrentProcess(), 0);
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
