// Suspend and resume process and query suspend state
//
// Compüile with:
// cl Priority.cpp

#define _WIN32_WINNT 0x0501 // Windows XP and above
#include "stdio.h"
#include <windows.h>
#include <psapi.h>

// gegen folgende Libraries linken:
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")


typedef LONG KPRIORITY;

struct CLIENT_ID
{
	DWORD UniqueProcess; // Process ID
#ifdef _WIN64
	ULONG pad1;
#endif
	DWORD UniqueThread; // Thread ID
#ifdef _WIN64
	ULONG pad2;
#endif
};

typedef struct
{
	FILETIME ProcessorTime;
	FILETIME UserTime;
	FILETIME CreateTime;
	ULONG WaitTime;
#ifdef _WIN64
	ULONG pad1;
#endif
	PVOID StartAddress;
	CLIENT_ID Client_Id;
	KPRIORITY CurrentPriority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchesPerSec;
	ULONG ThreadState;
	ULONG ThreadWaitReason;
	ULONG pad2;
} SYSTEM_THREAD_INFORMATION;


typedef struct
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING;

typedef struct
{
	ULONG_PTR PeakVirtualSize;
	ULONG_PTR VirtualSize;
	ULONG PageFaultCount;
#ifdef _WIN64
	ULONG pad1;
#endif
	ULONG_PTR PeakWorkingSetSize;
	ULONG_PTR WorkingSetSize;
	ULONG_PTR QuotaPeakPagedPoolUsage;
	ULONG_PTR QuotaPagedPoolUsage;
	ULONG_PTR QuotaPeakNonPagedPoolUsage;
	ULONG_PTR QuotaNonPagedPoolUsage;
	ULONG_PTR PagefileUsage;
	ULONG_PTR PeakPagefileUsage;
} VM_COUNTERS;

typedef struct
{
	ULONG NextOffset;
	ULONG ThreadCount;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	FILETIME CreateTime;
	FILETIME UserTime;
	FILETIME KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
#ifdef _WIN64
	ULONG pad1;
#endif
	ULONG ProcessId;
#ifdef _WIN64
	ULONG pad2;
#endif
	ULONG InheritedFromProcessId;
#ifdef _WIN64
	ULONG pad3;
#endif
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // always NULL, use SystemExtendedProcessInformation (57) to get value
	VM_COUNTERS VirtualMemoryCounters;
	ULONG_PTR PrivatePageCount;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD_INFORMATION ThreadInfos[1];
} SYSTEM_PROCESS_INFORMATION;

SYSTEM_PROCESS_INFORMATION *info;
#define SYSTEMPROCESSINFORMATION 5
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS) 0xC0000004)

typedef NTSTATUS (WINAPI* t_NtQuerySystemInformation)(int, PVOID, ULONG, PULONG);


typedef enum
{
	ThreadStateInitialized,
	ThreadStateReady,
	ThreadStateRunning,
	ThreadStateStandby,
	ThreadStateTerminated,
	ThreadStateWaiting,
	ThreadStateTransition,
	ThreadStateDeferredReady
} THREAD_STATE;

typedef enum
{
	ThreadWaitReasonExecutive,
	ThreadWaitReasonFreePage,
	ThreadWaitReasonPageIn,
	ThreadWaitReasonPoolAllocation,
	ThreadWaitReasonDelayExecution,
	ThreadWaitReasonSuspended,
	ThreadWaitReasonUserRequest,
	ThreadWaitReasonWrExecutive,
	ThreadWaitReasonWrFreePage,
	ThreadWaitReasonWrPageIn,
	ThreadWaitReasonWrPoolAllocation,
	ThreadWaitReasonWrDelayExecution,
	ThreadWaitReasonWrSuspended,
	ThreadWaitReasonWrUserRequest,
	ThreadWaitReasonWrEventPair,
	ThreadWaitReasonWrQueue,
	ThreadWaitReasonWrLpcReceive,
	ThreadWaitReasonWrLpcReply,
	ThreadWaitReasonWrVirtualMemory,
	ThreadWaitReasonWrPageOut,
	ThreadWaitReasonWrRendezvous,
	ThreadWaitReasonWrKeyedEvent,
	ThreadWaitReasonWrTerminated,
	ThreadWaitReasonWrProcessInSwap,
	ThreadWaitReasonWrCpuRateControl,
	ThreadWaitReasonWrCalloutStack,
	ThreadWaitReasonWrKernel,
	ThreadWaitReasonWrResource,
	ThreadWaitReasonWrPushLock,
	ThreadWaitReasonWrMutex,
	ThreadWaitReasonWrQuantumEnd,
	ThreadWaitReasonWrDispatchInt,
	ThreadWaitReasonWrPreempted,
	ThreadWaitReasonWrYieldExecution,
	ThreadWaitReasonWrFastMutex,
	ThreadWaitReasonWrGuardedMutex,
	ThreadWaitReasonWrRundown,
	ThreadWaitReasonMaximumWaitReason
} THREAD_WAIT_REASON;

// die undokumentierten Funktionen, die von NTDLL.DLL exportiert werden
typedef NTSTATUS (NTAPI *_NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef NTSTATUS (NTAPI *_NtResumeProcess)(IN HANDLE ProcessHandle);


// Betriebssystemprivileg anfordern (TRUE) oder abgeben (FALSE)
int privilege(LPTSTR pszPrivilege, BOOL bEnable)
{ HANDLE hToken;
  TOKEN_PRIVILEGES tp;

  // ermittle den Prozess Token
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken))
    return 1;

  // ermittle die luid
  if (!LookupPrivilegeValue(NULL, pszPrivilege, &tp.Privileges[0].Luid))
    return 1;

  tp.PrivilegeCount = 1;

  if (bEnable)
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  else
    tp.Privileges[0].Attributes = 0;

  // Privileg für Prozess ermöglichen/sperren
  if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0))
    return 1;

  if (!CloseHandle(hToken)) return 1;

  return 0;
}


// SucheProzesse - Suche Prozesse mit beginnendem Prozessnamenteil "sProcName"
// Gibt Anzahl der Prozesse zurück, in DWORD-Array aProcessID[] werden PIDs zurückgegeben
int SearchProcess(char *sProcName, DWORD aProcessID[], int iInstance)
{ DWORD aProcesses[1024], cbNeeded, cProcesses;
  char szProcessName[MAX_PATH], szFullName[MAX_PATH];
  HANDLE hProcess;
  int iCounter = 0, iFound = 0;
  bool bFinished = false;

  // Liste aller laufenden PIDs ermitteln
  if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
  { fprintf(stderr, "Cannot retrieve process list.\n");
    return -1;
  }

  // Anzahl PIDs
  cProcesses = cbNeeded / sizeof(DWORD);

  // Name und PID ausgeben
  for (unsigned int i = 0; (i < cProcesses) && (!bFinished); i++)
  {
    // Prozess Handle zur PID ermitteln
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, aProcesses[i]);
    if (hProcess)
		{
      // vollständigen Prozessnamen ermitteln
			if (GetProcessImageFileName(hProcess, szFullName, MAX_PATH))
			{
				// Dateinamen extrahieren
				if (strrchr(szFullName, '\\'))
				{
					strcpy(szProcessName, strrchr(szFullName, '\\') + 1);
				} else {
					strcpy(szProcessName, szFullName);
				}

      	// gesuchter Namensteil enthalten?
      	if (strnicmp(sProcName, szProcessName, strlen(sProcName)) == 0)
      	{ // gesuchte Instanz?
      		iFound++;
         	if ((iFound == iInstance) || (iInstance == -1))
      		{ // ja, dann PID in Liste
      			aProcessID[iCounter] = aProcesses[i];
      			if (iCounter < 1024) iCounter++;
      			// wenn ich nur eine Instanz suche, bin ich jetzt fertig
    				if (iInstance != -1) bFinished = true;
      		}
      	}
			}
      CloseHandle(hProcess);
		}
	}

  return iCounter;
}

// checks if process is suspended
class CheckSuspended
{
private:
	BYTE* pBuffer;
	DWORD dwBufLen;
	t_NtQuerySystemInformation f_NtQuerySystemInformation;

public:

	CheckSuspended()
	{
		dwBufLen = 0;
		pBuffer = NULL;
		// define WINAPI function NtQuerySystemInformation
		f_NtQuerySystemInformation = (t_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQuerySystemInformation");
	}

	virtual ~CheckSuspended()
	{ // free memory
		if (pBuffer) LocalFree(pBuffer);
	}

	// Snapshot of information of all running processes and their threads.
	// returns NTSTATUS Error code or zero if successfull
	DWORD Capture()
	{
		if (!f_NtQuerySystemInformation)
			return 1;

		// This runs in a loop because in the mean time a new process may have started
		// (happens normally only while debugging)
		while (true)
		{
			NTSTATUS lResult = f_NtQuerySystemInformation(SYSTEMPROCESSINFORMATION, pBuffer, dwBufLen, &dwBufLen);

			if (lResult == STATUS_INFO_LENGTH_MISMATCH)
			{ // The buffer is too small
				if (pBuffer) LocalFree(pBuffer);
				pBuffer = (BYTE*)LocalAlloc(LMEM_FIXED, dwBufLen);
				if (!pBuffer) return GetLastError();
				continue;
			}
			return lResult;
		}
	}

	// Searches a process by a given Process Identifier
	// Capture() must have been called before
	SYSTEM_PROCESS_INFORMATION* FindProcessByPid(DWORD dwPid)
	{
		if (!pBuffer)
			return NULL;

		SYSTEM_PROCESS_INFORMATION* pProcInfo = (SYSTEM_PROCESS_INFORMATION*)pBuffer;
		while (true)
		{ // loop through process information structs
			if (pProcInfo->ProcessId == dwPid)
				return pProcInfo;

			// reached the end
			if (!pProcInfo->NextOffset)
				return NULL;

			// next process
			pProcInfo = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)pProcInfo + pProcInfo->NextOffset);
		}
	}

	// Checks if all threads of a process are suspended
	DWORD AreThreadsSuspended(SYSTEM_PROCESS_INFORMATION* pProcInfo, BOOL* pb_Suspended)
	{
  	if (!pProcInfo)
  		return 1;

    SYSTEM_THREAD_INFORMATION* pThreadInfo = (SYSTEM_THREAD_INFORMATION*)&pProcInfo->ThreadInfos;

		if (!pThreadInfo)
			return 1;

    for (DWORD i = 0; i < pProcInfo->ThreadCount; i++)
    { // loop through thread information structs
    	if ((pThreadInfo->ThreadState != ThreadStateWaiting) || (pThreadInfo->ThreadWaitReason != ThreadWaitReasonSuspended))
    	{ // only if all threads are suspended, the process is suspended
    		*pb_Suspended = false;
    		return 0;
    	}

			// next struct
			pThreadInfo++;
    }

 		// all threads are suspended
 		*pb_Suspended = true;
 		return 0;
	}
};


int main(int argc, char* argv[])
{
	HANDLE hProcess = 0;
	int iModus = 1, rc = 0, iInstance = 1, iPIDCount;
	DWORD dwPIDList[1024];
	bool bPID = true;
	char cPuffer[1024];
	CheckSuspended* cSnapShot;
	SYSTEM_PROCESS_INFORMATION* pProcInfo;

	// Argumente prüfen
	if ((argc < 2) || ((argc > 1) && ((stricmp(argv[1], "-?") == 0) || (stricmp(argv[1], "/?") == 0))))
  { printf("Suspend.exe                                            (c) Markus Scholtes 2017\n\n");
    printf("Usage: Suspend [<parameter>] [<PID|program name>]\n\n");
    printf("Suspends process(es) oder resumes them. The operating system has a suspend\n");
    printf("counter, a process has to be resumed as often as it was suspended.\n");
    printf("Instead of a complete program name a starting part of the name can be supplied.\n");
    printf("Only the first found process is processed (see parameter /INSTANCE).\n\n");
		printf("Parameter:\n");
    printf("/INSTANCE:n - process n. found process with name part (default: 1).\n");
    printf("/INSTANCE:ALL - process all found processes with name part.\n");
    printf("        The parameter /INSTANCE: can be shortened by /I:.\n");
    printf("/QUERY or /Q - query suspend state of process(es).\n");
    printf("/SUSPEND or /S - suspend process(es) (default action).\n");
    printf("/RESUME or /R - resume process(es).\n");
    return 2;
	}

  // Parameter auswerten
  for (int i = 1; i < argc; i++)
  { if ((argv[i][0] == '/') || (argv[i][0] == '-'))
    { switch (toupper(argv[i][1]))
      { case 'Q': // Query
      			iModus = 0;
				  break;

        case 'R': // Resume
      			iModus = 2;
				  break;

				case 'S':  // Suspend (optional, da Standard)
      			iModus = 1;
				  break;

				case 'I':
					if (strnicmp(argv[i]+1, "INSTANCE:", 9) == 0)
				  { if (strnicmp(argv[i]+10, "ALL", 3) == 0)
				  		iInstance = -1;
				  	else
				  	{
				  		iInstance = atoi(argv[i] + 10);
				    	if (iInstance < 1)
				    	{ fprintf(stderr, "Invalid instance number specified.\n");
				      	rc = 2;
				    	}
				    }
				  }
				  else
				  {
						if (strnicmp(argv[i]+1, "I:", 2) == 0)
					  { if (strnicmp(argv[i]+3, "ALL", 3) == 0)
					  		iInstance = -1;
					  	else
					  	{
					  		iInstance = atoi(argv[i] + 3);
					    	if (iInstance < 1)
					    	{ fprintf(stderr, "Invalid instance number specified.\n");
					      	rc = 2;
					    	}
					    }
					  }
					  else
					    rc = 2;
				  }
				  break;

				default: // Parameterfehler
					rc = 2;
				 break;
	    }
    }
    else
    { // einmal PID oder Prozessname speichern (beim zweitenmal Fehler!)
    	if (rc == 0) strcpy(cPuffer, argv[i]);
    	rc++;
    }
  }

  // nur bei rc == 1 sind die Parameter korrekt
  if (rc != 1)
  { fprintf(stderr, "Invalid parameter.\n");
    return 2;
  }

  // PID oder Prozessname übergeben?
  for (unsigned int j = 0; (j < strlen(cPuffer)) && (bPID); j++)
  {
  	if ((cPuffer[j] < '0') || (cPuffer[j] > '9')) bPID = false;
  }

	// DEBUG-Recht anfordern, um auch fremde Prozesse untersuchen zu können
  if (privilege(SE_DEBUG_NAME, TRUE))
  { fprintf(stderr,"Debug prvilege denied.\n");
    return 1; }

	if (bPID)
	{ // PID übergeben -> in Array speichern
		iPIDCount = 1;
		dwPIDList[0] = atoi(cPuffer);

		// PID auf Gültigkeit prüfen
		if (dwPIDList[0] < 20)
  	{ fprintf(stderr, "Invalid process ID %s.\n", cPuffer);
		  // DEBUG-Recht zurückgeben
  		privilege(SE_DEBUG_NAME, FALSE);
  		return 2;
  	}
	}
	else
	{ // Prozessnamensteil übergeben, Prozessliste durchsuchen
		iPIDCount = SearchProcess(cPuffer, dwPIDList, iInstance);

		if (iPIDCount <= 0)
  	{ printf("No process to name mask found.\n");
		  // DEBUG-Recht zurückgeben
  		privilege(SE_DEBUG_NAME,FALSE);
  		return 0;
  	}
	}

	// Funktionen importieren
	_NtSuspendProcess NtSuspendProcess = (_NtSuspendProcess)GetProcAddress(GetModuleHandle("NTDLL"), "NtSuspendProcess");
	_NtResumeProcess NtResumeProcess = (_NtResumeProcess)GetProcAddress(GetModuleHandle("NTDLL"), "NtResumeProcess");
	if ((!NtSuspendProcess) || (!NtResumeProcess))
  { fprintf(stderr, "Cannot import functions of NTDLL.DLL.\n");
  	return 1;
  }

	if (iModus == 0)
	{ // bei Abfragemodus Prozessinformationssnapshot erstellen
		cSnapShot = new CheckSuspended();
		if (cSnapShot->Capture())
		{
			delete cSnapShot;
			fprintf(stderr, "Error retrieving process information.\n");
			return 1;
		}
	}


	// PID-Liste durchlaufen
  for (int i = 0; i < iPIDCount; i++)
  {
		if (iModus > 0)
		{
			// Prozess öffnen
			hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, dwPIDList[i]);

			// Prozess anhalten oder fortsetzen
			// Achtung: das Betriebssystem unterhält einen Zähler.
			// Ein Prozess, der z.B. zweimal angehalten wurde, muss zweimal
			// fortgesetzt
			if (!hProcess)
			{
				fprintf(stderr, "Cannot open process with ID %d.\n", dwPIDList[i]);
				if (iPIDCount == 1)
				{
				  // DEBUG-Recht zurückgeben
	  			privilege(SE_DEBUG_NAME, FALSE);
					return 1;
				}
			}
			else
			{ // welche Funktion ist gewählt?
		  	if (iModus == 1)
		  	{ // Prozess anhalten
	  			NtSuspendProcess(hProcess);
	  			printf("Process with ID %d suspended.\n", dwPIDList[i]);
		  	}
		  	else
		  	{ // Prozess fortsetzen
		  		NtResumeProcess(hProcess);
	  			printf("Process with ID %d resumed.\n", dwPIDList[i]);
		  	}
				// Handle zu Prozess schliessen
				CloseHandle(hProcess);
			}
		}
		else
		{ // Status abfragen
			pProcInfo = cSnapShot->FindProcessByPid(dwPIDList[i]);
			if (!pProcInfo)
			{
				printf("Can get no informationen to process with ID %d.\n", dwPIDList[i]);
			}
			else
			{ BOOL bSuspended = false;
				if (cSnapShot->AreThreadsSuspended(pProcInfo, &bSuspended))
				{
					printf("Can get no thread informationen to process with ID %d.\n", dwPIDList[i]);
				}
				else
				{
					if (bSuspended)
	  				printf("Process with ID %d is suspended.\n", dwPIDList[i]);
					else
	  				printf("Process with ID %d is not suspended.\n", dwPIDList[i]);
				}
			}
		}
	}

 	// bei Abfragemodus Prozessinformationssnapshot löschen
 	if (iModus == 0) delete cSnapShot;

  // DEBUG-Recht zurückgeben
  privilege(SE_DEBUG_NAME, FALSE);

	return 0;
}
