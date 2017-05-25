// Prozess anhalten und fortsetzen
//
// Kompilieren mit:
// cl Priority.cpp

#define _WIN32_WINNT 0x0501 // Windows XP and above
#include "stdio.h"
#include <windows.h>
#include <psapi.h>

// gegen folgende Libraries linken:
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// f¸r Borland Compiler
#ifndef NTSTATUS
#define NTSTATUS long
#endif

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

  // Privileg f¸r Prozess ermˆglichen/sperren
  if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0))
    return 1;

  if (!CloseHandle(hToken)) return 1;

  return 0;
}


// SucheProzesse - Suche Prozesse mit beginnendem Prozessnamenteil "sProcName"
// Gibt Anzahl der Prozesse zur¸ck, in DWORD-Array aProcessID[] werden PIDs zur¸ckgegeben
int SearchProcess(char *sProcName, DWORD aProcessID[], int iInstance)
{ DWORD aProcesses[1024], cbNeeded, cProcesses;
  char szProcessName[MAX_PATH], szFullName[MAX_PATH];
  HANDLE hProcess;
  int iCounter = 0, iFound = 0;
  bool bFinished = false;

  // Liste aller laufenden PIDs ermitteln
  if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
  { fprintf(stderr, "Kann Prozessliste nicht ermitteln.\n");
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
      // vollst‰ndigen Prozessnamen ermitteln
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


int main(int argc, char* argv[])
{
	HANDLE hProcess = 0;
	int rc = 0, iInstance = 1, iPIDCount;
	DWORD dwPIDList[1024];
	bool bModus = true, bPID = true;
	char cPuffer[1024];

	// Argumente pr¸fen
	if ((argc < 2) || ((argc > 1) && ((stricmp(argv[1], "-?") == 0) || (stricmp(argv[1], "/?") == 0))))
  { printf("Suspend.exe                                            (c) Markus Scholtes 2016\n\n");
    printf("Aufruf: Suspend [<Parameter>] [<PID|Programmname>]\n\n");
    printf("HÑlt Prozess(e) an oder setzt ihn/sie fort. Das Betriebssystem unterhÑlt einen\n");
    printf("Suspend-ZÑhler, ein Prozess muss genauso oft fortgesetzt werden, wie er\n");
    printf("angehalten wurde.\n");
    printf("Es reicht die Angabe des Anfangs des Programmnamens. Es wird nur der erste\n");
    printf("gefundene Prozess bearbeitet (siehe Parameter /INSTANCE).\n\n");
		printf("Parameter:\n");
    printf("/INSTANCE:n - n. gefundener Prozess mit Namensteil bearbeiten (Standard: 1).\n");
    printf("/INSTANCE:ALL - alle gefundenen Prozesse mit Namensteil bearbeiten.\n");
    printf("        Der Parameter /INSTANCE: kann durch /I: abgekÅrzt werden.\n");
    printf("/SUSPEND oder /S - Prozess(e) anhalten (Standardaktion).\n");
    printf("/RESUME oder /R - Prozess(e) fortsetzen.\n");
    return 2;
	}

  // Parameter auswerten
  for (int i = 1; i < argc; i++)
  { if ((argv[i][0] == '/') || (argv[i][0] == '-'))
    { switch (toupper(argv[i][1]))
      { case 'R': // Resume
      			bModus = false;
				  break;

				case 'S':  // Suspend (optional, da Standard)
      			bModus = true;
				  break;

				case 'I':
					if (strnicmp(argv[i]+1, "INSTANCE:", 9) == 0)
				  { if (strnicmp(argv[i]+10, "ALL", 3) == 0)
				  		iInstance = -1;
				  	else
				  	{
				  		iInstance = atoi(argv[i] + 10);
				    	if (iInstance < 1)
				    	{ fprintf(stderr, "UngÅltige Instanznummer angegeben.\n");
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
					    	{ fprintf(stderr, "UngÅltige Instanznummer angegeben.\n");
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
  { fprintf(stderr, "Fehlerhafte Parameter.\n");
    return 2;
  }

  // PID oder Prozessname ¸bergeben?
  for (unsigned int j = 0; (j < strlen(cPuffer)) && (bPID); j++)
  { 
  	if ((cPuffer[j] < '0') || (cPuffer[j] > '9')) bPID = false;
  }

	// DEBUG-Recht anfordern, um auch fremde Prozesse untersuchen zu kˆnnen
  if (privilege(SE_DEBUG_NAME, TRUE))
  { fprintf(stderr,"Debug-Recht verweigert.\n");
    return 1; }

	if (bPID)
	{ // PID ¸bergeben -> in Array speichern
		iPIDCount = 1;
		dwPIDList[0] = atoi(cPuffer);

		// PID auf G¸ltigkeit pr¸fen
		if (dwPIDList[0] < 20)
  	{ fprintf(stderr, "UngÅltige Prozess-ID %s.\n", cPuffer);
		  // DEBUG-Recht zur¸ckgeben
  		privilege(SE_DEBUG_NAME, FALSE);
  		return 2;
  	}
	}
	else
	{ // Prozessnamensteil ¸bergeben, Prozessliste durchsuchen
		iPIDCount = SearchProcess(cPuffer, dwPIDList, iInstance);

		if (iPIDCount <= 0)
  	{ printf("Keinen passenden Prozess gefunden.\n");
		  // DEBUG-Recht zur¸ckgeben
  		privilege(SE_DEBUG_NAME,FALSE);
  		return 0;
  	}
	}

	// Funktionen importieren
	_NtSuspendProcess NtSuspendProcess = (_NtSuspendProcess)GetProcAddress(GetModuleHandle("NTDLL"), "NtSuspendProcess");
	_NtResumeProcess NtResumeProcess = (_NtResumeProcess)GetProcAddress(GetModuleHandle("NTDLL"), "NtResumeProcess");
	if ((!NtSuspendProcess) || (!NtResumeProcess))
  { fprintf(stderr, "Kann Funktionen nicht aus NTDLL.DLL importieren\n");
  	return 1;
  }


	// PID-Liste durchlaufen
  for (int i = 0; i < iPIDCount; i++)
  {
		// Prozess ˆffnen
		hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, dwPIDList[i]);

		// Prozess anhalten oder fortsetzen
		// Achtung: das Betriebssystem unterh‰lt einen Z‰hler.
		// Ein Prozess, der z.B. zweimal angehalten wurde, muss zweimal
		// fortgesetzt
		if (!hProcess)
		{
			fprintf(stderr, "Kann Prozess mit der ID %d nicht îffnen.\n", dwPIDList[i]);
			if (iPIDCount == 1) 
			{ 
			  // DEBUG-Recht zur¸ckgeben
  			privilege(SE_DEBUG_NAME, FALSE);
				return 1;
			}
		}
		else
		{ // welche Funktion ist gew‰hlt?
	  	if (bModus)
	  	{ // Prozess anhalten
  			NtSuspendProcess(hProcess);
  			printf("Prozess mit der ID %d angehalten.\n", dwPIDList[i]);
	  	}
	  	else
	  	{ // Prozess fortsetzen
	  		NtResumeProcess(hProcess);
  			printf("Prozess mit der ID %d fortgesetzt.\n", dwPIDList[i]);
		  }

			// Handle zu Prozess schliessen
			CloseHandle(hProcess);
		}
	}

  // DEBUG-Recht zur¸ckgeben
  privilege(SE_DEBUG_NAME, FALSE);

	return 0;
}
