/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org>,
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 * Copyright 2010-2022, Karl Heyes <karl@kheyes.plus.com>
 *
 */

#include <config.h>
#include <winsock2.h>
#include <stdio.h>
#include <direct.h>

extern "C" {
#include "thread/thread.h"
#include "avl/avl.h"
#include "log/log.h"
#include "global.h"
#include "httpp/httpp.h"
#include "net/sock.h"
#include "connection.h"
#include "refbuf.h"
#include "client.h"
#include "stats.h"
#include "fserve.h"
}

// Issues to be wary of. Careful of the runtime you use, I've had printf and similar routines
// crash because of this on apparently valid strings. some weird thing related to checking for
// multiple byte characters.  DeleteService only marks a service for deletion, and the docs
// are unclear on the cases that lead to purging however a reboot should do it.

SERVICE_STATUS          ServiceStatus; 
SERVICE_STATUS_HANDLE   hStatus; 
 
void  ServiceMain(int argc, char** argv); 
void  ControlHandler(DWORD request); 


void installService (const char *path)
{
	if (path) {
        TCHAR fullPath [MAX_PATH] = "\"";
        int len = GetModuleFileName (NULL, fullPath+1, sizeof (fullPath)-1);

		_snprintf (fullPath+len+1, sizeof (fullPath)-len, "\" \"%s\"", path);

		SC_HANDLE manager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if (manager == NULL)
		{
            MessageBox (NULL, "OpenSCManager failed", NULL, MB_SERVICE_NOTIFICATION);
			return;
		}

        SC_HANDLE service = CreateService(
                manager,
                PACKAGE_NAME,
                PACKAGE_NAME " Streaming Media Server",
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_IGNORE,
                fullPath,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL
		);
		if (service == NULL)
		{
            MessageBox (NULL, "CreateService failed", NULL, MB_SERVICE_NOTIFICATION);
			CloseServiceHandle (manager);
			return;
		}

        SERVICE_DESCRIPTION sd;

        sd.lpDescription = (char*)"Provides streaming media services";

        if (ChangeServiceConfig2(
                    service,                        // handle to service
                    SERVICE_CONFIG_DESCRIPTION,     // change: description
                    &sd) == FALSE)                  // new description
        {
            printf("ChangeServiceConfig2 failed\n");
        }

		printf ("Service Installed\n");
		CloseServiceHandle (service);
		CloseServiceHandle (manager);
	}
}
void removeService()
{
	SC_HANDLE manager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
	if (manager == NULL)
	{
        MessageBox (NULL, "OpenSCManager failed", NULL, MB_SERVICE_NOTIFICATION);
		return;
	}

	SC_HANDLE service = OpenService (manager, PACKAGE_NAME, DELETE);
	if (service) {
		DeleteService(service);
        CloseServiceHandle (service);
		printf ("Service deleted, may require reboot to complete removal\n");
	}
    else
		printf ("Service not found\n");
    CloseServiceHandle (manager);
    Sleep (1500);
}
void ControlHandler(DWORD request) 
{ 
   switch(request) { 
      case SERVICE_CONTROL_STOP: 
          if (ServiceStatus.dwCurrentState != SERVICE_STOPPED && ServiceStatus.dwCurrentState != SERVICE_STOP_PENDING)
          {
              ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
              SetServiceStatus (hStatus, &ServiceStatus);
              global.running = ICE_HALTING;
              return; 
          }
 
      default:
		break;
    } 
}


static int run_server (int argc, char *argv[])
{
    int		ret;

    initialize_subsystems();
    fserve_initialize();

    ret = server_init (argc, argv);
    if (ret == 0)
        server_process();

    shutdown_subsystems();
    return ret;
}


void ServiceMain(int argc, char** argv) 
{ 
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
    ServiceStatus.dwWin32ExitCode = -1; 
    ServiceStatus.dwServiceSpecificExitCode = 0; 
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0; 

    hStatus = RegisterServiceCtrlHandler(PACKAGE_STRING, (LPHANDLER_FUNCTION)ControlHandler); 
    if (hStatus == (SERVICE_STATUS_HANDLE)0) { 
        // Registering Control Handler failed
        MessageBox (NULL, "RegisterServiceCtrlHandler failed", NULL, MB_SERVICE_NOTIFICATION);
        return; 
    }  

    // We report the running status to SCM. 
    ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus (hStatus, &ServiceStatus);

    /* Here we do the work */

    int		argc2 = 3;
    char*	argv2 [3];

    argv2 [0] = argv[0];
    argv2 [1] = (char*)"-c";
    if (argc < 2)
        argv2 [2] = (char *)"icecast.xml";
    else
        argv2 [2] = argv[1];

    ServiceStatus.dwWin32ExitCode = run_server (argc2, argv2);

    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    ServiceStatus.dwControlsAccepted &= ~SERVICE_ACCEPT_STOP;
    SetServiceStatus(hStatus, &ServiceStatus);
}


int main (int argc, char *argv[]) 
{
    do
    {
        if (argc < 2 || argc > 3)
            break;
        if (strcmp (argv[1], "-v") == 0 || strcmp (argv[1], "-h") == 0)
            break;
        if (!strcmp(argv[1], "remove") || !strcmp(argv[1], "uninstall"))
        {
            removeService();
            return 0;
        }
        if (!strcmp(argv[1], "install"))
        {
            if (argc == 3)
            {
                installService(argv[2]);
                Sleep (1000);
                return 0;
            }
            printf ("install requires a path arg as well\n");
            break;
        }
        if (strcmp (argv[1], "-c") == 0)
        {
            if (argc == 3)
                return run_server (argc, argv);
            break;
        }

        if (_chdir(argv[1]) < 0)
        {
            char buffer [256];
            snprintf (buffer, sizeof(buffer), "Unable to change to directory %s", argv[1]);
            MessageBox (NULL, buffer, NULL, MB_SERVICE_NOTIFICATION);
            return -1;
        }

        SERVICE_TABLE_ENTRY ServiceTable[2];
        ServiceTable[0].lpServiceName = (char*)PACKAGE_STRING;
        ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

        ServiceTable[1].lpServiceName = NULL;
        ServiceTable[1].lpServiceProc = NULL;
        // Start the control dispatcher thread for our service
        if (StartServiceCtrlDispatcher (ServiceTable) == 0)
            MessageBox (NULL, "StartServiceCtrlDispatcher failed", NULL, MB_SERVICE_NOTIFICATION);
        return 0;
    } while (0);

    printf (PACKAGE_STRING "\n\n"
            "Usage: icecast [remove] | [install <path>]\n"
            "       icecast -c icecast.xml\n\n");
    return -1;
}
