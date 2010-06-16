/*
  Copyright (c) 2009, Rochester Institute of Technology
  All rights reserved.

  Redistribution and use in source and binary forms are permitted provided
  that:

  (1) source distributions retain this entire copyright notice and comment,
      and
  (2) distributions including binaries display the following acknowledgement:

         "This product includes software developed by Rochester Institute of Technology."

      in the documentation or other materials provided with the distribution
      and in all advertising materials mentioning features or use of this
      software.

  The name of the University may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  This software contains code taken from the Eventlog to Syslog service
  developed by Curtis Smith of Purdue University.

  THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.

  This software was developed by:
     Sherwin Faria

     Rochester Institute of Technology
     Information and Technology Services
     1 Lomb Memorial Drive, Bldg 10
     Rochester, NY 14623 U.S.A.

  Send all comments, suggestions, or bug reports to:
     sherwin.faria@gmail.com

*/
#include "main.h"
#include <malloc.h>
#include <wchar.h>
#include <winevt.h>
#include "log.h"
#include "service.h"
#include "syslog.h"
#include "winevent.h"

#pragma comment(lib, "delayimp.lib") /* Prevents winevt from loading unless necessary */
#pragma comment(lib, "wevtapi.lib")	 /* New Windows Events logging library for Vista and beyond */

/* Number of eventlogs */
#define WIN_EVENTLOG_SZ		32

/* Eventlog descriptor */
struct WinEventlog {
	WCHAR name[WIN_EVENTLOG_NAME_SZ];	/* Name of eventlog		*/
	HANDLE handle;					/* Handle to eventlog	*/
	int recnum;					/* Next record number		*/
};

/* List of eventlogs */
static struct WinEventlog WinEventlogList[WIN_EVENTLOG_SZ];
int WinEventlogCount = 0;

/* Get specific values from an event */
PEVT_VARIANT GetEventInfo(EVT_HANDLE hEvent)
{
	EVT_HANDLE hContext = NULL;
	PEVT_VARIANT pRenderedEvents = NULL;
	LPWSTR ppValues[] = {L"Event/System/Provider/@Name",
						 L"Event/System/TimeCreated/@SystemTime",
						 L"Event/System/EventID",
						 L"Event/System/Level"};
    DWORD count = sizeof(ppValues)/sizeof(LPWSTR);
    DWORD dwReturned = 0;
	DWORD dwBufferSize = (256*sizeof(WCHAR)*RENDER_ITEMS);
	DWORD dwValuesCount = 0;
	DWORD status = 0;

	/* Create the context to use for EvtRender */
	hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
	if (NULL == hContext) {
		Log(LOG_ERROR|LOG_SYS, "EvtCreateRenderContext failed");
		goto cleanup;
	}

	pRenderedEvents = (PEVT_VARIANT)malloc(dwBufferSize);
	/* Use EvtRender to capture the Publisher name from the Event */
	/* Log Errors to the event log if things go wrong */
	if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedEvents, &dwReturned, &dwValuesCount)) {
		if (ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
			dwBufferSize = dwReturned;
			realloc(pRenderedEvents, dwBufferSize);
			if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedEvents, &dwReturned, &dwValuesCount)) {
				if (LogInteractive)
					Log(LOG_ERROR|LOG_SYS, "Error Rendering Event");
				status = ERR_FAIL;
				goto cleanup;
			}
		} else {
			status = ERR_FAIL;
			if (LogInteractive)
				Log(LOG_ERROR|LOG_SYS, "Error Rendering Event");
		}
	}

cleanup:
	if (hContext)
		EvtClose(hContext);

	if (status == ERR_FAIL)
		return NULL;
	else 
		return pRenderedEvents;
}

/* Gets the specified message string from the event. If the event does not
   contain the specified message, the function returns NULL. */
LPWSTR GetMessageString(EVT_HANDLE hMetadata, EVT_HANDLE hEvent)
{
	LPWSTR pBuffer = NULL;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD status = 0;

	/* Get the message string from the provider */
	EvtFormatMessage(hMetadata, hEvent, 0, 0, NULL, EvtFormatMessageEvent, dwBufferSize, pBuffer, &dwBufferUsed);
    
	/* Ensure the call succeeded */
	/* If buffer was not large enough realloc it */
	status = GetLastError();
	if (ERROR_INSUFFICIENT_BUFFER == status) {
		dwBufferSize = dwBufferUsed;

		pBuffer = (LPWSTR)malloc(dwBufferSize * sizeof(WCHAR));

		/* Once we have realloc'd the buffer try to grab the message string again */
		if (pBuffer)
			EvtFormatMessage(hMetadata, hEvent, 0, 0, NULL, EvtFormatMessageEvent, dwBufferSize, pBuffer, &dwBufferUsed);
		else {
			Log(LOG_ERROR|LOG_SYS, "EvtFormatMessage: malloc failed");
			return NULL;
		}
	}
	else if (ERROR_EVT_MESSAGE_NOT_FOUND == status || ERROR_EVT_MESSAGE_ID_NOT_FOUND == status) {
		if (pBuffer)
			free(pBuffer);
		return NULL;
	}
	else {
		Log(LOG_ERROR|LOG_SYS, "EvtFormatMessage failed: could not get message string");
		if (pBuffer)
			free(pBuffer);
		return NULL;
	}

	/* Success */
	return pBuffer;
}

/* Create new eventlog descriptor */
int WinEventlogCreate(char * name)
{
	/* Check count */
	if (WinEventlogCount == WIN_EVENTLOG_SZ) {
		Log(LOG_ERROR, "Too many eventlogs: %d", WIN_EVENTLOG_SZ);
		return 1;
	}

	/* Store new name */
	_snwprintf_s(WinEventlogList[WinEventlogCount].name, COUNT_OF(WinEventlogList[WinEventlogCount].name), _TRUNCATE, L"%S", name);

	/* Increment count */
	WinEventlogCount++;

	/* Success */
	return 0;
}

/* Close eventlog */
static void WinEventlogClose(int log)
{
	/* Close log */
	CloseEventLog(WinEventlogList[log].handle);
	WinEventlogList[log].handle = NULL;
}

/* Close eventlogs */
void WinEventlogsClose()
{
	int i;

	/* Loop until list depleated */
	for (i = 0; i < WinEventlogCount; i++)
		if (WinEventlogList[i].handle)
			WinEventlogClose(i);

	/* Reset count */
	WinEventlogCount = 0;
}

/* Open event log */
static int WinEventlogOpen(int log)
{
	DWORD count;
	DWORD oldest;

	/* Reset all indicators */
	WinEventlogList[log].recnum = 1;

	/* Open log */
	WinEventlogList[log].handle = OpenEventLogW(NULL, WinEventlogList[log].name);
	if (WinEventlogList[log].handle == NULL) {
		Log(LOG_ERROR|LOG_SYS, "Cannot open event log: \"%S\"", WinEventlogList[log].name);
		return 1;
	}

	/* Get number of records to skip */
	if (GetNumberOfEventLogRecords(WinEventlogList[log].handle, &count) == 0) {
		Log(LOG_ERROR|LOG_SYS, "Cannot get record count for event log: \"%S\"", WinEventlogList[log].name);
		return 1;
	}

	/* Get oldest record number */
	if (GetOldestEventLogRecord(WinEventlogList[log].handle, &oldest) == 0 && count != 0) {
		Log(LOG_ERROR|LOG_SYS, "Cannot get oldest record number for event log: \"%S\"", WinEventlogList[log].name);
		return 1;
	}

	/* Store record of next event */
	WinEventlogList[log].recnum = oldest + count;
	if (WinEventlogList[log].recnum == 0)
		WinEventlogList[log].recnum = 1; /* ?? */

	/* Success */
	return 0;
}

/* Open WinEvent logs */
int WinEventlogsOpen()
{
	int i;

	/* Open the log files */
	for (i = 0; i < WinEventlogCount; i++)
		if (WinEventlogOpen(i))
			break;

	/* Check for errors */
	if (i != WinEventlogCount) {
		EventlogsClose();
		return 1;
	} else
		EventlogsClose(); /* Handle not necessary for new API */

	/* Success */
	return 0;
}

/* Run query for Events */
EVT_HANDLE WinEventQuery(LPWSTR pwsQuery)
{
	EVT_HANDLE hResult;
	DWORD status;

	/* Query for an event. */
	hResult = EvtQuery(NULL, NULL, pwsQuery, EvtQueryChannelPath);
	if (NULL == hResult) {
		status = GetLastError();

		if (status == ERROR_EVT_CHANNEL_NOT_FOUND)
			Log(LOG_ERROR, "EvtQuery: Channel \"%S\" was not found",pwsQuery);
		else if (status == RPC_S_UNKNOWN_IF)
			Log(LOG_ERROR|LOG_SYS, "Error: Eventlog Service appears to be shutting down");
		else
			Log(LOG_ERROR|LOG_SYS, "EvtQuery failed");
	}

	return hResult;
}

/* Get the next eventlog message */
WCHAR * WinEventlogNext(EventList ignore_list[MAX_IGNORED_EVENTS], int log)
{
    EVT_HANDLE hProviderMetadata = NULL;
    EVT_HANDLE hResult = NULL;
    EVT_HANDLE hEvent = NULL;
	PEVT_VARIANT eventInfo = NULL;
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferNeeded = 0;
	DWORD dwBufferSize = 512;
    LPWSTR pwsMessage = NULL;
    LPWSTR pwszPublisherName = NULL;
	LPWSTR pwsQuery = NULL;
	ULONGLONG eventTime;
	int event_id = 0;
	int level;

	BOOL reopen = FALSE;
	BOOL bFilter = FALSE;

	char mbsource[SOURCE_SZ];
	WCHAR source[SOURCE_SZ];
	WCHAR hostname[HOSTNAME_SZ];
	WCHAR * formatted_string = NULL;
	WCHAR * tstamp = NULL;
	WCHAR * index = NULL;
	WCHAR defmsg[ERRMSG_SZ];
	WCHAR tstamped_message[SYSLOG_SZ];

	pwsQuery = (LPWSTR)malloc(QUERY_SZ);

	/* Create the query to pull the specified event */
	swprintf_s(pwsQuery, QUERY_SZ/sizeof(WCHAR), L"<QueryList><Query Path='%s'><Select>*[System[EventRecordID >= %i]]</Select></Query></QueryList>", WinEventlogList[log].name, WinEventlogList[log].recnum);

	do {
		hResult = WinEventQuery(pwsQuery);
		if (hResult == NULL) {
			/* Check error */
			status = GetLastError();
			switch (status) {
				/* Eventlog corrupted (?)... Reopen */
				case ERROR_EVENTLOG_FILE_CORRUPT:
					Log(LOG_INFO, "Eventlog was corrupted: \"%S\"", WinEventlogList[log].name);
					reopen = TRUE;
					break;

				/* Eventlog files are clearing... Reopen */
				case ERROR_EVENTLOG_FILE_CHANGED:
					Log(LOG_INFO, "Eventlog was cleared: \"%S\"", WinEventlogList[log].name);
					reopen = TRUE;
					break;

				/* Record not available (yet) */
				case ERROR_INVALID_PARAMETER:
					if (LogInteractive)
						Log(LOG_INFO|LOG_SYS, "Invalid Parameter in Log: \"%S\"", WinEventlogList[log].name);
					continue;

				/* Normal end of eventlog messages */
				case ERROR_HANDLE_EOF:
					if (LogInteractive)
						Log(LOG_INFO, "End of Eventlog: \"%S\"", WinEventlogList[log].name);
					return NULL;

				/* Eventlog probably closing down */
				case RPC_S_UNKNOWN_IF:
					if (LogInteractive)
						Log(LOG_INFO, "Eventlog appears to be shutting down: \"%S\"", WinEventlogList[log].name);
					return NULL;

				/* Unknown condition */
				default:
					Log(LOG_ERROR|LOG_SYS, "Eventlog \"%S\" returned error", WinEventlogList[log].name);
					ServiceIsRunning = FALSE;
					return NULL;
			}
		}

		/* Process reopen */
		if (reopen) {
			Log(LOG_INFO, "Reopening Log: %S", WinEventlogList[log].name);
			if (WinEventlogOpen(log) != 0) {
				Log(LOG_INFO, "Error reopening Log: %S", WinEventlogList[log].name);
				ServiceIsRunning = FALSE;
				return NULL;
			}
			WinEventlogClose(log);
			if (hResult)
				EvtClose(hResult);
			reopen = FALSE;
		}
	}while (reopen);

	reopen = TRUE;
	do {
		/* Loop through the result set. */
		if (!EvtNext(hResult, 1, &hEvent, TIMEOUT, 0, &dwBufferNeeded)) {
			/* If the last call timed out try it again one more time */
			if ((status = GetLastError()) == ERROR_TIMEOUT)
				EvtNext(hResult, 1, &hEvent, TIMEOUT, 0, &dwBufferNeeded);

			if ((status = GetLastError()) == ERROR_NO_MORE_ITEMS) {
				reopen = FALSE;
				break;
			} else if (status != ERROR_SUCCESS) {
				if (status != ERROR_TIMEOUT || LogInteractive)
					Log(LOG_ERROR|LOG_SYS, "EvtNext: Error getting event from Log: '%S' with RecordID: %i", WinEventlogList[log].name, WinEventlogList[log].recnum);
				continue;
			}
		}
		/* Increase record number */
		WinEventlogList[log].recnum++;

		/* Get and store the publishers new Windows Events name */
		eventInfo = GetEventInfo(hEvent);
		if (eventInfo) {
			pwszPublisherName = (LPWSTR)eventInfo[0].StringVal;
		}
		else {
			continue;
		}
		eventTime = eventInfo[1].FileTimeVal;
		event_id = eventInfo[2].UInt16Val;

		/* Check for the "Microsoft-Windows-" prefix in the publisher name */
		/* and remove it if found. Saves 18 characters in the message */
		if(wcsncmp(pwszPublisherName, L"Microsoft-Windows-", 18) == 0)
			wcsncpy_s(source, COUNT_OF(source), pwszPublisherName+18, _TRUNCATE);
		else
			wcsncpy_s(source, COUNT_OF(source), pwszPublisherName, _TRUNCATE);

		/* Check Event Info Against Ignore List */
		WideCharToMultiByte(CP_UTF8, 0, source, -1, mbsource, SOURCE_SZ, NULL, NULL);
		if (IgnoreSyslogEvent(ignore_list, mbsource, event_id)) {
			if (LogInteractive)
				printf("IGNORING_EVENT: SOURCE=%s & ID=%i\n", mbsource, event_id);
			bFilter = TRUE;
		} else {
			bFilter = FALSE;
		}

		/* Format Event Timestamp */
		if ((tstamp = WinEvtTimeToString(eventTime)) == NULL)
			tstamp = L"TIME_ERROR";

		/* Add hostname for RFC compliance (RFC 3164) */
		if (ExpandEnvironmentStringsW(L"%COMPUTERNAME%", hostname, COUNT_OF(hostname)) == 0) {
			wcscpy_s(hostname, COUNT_OF(hostname), L"HOSTNAME_ERR");
			Log(LOG_ERROR|LOG_SYS, "Cannot expand %COMPUTERNAME%");
		}

		/* replace every space in source by underscores */
		index = source;
		while( *index ) {
			if( *index == L' ' ) {
				*index = L'_';
			}
			index++;
		}

		/* Add Timestamp and hostname then format source & event ID for consistency with Event Viewer */
		_snwprintf_s(tstamped_message, COUNT_OF(tstamped_message), _TRUNCATE, L"%s %s %s: %i: ", tstamp, hostname, source, event_id);

		/* Get the handle to the provider's metadata that contains the message strings. */
		hProviderMetadata = EvtOpenPublisherMetadata(NULL, pwszPublisherName, NULL, 0, 0);
		if (NULL == hProviderMetadata) {
			if (LogInteractive)
				Log(LOG_ERROR|LOG_SYS, "OpenPublisherMetadata failed for Publisher: \"%S\"", source);
			continue;
		}

		/* Get the message string from the event */
		pwsMessage = GetMessageString(hProviderMetadata, hEvent);
		if (pwsMessage == NULL) {
			Log(LOG_ERROR|LOG_SYS, "Error getting message string for RecordID: %i in Log: %S DETAILS: Publisher: %S EventID: %i", WinEventlogList[log].recnum, WinEventlogList[log].name, source, event_id);
			continue;
		}

		/* Get string and strip whitespace */
		formatted_string = CollapseExpandMessageW(pwsMessage);

		/* Create a default message if resources or formatting didn't work */
		if (formatted_string == NULL) {
			_snwprintf_s(defmsg, COUNT_OF(defmsg), _TRUNCATE,
				L"(Facility: %u, Status: %s)",
				HRESULT_FACILITY(event_id),
				FAILED(event_id) ? L"Failure" : L"Success"
			);
			formatted_string = defmsg;
		}

		/* Combine the message strings */
		wcsncat_s(tstamped_message, COUNT_OF(tstamped_message), formatted_string, _TRUNCATE);

		/* Select syslog level */
		switch ((int)eventInfo[3].ByteVal) {

		case WINEVENT_CRITICAL_LEVEL:
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_CRIT);
			break;		
		case WINEVENT_ERROR_LEVEL:
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_ERR);
			break;
		case WINEVENT_WARNING_LEVEL:
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_WARNING);
			break;
		case WINEVENT_INFORMATION_LEVEL:
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_NOTICE);
			break;
		case WINEVENT_AUDIT_LEVEL:
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_NOTICE);
			break;
		case WINEVENT_VERBOSE_LEVEL:
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_DEBUG);
			break;

		/* Everything else */
		default:
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_NOTICE);
			break;
		}

		/* Send the event to the Syslog Server */
		if (!bFilter)
			if (SyslogSendW(tstamped_message, level))
				status = ERR_FAIL;

		/* Cleanup memory and open handles */
		if(pwsMessage)
			free(pwsMessage);
		if(eventInfo)
			free(eventInfo);

		if (hProviderMetadata)
			EvtClose(hProviderMetadata);
		if (hEvent)
			EvtClose(hEvent);

		if (status == ERR_FAIL)
			break;

	}while (reopen);
	
	if(pwsQuery)
		free(pwsQuery);

    if (hResult)
        EvtClose(hResult);

	if (status == ERR_FAIL) {
		Log(LOG_INFO, "Status = ERR_FAIL - Log: \"%S\" & RecNum: %i", WinEventlogList[log].name, WinEventlogList[log].recnum);
		return NULL; /* Return Failure */
	}
	else
		return L"1"; /* Return Success*/
}

/* Format Timestamp from EventLog */
WCHAR * WinEvtTimeToString(ULONGLONG ulongTime)
{
	SYSTEMTIME sysTime;
	FILETIME fTime, lfTime;
	ULARGE_INTEGER ulargeTime;
	struct tm tm_struct;
	WCHAR result[17] = L"";
	static WCHAR * formatted_result = L"Mmm dd hh:mm:ss";

	memset(&tm_struct, 0, sizeof(tm_struct));

	/* Convert from ULONGLONG to usable FILETIME value */
	ulargeTime.QuadPart = ulongTime;
	
	fTime.dwLowDateTime = ulargeTime.LowPart;
	fTime.dwHighDateTime = ulargeTime.HighPart;

	/* Adjust time value to reflect current timezone */
	/* then convert to a SYSTEMTIME */
	if (FileTimeToLocalFileTime(&fTime, &lfTime) == 0) {
		Log(LOG_ERROR|LOG_SYS,"Error formatting event time to local time");
		return NULL;
	}
	if (FileTimeToSystemTime(&lfTime, &sysTime) == 0) {
		Log(LOG_ERROR|LOG_SYS,"Error formatting event time to system time");
		return NULL;
	}

	/* Convert SYSTEMTIME to tm */
	tm_struct.tm_year = sysTime.wYear - 1900;
	tm_struct.tm_mon  = sysTime.wMonth - 1;
	tm_struct.tm_mday = sysTime.wDay;
	tm_struct.tm_hour = sysTime.wHour;
	tm_struct.tm_wday = sysTime.wDayOfWeek;
	tm_struct.tm_min  = sysTime.wMinute;
	tm_struct.tm_sec  = sysTime.wSecond;
	
	/* Format timestamp string */
	wcsftime(result, COUNT_OF(result), L"%b %d %H:%M:%S", &tm_struct);
	if (result[4] == L'0') /* Replace leading zero with a space for */
		result[4] = L' ';  /* single digit days so we comply with the RFC */

	wcsncpy_s(formatted_result, COUNT_OF(L"Mmm dd hh:mm:ss"), result, _TRUNCATE);
	
	return formatted_result;
}