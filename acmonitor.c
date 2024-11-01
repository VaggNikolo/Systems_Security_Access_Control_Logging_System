#define _XOPEN_SOURCE 600
#define LINE_SZ 256

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct log_entry {
	int uid;             /* user id (positive integer) */
	int access_type;     /* access type values [0-2] */
	int action_denied;   /* is action denied values [0-1] */
	time_t date;         /* file access date */
	time_t time;         /* file access time */
	char *file;          /* filename (string) */
	char *fingerprint;   /* file fingerprint */
};

struct log_entry ** unmarshal_users(FILE *log) {
	struct log_entry **logs;
	struct tm tm;
	char buffer[LINE_SZ], *fcnt, *ptr;
	int i = 0, curr_logs, max_logs = 256;

	if (!log) return NULL;

	logs = (struct log_entry **)malloc(sizeof(struct log_entry *) * max_logs);
	curr_logs = max_logs;

	// Read the log file line by line
	while ((fcnt = fgets(buffer, sizeof(buffer), log)) != NULL) {
		logs[i] = (struct log_entry *)malloc(sizeof(struct log_entry));

		// Parse the user ID (uid)
		ptr = strtok(buffer, "\t");
		logs[i]->uid = atoi(ptr);
		
		// Parse the file name
		ptr = strtok(NULL, "\t");
		logs[i]->file = (char *)malloc(strlen(ptr) + 1);
		strncpy(logs[i]->file, ptr, strlen(ptr) + 1);
		
		// Parse the date
		ptr = strtok(NULL, "\t");
		strptime(ptr, "%d/%m/%y", &tm);
		logs[i]->date = mktime(&tm);
		
		// Parse the Timestamp
		ptr = strtok(NULL, "\t");
		strptime(ptr, "%H/%M/%S", &tm);
		logs[i]->time = mktime(&tm);

		// Parse the Access Type
		ptr = strtok(NULL, "\t");
		logs[i]->access_type = atoi(ptr);

		// Parse the action_denied flag
		ptr = strtok(NULL, "\t");
		logs[i]->action_denied = atoi(ptr);
		
		// Parse the fingerprint
		ptr = strtok(NULL, "\n");
		logs[i]->fingerprint = (char *)malloc(strlen(ptr) + 1);
		strncpy(logs[i]->fingerprint, ptr, strlen(ptr) + 1);

		i++;
		
		// If the array is full, add space for 256 more entries
		if (i == curr_logs) {
			curr_logs += max_logs;
			logs = realloc(logs, sizeof(struct log_entry *) * curr_logs);
		}
	}

	logs[i] = NULL;
	return logs;
}

// This function returns 1 if a certain value is found in the array and 0 otherwise 
int searchInt(int *arr, int val, int length) {
	if (!arr) return 0;

	for (int i = 0; i < length; i++) {
		if (arr[i] == val) return 1;
	}
	return 0;
}


// This function returns 1 if a certain filename is found in the array and 0 otherwise
int searchFile(char **arr, char* val, int length) {
	if (!arr) return 0;

	for (int i = 0; i < length; i++) {
		if (strcmp(arr[i], val) == 0) return 1;
	}
	return 0;
}

// This function extracts unique user IDs from an array of log entries
int * uniqueUIDs(struct log_entry **logs, int *length) {
	int *uids = NULL;
	*length = 0;

	while (*logs != NULL) {
		// Check if the current UID is already in the list of unique UIDs
		if (!searchInt(uids, (*logs)->uid, *length)) {
			uids = realloc(uids, sizeof(int) * (++(*length)));
			uids[*length - 1] = (*logs)->uid;
		}
		logs++;
	}

	return uids;
}

// Function to find the first valid fingerprint associated with a given user ID and filename
char * findFirstFingerprint(struct log_entry **logs, int uid, char *filename) {
	while (*logs) {
		/* Check if the log entry is for the current user and filename 
		and if access was not denied */
		if ((*logs)->uid == uid && strcmp((*logs)->file, realpath(filename, NULL)) == 0 && !((*logs)->action_denied))
			return (*logs)->fingerprint;
		logs++;
	}
	return NULL;
}

// Help Message
void usage(void) {
	printf(	
		"\n"
		"usage:\n"
		"\t./monitor \n"
		"Options:\n"
		"-m, Prints malicious users\n"
		"-i <filename>, Prints table of users that modified "
		"the file <filename> and the number of modifications\n"
		"-h, Help message\n\n"
	);
	exit(1);
}

void list_malicious_users(FILE *log) {
	struct log_entry **logs = unmarshal_users(log), **p;
	int *uids, uids_l, files_l;
	char **files = NULL;

	// Get unique user IDs 
	uids = uniqueUIDs(logs, &uids_l);

	// Loop through each unique user ID
	for (int i = 0; i < uids_l; i++) {
		files_l = 0;
		files = (char **)calloc(7, sizeof(char *));  // Allocate memory for storing up to 7 file names
		p = logs;

		while (*p) {
			// Check if the log entry is for the current user and if access was denied
			if ((*p)->uid == uids[i] && (*p)->action_denied) {
				// Check if the file hasn't been recorded for this user yet
				if (!searchFile(files, (*p)->file, files_l)) {
					files[files_l] = (char *)malloc(strlen((*p)->file) + 1);
					strncpy(files[files_l], (*p)->file, strlen((*p)->file) + 1);
					files_l++;
				}
			}
			/* If the user has attempted to access 5 or more unauthorized files, 
			print the user ID and exit the loop */
			if (files_l >= 5) {
				printf("%d\n", uids[i]);
				break;
			}
			p++;
		}
	}
}

void list_file_modifications(FILE *log, char *file_to_scan) {
	struct log_entry **logs = unmarshal_users(log), **p;
	int *uids, length, mods;
	char *last_fngp;

	if (access(realpath(file_to_scan, NULL), F_OK)) {
		printf("./acmonitor: file \"%s\" does not exist\n", file_to_scan);
		usage();
	}
	
	// Get unique user IDs 
	uids = uniqueUIDs(logs, &length);
	
	// Loop through each unique user ID  
	for (int i = 0; i < length; i++) {
		mods = 0;
		last_fngp = findFirstFingerprint(logs, uids[i], file_to_scan); // Find the initial fingerprint for this user
		p = logs;

		while (*p) {
			// Check if the log entry is for the current user and if the file matches
			if ((*p)->uid == uids[i] && strcmp((*p)->file, realpath(file_to_scan, NULL)) == 0) {
				// Check if the first fingerprint has changed and if the access type is modification
				if (strcmp((*p)->fingerprint, last_fngp) != 0 && (*p)->access_type == 2) {
					mods++;
					last_fngp = (*p)->fingerprint; // Update to the current fingerprint
				}
			}
			p++;
		}
		
		// If the user modified the file, print the number of times
		if (mods > 0) printf("User %d modified the file %d times\n", uids[i], mods);
	}
}

int main(int argc, char *argv[]) {
	int ch;
	FILE *log;

	if (argc < 2) usage();
	
	// Open the log file for reading
	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./file_logging.log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {
		// Prints users that modified the file given and the number of modifications
		case 'i':
			list_file_modifications(log, optarg);
			break;
		// Prints malicious users
		case 'm':
			list_malicious_users(log);
			break;
		// Help Message
		default:
			usage();
		}
	}

	fclose(log);
	argc -= optind;
	argv += optind;
	return 0;
}
