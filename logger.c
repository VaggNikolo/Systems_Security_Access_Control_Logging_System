#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h> //install the required package
#include <openssl/err.h>
#include <fcntl.h>
#include <linux/limits.h>

int w_flag = 0;

// Function to compute the SHA-256 hash 
char* str2hash(const char *str, int length) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    char *out = calloc(65, sizeof(char));  // 64 chars for SHA-256 + 1 for null terminator

    // Initalize and compute hash
    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, str, length);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    // Convert hash bytes to hex string
    for (int i = 0; i < md_len; ++i)
        snprintf(&(out[i*2]), 3, "%02x", md_value[i]);
    
    return out;
}

FILE * fopen(const char *path, const char *mode)  {

	// Set access type (0 & 1)
	int access_type;
	if (mode[0] == (char)'r')
		access_type = 1;  // Read access
	else
		access_type = (!access(realpath(path, NULL), F_OK)) ? 1 : 0;

	int ret;
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	// Get current date & time
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);

	char date[36];
	sprintf(date, "%02d/%02d/%04u", tm -> tm_mday, tm -> tm_mon + 1, tm -> tm_year + 1900);
	char timestamp[14];
	sprintf(timestamp, "%02d:%02d:%02d", tm -> tm_hour, tm -> tm_min, tm -> tm_sec);

	// Check if access is denied 
	int isActionDenied = (access(realpath(path, NULL), R_OK | W_OK) == 0) ? 0 : 1;

	// Generate fingerprint if access was not denied 
	char * file_count, * fingerprint;
	if (isActionDenied)
		fingerprint = "0"; // No valid fingerprint
	else {
		if (mode[1] == '+' || mode[0] == 'r') {

			file_count = calloc(256, sizeof(char));
			fseek(original_fopen_ret, 0, SEEK_SET);
			
			// Read the data from the file
			while ((ret = fread(file_count, sizeof(char), 128, original_fopen_ret)) > 0)
				file_count[ret] = 0x00;
			// Generate the fingerprint
			fingerprint = str2hash(file_count, strlen(file_count));
		} else
			fingerprint = "0";  // If not read/write, no valid fingerprint
	}

	// Write log info to file 
	char *log = malloc(256);
	sprintf(log, "%d\t%s\t%s\t%s\t%d\t%d\t%s\n", getuid(), realpath(path, NULL), date, timestamp, access_type, isActionDenied, fingerprint);

	// writing all info to logging file using File Descriptors
	int fd = open("file_logging.log", O_RDWR | O_CREAT | O_APPEND, 0666);
	ssize_t bytes_written = write(fd, log, strlen(log));
	if (bytes_written < 0) {
    		perror("write failed");
	} else if (bytes_written < strlen(log)) {
    		fprintf(stderr, "Partial write occurred\n");
	}
	close(fd);
	
	// Set w_flag = 1 if the file is opened for writing
	if (mode[0] == 'w' && mode[1] != '+') 
		w_flag = 1;
	else 
		w_flag = 0;

	return original_fopen_ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)  {

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	int ret;
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	/* log in logging file */

	// Find the filename associated with the file stream
	int fdw = fileno(stream);
	char fd_path[PATH_MAX], *filename; 
	sprintf(fd_path, "/proc/self/fd/%d", fdw);
	filename = malloc(PATH_MAX);
	int n = readlink(fd_path, filename, PATH_MAX);
	if (n < 0)
		abort();
	filename[n] = '\0';

	// Check is access is denied 
	int isActionDenied = (access(filename, W_OK) == 0 ) ? 0 : 1;

	// Get current date & time
	time_t t = time(NULL);
	struct tm *tm = gmtime(&t);

	char date[36];
	sprintf(date, "%02d/%02d/%04d", tm -> tm_mday, tm -> tm_mon + 1, tm -> tm_year + 1900);
	char timestamp[14];
	sprintf(timestamp, "%02d:%02d:%02d", tm -> tm_hour, tm -> tm_min, tm -> tm_sec);

	// Set access type for write(2)
	int access_type = 2;

	// getting fingerprint
	char *fingerprint, *file_cnt;
		
	file_cnt = calloc(256, sizeof(char));
	
	// Reset the stream to the beginning for reading
	fseek(stream, 0, SEEK_SET);
	while ((ret = fread(file_cnt, sizeof(char), 128, stream)) > 0)
		file_cnt[ret] = 0x00;
	
	// If writing (w_flag = 1), concatenate new data to the existing ones
	if (w_flag)
		strcat(file_cnt, ptr);
	
	// Generate the fingerprint
	fingerprint = str2hash(file_cnt, strlen(file_cnt));

	char *log = malloc(256);
	sprintf(log, "%d\t%s\t%s\t%s\t%d\t%d\t%s\n", getuid(), filename, date, timestamp, access_type, isActionDenied, fingerprint);
	free(fingerprint);

	// Writing log info to file
	int fd = open("file_logging.log", O_RDWR | O_CREAT | O_APPEND, 0666);
	ssize_t bytes_written = write(fd, log, strlen(log));
	if (bytes_written < 0) {
    		perror("write failed");
	} else if (bytes_written < strlen(log)) {
    		fprintf(stderr, "Partial write occurred\n");
	}
	close(fd);

	return original_fwrite_ret;
}


