#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Function to add rights to a file
void add_rights(char *path, mode_t right) {

	struct stat st;
	mode_t mode;

	stat(path, &st);
	mode = st.st_mode & 0777;
	mode |= right;
	chmod(path, mode);

	return; 
}

// Function to remove rights to a file
void remove_rights(char *path, mode_t right) {

	struct stat st;
	mode_t mode;

	stat(path, &st);
	mode = st.st_mode & 0777;
	mode &= ~(right);
	chmod(path, mode);

	return;
}

// Function to create multiple files and test access rights
void test_multiple_files(void) {

	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};

	
	// Create and write to the first 5 files
	for (i = 0; i < 5; i++) {
		file = fopen(filenames[i], "w+"); // Open file for reading and writing
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}
	
	 // Test access rights on every second file (1,3,5)
	for (i = 1; i < 5; i+=2) {
		remove_rights(filenames[i], S_IRUSR); // Remove read permission
		file = fopen(filenames[i], "r"); // Try to open file for reading (should fail)

		add_rights(filenames[i], S_IRUSR); // Restore read permission
		file = fopen(filenames[i], "r"); // Try to open file for reading (should succeed)
		fclose(file);
	}

	return;
}

// Function to test various file operations using a single test file
void test_random(void) {

	size_t bytes;
	FILE *file;
	char hello[] = "test\n";

	// Test read
	file = fopen("test", "r");

	// Test write
	file = fopen("test", "w");
	if (file) {
		fwrite(hello, sizeof(hello)-1, 1, file);
		fclose(file);
	}

	// Test read-write
	file = fopen("test", "w+");
	if (file) {
		fwrite(hello, sizeof(hello)-1, 1, file);
		fclose(file);
	}

	// Test read-append
	file = fopen("test", "a+");
	if (file) {
		fwrite(hello, sizeof(hello)-1, 1, file);
		fclose(file);
	}

	// Test write rights
	remove_rights("test", S_IWUSR); // Remove write permission
	file = fopen("test", "w+"); // Try to open file for writing (should fail)
	add_rights("test", S_IWUSR); // Restore write permission
	
	
	// Test read rights
	remove_rights("test", S_IRUSR); // Remove read permission
	file = fopen("test", "r"); // Try to open file for reading (should fail)
	add_rights("test", S_IRUSR); // Restore read permission

	return;
}

// Function to test multiple consecutive appends to a file
void test_consecutive_appends(void) {

	int i;
	size_t bytes;
	FILE *file;
	char hello[] = "hello, world!\n";

	// Open a file for appending
	file = fopen("helloworld", "a+");
	if (file) {
		// Append content multiple times
		for (i = 0; i < 10; i++) {
			bytes = fwrite(hello, sizeof(hello)-1, 1, file);
		}
		fclose(file);
	}

	return;
}

// Function to test malicious file writing attempts
void test_malicious(void) {

	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};
	char malicious[] = "malicious\n";

	// Append malicious content to all files
	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "a+");
		if (file) {
			bytes = fwrite(filenames[i], sizeof(malicious)-1, 1, file);
			fclose(file);
		}
	}

	for (i = 0; i < 10; i++) {
		remove_rights(filenames[i], S_IRUSR); // Remove read permission
		file = fopen(filenames[i], "r"); // Try to open file for reading (should fail)
		add_rights(filenames[i], S_IRUSR); // Restore read permission
	}
	
	return;
}

// Main function to run tests
int main() 
{

	test_multiple_files();

	test_random();

	test_consecutive_appends();

	test_malicious();
		
	return 0;

}
