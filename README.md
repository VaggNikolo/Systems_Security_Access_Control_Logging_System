Access Control Logging and Monitoring Tool

This project implements an Access Control Logging and Monitoring Tool in C, designed to track file access events, log them, and monitor logs for unauthorized access. This tool leverages LD_PRELOAD to intercept file operations, allowing it to log details about file accesses and modifications in real-time.
Features

    Logging of File Operations:
        Logs each file access and modification with details including user ID, filename, date, time, access type, action denied status, and file fingerprint (SHA-256 hash).
    Malicious User Detection:
        Flags users as malicious if they attempt to access more than five files without permission.
    Modification Tracking:
        Tracks modifications to specific files, recording each time a user modifies a file based on the file's digital fingerprint.

How It Works

The tool consists of three main components:

    logger.so - A shared library that intercepts fopen and fwrite system calls to log file access events.
    acmonitor - A monitoring tool to analyze the generated logs and report unauthorized access patterns and file modifications.
    test_aclog - A test tool that generates file access and modification events to simulate various scenarios for testing.

Files

    logger.c: Source file for logger.so, intercepts fopen and fwrite to log access details.
    acmonitor.c: Source file for the monitoring tool, parses logs and identifies malicious access attempts.
    test_aclog.c: Generates test cases to simulate file accesses and modifications.
    Makefile: Compiles all components and automates testing.

Usage
1. Compilation

To compile the project, run:

bash

make

This will create:

    logger.so: The logging shared library.
    acmonitor: The log monitoring tool.
    test_aclog: The tool for generating test cases.

2. Running the Test Tool with Logging

To run the test_aclog tool with logger.so preloaded (to log the file operations), use:

bash

make run

This command will:

    Load logger.so using LD_PRELOAD.
    Execute test_aclog, which will simulate various file access scenarios.

3. Viewing the Log File

After running test_aclog, a log file file_logging.log is generated. It contains entries for each file access or modification event, with fields such as:

    UID (User ID)
    File name
    Date and time of access
    Access type (creation, open, or write)
    Action denied status
    File fingerprint (SHA-256 hash)

4. Using the Monitoring Tool

The acmonitor tool analyzes file_logging.log to detect suspicious behavior.
Commands:

    List Malicious Users:

    bash

./acmonitor -m

Lists users who attempted to access more than five files without permission.

Track File Modifications:

bash

./acmonitor -i <filename>

Lists users who modified <filename>, along with the number of modifications detected.

Help Message:

bash

    ./acmonitor -h

    Displays a usage guide for acmonitor.

5. Cleaning Up

To remove generated binaries and temporary files, run:

bash

make clean

Code Structure

    Memory Safety: All string operations use safe functions (strncpy, snprintf) to prevent buffer overflows.
    Dynamic Memory Allocation: The program dynamically manages memory for log entries and strings.
    SHA-256 Fingerprinting: Uses OpenSSL's EVP interface for generating SHA-256 hashes of file contents to uniquely identify file modifications.

Requirements

    OpenSSL: Ensure that OpenSSL libraries are installed on your system for SHA-256 hashing.
    Linux Environment: This tool uses Linux-specific headers and LD_PRELOAD, and may not be compatible with other operating systems.