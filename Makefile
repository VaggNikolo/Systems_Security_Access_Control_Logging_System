all: logger acmonitor test_aclog

logger: logger.c
	gcc -O2 -Wall -g -fPIC -shared -o logger.so logger.c -lcrypto -ldl

acmonitor: acmonitor.c 
	gcc -O2 -g acmonitor.c -o acmonitor

test_aclog: test_aclog.c 
	gcc -O2 -g test_aclog.c -o test_aclog

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	rm -rf file_* helloworld test
