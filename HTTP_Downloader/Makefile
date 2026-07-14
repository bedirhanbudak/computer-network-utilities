all: http_downloader

http_downloader: http_downloader.c
	gcc -Wall -o http_downloader http_downloader.c -lssl -lcrypto -lpthread

clean:
	rm -f part_* http_downloader