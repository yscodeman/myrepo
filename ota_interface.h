#ifndef __OTA_INTERFACE_H__
#define __OTA_INTERFACE_H__

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <error.h>

#include <unistd.h>
#include <fcntl.h>
#include <cutils/log.h>

#include <pthread.h>

#include <curl/curl.h>
#include "chintMd5.h"

// #define LOG_TAG "otaMain"

#define MAXClIENT 10
#define DATELEN 256
#define LOGIN_DATA_LEN  4096
#define OTA_DOMAIN "/data/ota.domain"


typedef struct deviceInfo {
	char os[8];
	char otaUpgrade[8];
	char delayTime[8];
	char macAddr[32];
	char version[32];
	char otaMd5[64];
	char otaUrl[128];
	char interfaceString[256];
	pthread_mutex_t mute;

	size_t (*receive_login_data)(void *buffer, size_t size, size_t nmemb, FILE *file);
}deviceInfo;

int calculateFileMd5(const char *file_path, char *md5_str);
void generate_interface_string(deviceInfo* di);
int checkNet(void);
int connect_server(deviceInfo *devInfo);
int upload_devInfo(deviceInfo *devInfo);

int getMacAddr(char* mac);
int getTimeStamp(char* str);
int getDevInfoMd5(deviceInfo* info);


#endif
