#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <cutils/properties.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <poll.h>
#include <pthread.h>
#include <stdio.h>


#include "cJSON.h"
#include "ota_interface.h"
#include "chint_downloader.h"

//#include "chromecast/internal/sdk/cast_control/public/cast_control.h"


#define EXECUTE_DEALY                    1800 //18000
#define CHECK_NETWORK_DEALY              20 //60
#define DELAY_30_MINS                    3
#define WAIT_DEVINFO_TIME                3


#define NORMAL_UPDATE_START_TIME         1
#define NORMAL_UPDATE_STOP_TIME          6

#define GET_RESPOND_EVENT                0
#define GET_VERSION_EVENT                1
#define GET_DOWNLOAD_EVENT               2
#define GET_DOWNLOAD_PROGRESSING_EVENT   3
#define GET_CHECK_PRE_VERSION_EVENT      4

#define GET_PRE_CHECK_VERSION            3
#define GET_NONE_PRE_CHECK_VERSION       4

#define GET_DOWNLOAD_ERROR               1
#define GET_DOWNLOAD_ABORT               2
#define GET_FORCE_DOWNLOAD_RESPOND       4

#define UPGRADE_STATE_INIT               0
#define UPGRADE_STATE_PARSING            1
#define UPGRADE_STATE_DOWNLOADING        2
#define UPGRADE_STATE_FINISHED           3
#define RECEIVE_DATA_LEN                 1024
#define MD5_LEN                          32


#define DOWNLOAD_DONE                    'D'

static int upgrade_status = UPGRADE_STATE_INIT;
static int receive_devinfo_shift = 0;

static pthread_t ota_tid = 0;
static int clientFd = 0;
static int TdcServer_fd = -1;
static int otaClient_fd = -1;
static int setupSocketSuccess = 0;
char response_connect_server_json[RECEIVE_DATA_LEN] = {0};

deviceInfo globalDeviceInfo;
static char *__save_file_path = (char*)"/cache/ota.zip";

static bool g_dl_finished = false;
static bool g_dl_aborted  = false;
static int g_dl_prog = -1;

static em_downloader_event g_dl_event = em_downloader_event_progress;

void download_callback(em_downloader_event e, void *param)
{
    switch (e) {
		case em_downloader_event_error:
        case em_downloader_event_abort:
        case em_downloader_event_finish:
            ALOGD("%s %d e=%d\n", __func__, __LINE__, e);
            g_dl_finished = true;
            g_dl_event = e;
            break;
        case em_downloader_event_progress: { //progress is (double*)param
            double cur_prog = *(double*)param + 1e-6;
            if (g_dl_prog != (int)cur_prog) {
                g_dl_prog = (int)cur_prog;
                ALOGD(" Downloading percent: %d", g_dl_prog);
            }
			break;
        }
		default:
			ALOGD("Unknow callback envent");
            break;
    }
}

static int enter_recovery_update(void) {
	int ret = -1;
	if ((access("/cache/ota.zip",F_OK)) != -1) {
		ret = system("echo --update_package=/cache/ota.zip > /cache/recovery/command");
		ret = system("reboot recovery");
	}
	return ret;
}


void delay_30min() {
	int day,hour,minu;
	time_t now;
	struct tm *tm_now;
	int delay_min = 30;

	time(&now) ;
	tm_now = localtime(&now) ;
	printf("Local Time Day:%d Hour:%d Min:%d\n",
						tm_now->tm_mday,
						tm_now->tm_hour,
						tm_now->tm_min);
	minu = (tm_now->tm_min+delay_min)%60;
	hour = (tm_now->tm_hour + (tm_now->tm_min+delay_min)/60)%24;
	day = tm_now->tm_mday + (tm_now->tm_hour + (tm_now->tm_min+delay_min)/60)/24 ;
	while (1) {
		time(&now);
		tm_now = localtime(&now);
		if (day == tm_now->tm_mday && hour == tm_now->tm_hour && minu == tm_now->tm_min) {
			break;
		}
		sleep(60);
	}
}


static void get_version(char *ver) {
	char* ret1;
	char* ret2;

	char ch = '.';
	char buf[PROPERTY_VALUE_MAX] = {'\0'};

	property_get("ro.build.version.incremental", buf, "19.49.10.1.1");

	ret1 = strchr(buf, ch) + 1;     //ret1 = 49.10.1.1
	ret2 = strchr(ret1, ch) + 1;    //ret2 = 10.1.1
	strcat(ver, ret2);              //ver = 10.1.1
}

void chint_set_upgradeStatus(int stat) {
    upgrade_status = stat;
}

int chint_get_upgradeStatus(void) {
    return upgrade_status;
}

void convert_to_cap(char* lowercase,char* dst)
{
    int i = 0;

    while (lowercase[i] != '\0') {
        if (lowercase[i] >= 'a' && lowercase[i] <= 'z') {
            dst[i] = lowercase[i] - 'a' + 'A';
        }else {
            dst[i] = lowercase[i];
        }
        i++;
    }
}

size_t receive_login_data(void *buffer, size_t size, size_t nmemb, FILE *file) {
    char* ptr = &response_connect_server_json[0];

    ALOGI("receive_devinfo_shift: %d,size: %lu\n",receive_devinfo_shift,size*nmemb);

    memcpy(ptr+receive_devinfo_shift, (char *)buffer, size*nmemb);

    if (size*nmemb+receive_devinfo_shift < RECEIVE_DATA_LEN) {
        receive_devinfo_shift = size*nmemb;
    }else {
        receive_devinfo_shift = 0;
    }

    return size*nmemb;
}


static int parseJson(char* input_file) {
	pthread_mutex_lock(&globalDeviceInfo.mute);
    fd_set readfds;
    int error_code = 0;

	char login_data_Buf[LOGIN_DATA_LEN] = {0};
	cJSON *root = NULL;
	cJSON *pEntity = NULL;
	cJSON *pErrCode = NULL;
	cJSON *pValue = NULL;
	cJSON *pUrl = NULL;
	cJSON *pMd5 = NULL;

	memset(login_data_Buf, 0, LOGIN_DATA_LEN);
	memcpy(login_data_Buf,input_file,sizeof(login_data_Buf));

	while (1) {
		root = cJSON_Parse(login_data_Buf);
		if (root == NULL) {
			ALOGE("[upgrade]%s, line:%d,cloudn't find http body! \n", __func__, __LINE__);
			goto err;
		}

		pEntity = cJSON_GetObjectItem(root, "entity");
		if (pEntity) {
			pErrCode = cJSON_GetObjectItem(root, "statusCode");
			if (pErrCode) {
				error_code = pErrCode->valueint;
            	ALOGD(" code: %d\n ", error_code);
			} else {
            	ALOGE("[upgrade]%s, line:%d,couldn't find statusCode node\n", __func__, __LINE__);
				goto err;
			}
			
        	if (error_code == 0) {
				ALOGD("Success connect to server");
			} else {
				ALOGE("Get error code: %d",error_code);
				goto err;
			}

			pValue = cJSON_GetObjectItem(root, "value");
			if (pValue) {
				pMd5 = cJSON_GetObjectItem(pValue, "md5");
	            if (pMd5) {
	                memcpy(&globalDeviceInfo.otaMd5, pMd5->valuestring, strlen(pMd5->valuestring));
	            } else {
	                ALOGE("[upgrade]%s, line:%d,couldn't find md5 node\n", __func__, __LINE__);
	                goto err;
	            }

				pUrl = cJSON_GetObjectItem(pValue, "otaurl");
	            if (pUrl) {
	                memcpy(&globalDeviceInfo.otaUrl, pUrl->valuestring, strlen(pUrl->valuestring));
	            } else {
	                ALOGE("[upgrade]%s, line:%d,couldn't find otaurl node\n", __func__, __LINE__);
	                goto err;
	            }
				break;
			} else {
            	ALOGE("[upgrade]%s, line:%d,couldn't find value node\n", __func__, __LINE__);
				goto err;
			}
        } else {
            ALOGE("[upgrade]%s, line:%d,couldn't find entity node\n", __func__, __LINE__);
            goto err;
        }
    }
    if (root != NULL) {
        cJSON_Delete(root);
        root = NULL;
    }
	pthread_mutex_unlock(&globalDeviceInfo.mute);
    chint_set_upgradeStatus(UPGRADE_STATE_DOWNLOADING);
    return 0;
err:
    if (root != NULL) {
        cJSON_Delete(root);
        root = NULL;
    }
	pthread_mutex_unlock(&globalDeviceInfo.mute);
    return -1;
	
}

static void sendDownLoadDoneMessage(void) {
	int sendByte = 0;
	char TdcSendBuf[64] = {0};

	strcpy(TdcSendBuf,"{download:1}");
	if (otaClient_fd > 0) {
		sendByte = send(otaClient_fd, TdcSendBuf, strlen(TdcSendBuf), 0);
		if (sendByte <= 0) {
			ALOGE("Send download message failed %s . Retry",strerror(errno));
			sendByte = send(otaClient_fd, TdcSendBuf, strlen(TdcSendBuf), 0);
			if ( sendByte <= 0) {
				ALOGE("Send download message failed %s . Return",strerror(errno));
				return;
			}
		}
	}
	
}

static void sendMessage(char cmd) {
	switch (cmd) {
		case DOWNLOAD_DONE:
			sendDownLoadDoneMessage();
			break;
		default:
			ALOGE("Unknow cmd");
			break;
	}
}

void *socket_ota_thread(void *arg) {
	clientFd = *((int*)arg);
	int iRecvLen = 0;
	char TdcRecvBuf[256] = {0};
	struct pollfd fds[1];
	
	ALOGD ("Thread sockfd = %d",clientFd);
	
	fds[0].fd = clientFd;
	fds[0].events = POLLIN;

	while(1) {
		memset(TdcRecvBuf, 0, 256);
		ALOGD("receiveing .....");
 
		iRecvLen = recv(clientFd, TdcRecvBuf, 256, 0);
		ALOGD("Message from client (%d)) :%s\n", iRecvLen, TdcRecvBuf);

		if (iRecvLen > 0) {
			if (!strcmp(TdcRecvBuf,"upgrade")) {
				enter_recovery_update();
			} else {
				parseJson(TdcRecvBuf);
			}
		}
	}

	close(clientFd);
	return NULL;
}

static int setupOtaSocket(void) {
	int iRet = -1;
	int iRecvLen = 0;
	int iCltAddrLen = 0;
	char TdcRecvBuf[DATELEN] = {0}; 
	char TdcSendBuf[DATELEN] = {0}; 
	struct sockaddr_un CltAddr;
	struct sockaddr_un SrvAddr;

	unlink(OTA_DOMAIN);
	
	TdcServer_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	ALOGD(" === TdcServer_fd = %d\n", TdcServer_fd);
	if (TdcServer_fd < 0) {
		ALOGD(" Cannot create communication socket");
		return -1;
	}

	//set server addr_param
	SrvAddr.sun_family = AF_UNIX;//IPV4
	strncpy(SrvAddr.sun_path, OTA_DOMAIN, sizeof(SrvAddr.sun_path) - 1);

	//bind sockfd & addr
	iRet = bind(TdcServer_fd, (struct sockaddr*)&SrvAddr, sizeof(SrvAddr));
	if (-1 == iRet) {
		ALOGE("cannot bind server socket");
		close(TdcServer_fd);
		unlink(OTA_DOMAIN);
		return -1;
	}

	//listen sockfd 
	iRet = listen(TdcServer_fd, MAXClIENT);
	if (-1 == iRet) {
		ALOGE("cannot listen the client connect request");
		close(TdcServer_fd);
		unlink(OTA_DOMAIN);
		return -1;
	}

	//have connect request use accept
	iCltAddrLen = sizeof(CltAddr);
	system("chmod 666 /data/ota.domain");
	
	otaClient_fd = accept(TdcServer_fd, (struct sockaddr*)&CltAddr, (socklen_t*)&iCltAddrLen);
	if(otaClient_fd < 0) {
		ALOGE("cannot accept client connect request");
		close(TdcServer_fd);
		unlink(OTA_DOMAIN);
		return -1;
	}
	
	iRet = pthread_create(&ota_tid, NULL, socket_ota_thread, &otaClient_fd);
	if (iRet != 0) {
		ALOGE("can't create thread.err:%s\r\n", strerror(iRet));
		return -1;
	}
	pthread_detach(ota_tid);

	return 0;
}

/* 1. setup socket for app communication */
/*
*	1.1 send device info to app
*	1.2 receive app wether download
*	  1.2.1 parse json to determime wether need download
*/

/* 2. http get */
/*
*	2.1 generate device info to communicate with server
*	2.2 parse cjson from server
*/

/* 3. download */
/*
*	1.3 download complete and RCR then send ok message to app
*	1.4 receive upgrade message from app
*/

int main(int argc,char* argv[]) {
	int ret = -1;
	char* url = NULL;
	FILE* fp = NULL;
	char cap_md5[64] = {0};
	char system_ota_file_md5[64] = {0};

	if ((access("/cache/ota.zip",F_OK)) != -1) {
		system("rm /cache/ota.zip");
	}
	if ((access("/cache/update_flag",F_OK)) != -1) {
		system("rm /cache/update_flag");
	}

	pthread_mutex_init(&globalDeviceInfo.mute, NULL);
	globalDeviceInfo.receive_login_data = receive_login_data;

	if (getMacAddr(globalDeviceInfo.macAddr) != 0) {
		ALOGE("Get mac addr failed: %s, retry ",strerror(errno));
		sleep(5);
		if (getMacAddr(globalDeviceInfo.macAddr) != 0) {
			ALOGE("Get mac addr failed: %s,exit the OTA service ",strerror(errno));
			pthread_mutex_destroy(&globalDeviceInfo.mute);
			return -1;
		}
	}

	get_version(globalDeviceInfo.version);

	generate_interface_string(&globalDeviceInfo);

	while (1) {
        if (0 == checkNet()) {
            ALOGE(" network not connect ");
            sleep(5);
            continue;
        }
        ALOGI(" network  connected ");
		
		if (setupSocketSuccess == 0) {
			if (setupOtaSocket() != 0) {
				ALOGE("Setup socket failed: %s, retry ",strerror(errno));
				if (setupOtaSocket() != 0) {
					ALOGE("Setup socket failed again: %s",strerror(errno));
				} else {
					setupSocketSuccess = 1;
				}
			} else {
				setupSocketSuccess = 1;
			}
		}

		ret = connect_server(&globalDeviceInfo);
		if (ret != 0) {
			ALOGE("Connect_server failed!  %s",strerror(errno));
			sleep(DELAY_30_MINS);
			continue;
		} else {
			sleep(WAIT_DEVINFO_TIME);
			ALOGI("After 3s get response_connect_server_json:\n%s",response_connect_server_json);
			if (parseJson(response_connect_server_json) != 0) {
				ALOGE("Get download information failed, need retry! \n");
				receive_devinfo_shift = 0;
				memset(response_connect_server_json,0,sizeof(response_connect_server_json));
				sleep(DELAY_30_MINS);
				continue;
			}
			memset(response_connect_server_json,0,sizeof(response_connect_server_json));
			receive_devinfo_shift = 0;
		}

		if (chint_get_upgradeStatus() != UPGRADE_STATE_DOWNLOADING) {
			sleep(1);
			continue;
		}

		url = &globalDeviceInfo.otaUrl[0];
		if (strlen(url) == 0) {
			ALOGE("[upgrade]%s: devUrl is NULL\n", __func__);
			sleep(DELAY_30_MINS);
			continue;
		}

		g_dl_finished = false;
		g_dl_aborted = false;
		g_dl_event = em_downloader_event_progress;
		g_dl_prog = -1;

		st_aml_dlinfo *pdlinfo = aml_downloader_init();
		aml_downloader_setcallback(pdlinfo, download_callback);
		aml_downloader_seturl(pdlinfo, url, NULL);
		aml_downloader_setsavepath(pdlinfo, __save_file_path);
		aml_downloader_start(pdlinfo);

		while (!g_dl_finished) {
			sleep(1);
		}
		ALOGD("%s %d g_dl_finished:%d dlevent:%d\n", __func__, __LINE__,
			g_dl_finished, g_dl_event);

		aml_downloader_uninit(pdlinfo);

		if (g_dl_event != em_downloader_event_finish) {
			ALOGE("[upgrade]Download error or abort\n");
			remove(__save_file_path);
			sleep(DELAY_30_MINS);
			continue;
		}

		memset(system_ota_file_md5, 0, sizeof(system_ota_file_md5));
		if (calculateFileMd5(__save_file_path,system_ota_file_md5) < 0) {
			ALOGE("Caltulate %s failed.",__save_file_path);
			remove(__save_file_path);
			sleep(DELAY_30_MINS);
			continue;
		}

		convert_to_cap(system_ota_file_md5,cap_md5);
		ALOGD("MD5 server:%s\n",globalDeviceInfo.otaMd5);
		ALOGD("MD5 file  :%s\ncap_md5: %s\n", system_ota_file_md5,cap_md5);

		if ( 0 == strncmp(system_ota_file_md5, globalDeviceInfo.otaMd5, MD5_LEN) ||
			0 == strncmp(cap_md5,globalDeviceInfo.otaMd5, MD5_LEN)) {
			ALOGI("MD5 same, upgrading!\n");
			sendMessage(DOWNLOAD_DONE);
		} else {
			ALOGE("MD5 different, return!\n");
			remove(__save_file_path);
			continue;
		}
		//break;
	}
	pthread_mutex_destroy(&globalDeviceInfo.mute);
	return 0;
}

