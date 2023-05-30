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
#define DELAY_30_MINS                    1800
#define DELAY_6_HOURS                    3600*6
#define DELAY_ONE_DAY                    3600*24
#define WAIT_DEVINFO_TIME                10


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
#define UPGRADE_STATE_ABORT              4

#define RECEIVE_DATA_LEN                 4096
#define MD5_LEN                          32				
#define SELECT_BUILD_DATE                2
#define DOWNLOAD_RETRY_TIMES             3

#define _10INCH_OS_INDEX                  "2"

#define DOWNLOAD_DONE                    'D'

static int upgrade_status = UPGRADE_STATE_INIT;
static int receive_devinfo_shift = 0;

static pthread_t ota_tid = 0;
static int receive_upgrade_cmd = 0;
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

static bool upgrade_cmd = false;

static em_downloader_event g_dl_event = em_downloader_event_progress;

void download_callback(em_downloader_event e, void *param)
{
    switch (e) {
		case em_downloader_event_error:
        case em_downloader_event_abort:
        case em_downloader_event_finish:
            ALOGD("%s %d e=%d", __func__, __LINE__, e);
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

static void get_version(char *ver, int select_num) {
	int i = 0;
	char* token;

	const char chr[2] = ".";
	char buf[PROPERTY_VALUE_MAX] = {'\0'};

	property_get("ro.build.version.incremental", buf, "19.49.10.1.1");

	token = strtok(buf, chr);
	for (i = 0;i < select_num;i++) {
		token = strtok(NULL, chr);
	}
	strcpy(ver,token);
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

    ALOGD("receive_devinfo_shift: %d,size: %lu",receive_devinfo_shift,size*nmemb);
	ALOGD(" response_connect_server_json: \n%s",buffer);

    memcpy(ptr+receive_devinfo_shift, (char *)buffer, size*nmemb);
	
    if (size*nmemb+receive_devinfo_shift < RECEIVE_DATA_LEN) {
        receive_devinfo_shift = size*nmemb;
    }else {
        receive_devinfo_shift = 0;
    }

    return size*nmemb;
}

static int parseApkJson(char* input_file) {
    fd_set readfds;
    int error_code = 0;

	char login_data_Buf[LOGIN_DATA_LEN] = {0};
	cJSON *root = NULL;
	cJSON *pUrl = NULL;
	cJSON *pMd5 = NULL;
	cJSON *pUpgrade = NULL;
	cJSON *pDelayTime = NULL;

	memset(login_data_Buf, 0, LOGIN_DATA_LEN);
	memcpy(login_data_Buf,input_file,sizeof(login_data_Buf));

	ALOGD("login_data_Buf: %s",login_data_Buf);

	while (1) {
		root = cJSON_Parse(login_data_Buf);
		if (root == NULL) {
			ALOGD("[upgrade]%s, line:%d,cloudn't find http body!", __func__, __LINE__);
			goto err;
		}
		if (root) {
			pMd5 = cJSON_GetObjectItem(root, "md5");
			if (pMd5) {
				memcpy(&globalDeviceInfo.otaMd5, pMd5->valuestring, strlen(pMd5->valuestring));
				ALOGD("Get apk send message md5: %s", globalDeviceInfo.otaMd5);
			} else {
				ALOGD("[upgrade]%s, line:%d,couldn't find md5 node", __func__, __LINE__);
			}

			pUrl = cJSON_GetObjectItem(root, "url");
			if (pUrl) {
				memcpy(&globalDeviceInfo.otaUrl, pUrl->valuestring, strlen(pUrl->valuestring));
				ALOGD("Get apk send message Url: %s", globalDeviceInfo.otaUrl);
				chint_set_upgradeStatus(UPGRADE_STATE_DOWNLOADING);
			} else {
				ALOGD("[upgrade]%s, line:%d,couldn't find otaurl node", __func__, __LINE__);
			}

			pUpgrade = cJSON_GetObjectItem(root, "upgrade");
			if (pUpgrade) {
				memcpy(&globalDeviceInfo.otaUpgrade, pUpgrade->valuestring, strlen(pUpgrade->valuestring));
				ALOGD("Get apk send message Upgrade: %s", globalDeviceInfo.otaUpgrade);
				receive_upgrade_cmd = 1;
			} else {
				ALOGD("[upgrade]%s, line:%d,couldn't find upgrade node", __func__, __LINE__);
			}

			pDelayTime = cJSON_GetObjectItem(root, "delayTime");
			if (pDelayTime) {
				memcpy(&globalDeviceInfo.delayTime, pDelayTime->valuestring, strlen(pDelayTime->valuestring));
				ALOGD("Get apk send message delayTime: %s", globalDeviceInfo.delayTime);
			} else {
				ALOGD("[upgrade]%s, line:%d,couldn't find delayTime node", __func__, __LINE__);
			}
			break;
		}
	}
	return 0;

err:
    if (root != NULL) {
        cJSON_Delete(root);
        root = NULL;
    }
	ALOGE(" pase apk json failed.");
    return -1;
}


static int parseJson(char* input_file) {
    fd_set readfds;
    int error_code = 0;

	char login_data_Buf[LOGIN_DATA_LEN] = {0};
	cJSON *root = NULL;
	cJSON *pEntity = NULL;
	cJSON *pRootCode = NULL;
	cJSON *pEntityCode = NULL;
	cJSON *pValue = NULL;
	cJSON *pUrl = NULL;
	cJSON *pMd5 = NULL;

	memset(login_data_Buf, 0, LOGIN_DATA_LEN);
	memcpy(login_data_Buf,input_file,sizeof(login_data_Buf));

	while (1) {
		root = cJSON_Parse(login_data_Buf);
		if (root == NULL) {
			ALOGD("[upgrade]%s, line:%d,cloudn't find http body!", __func__, __LINE__);
			goto err;
		}
		
		pRootCode = cJSON_GetObjectItem(root, "statusCode");
		if (pRootCode) {
			ALOGD("Root code: %d",pRootCode->valueint);
		} else {
			ALOGD("[upgrade]%s, line:%d,couldn't find pRootCode node", __func__, __LINE__);
			goto err;
		}

		pEntity = cJSON_GetObjectItem(root, "entity");
		if (pEntity) {
			pEntityCode = cJSON_GetObjectItem(pEntity, "statusCode");
			if (pEntityCode) {
				error_code = pEntityCode->valueint;
				ALOGD("code: %d", error_code);
			} else {
				ALOGD("[upgrade]%s, line:%d,couldn't find statusCode node", __func__, __LINE__);
				goto err;
			}

			if (error_code == 0) {
				ALOGD("Success connect to server");
			} else {
				ALOGD("Get error code: %d",error_code);
				goto err;
			}

			pValue = cJSON_GetObjectItem(pEntity, "value");
			if (pValue) {
				pMd5 = cJSON_GetObjectItem(pValue, "md5");
	            if (pMd5) {
	                memcpy(&globalDeviceInfo.otaMd5, pMd5->valuestring, strlen(pMd5->valuestring));
	            } else {
	                ALOGD("[upgrade]%s, line:%d,couldn't find md5 node", __func__, __LINE__);
	                goto err;
	            }

				pUrl = cJSON_GetObjectItem(pValue, "otaurl");
	            if (pUrl) {
	                memcpy(&globalDeviceInfo.otaUrl, pUrl->valuestring, strlen(pUrl->valuestring));
	            } else {
	                ALOGD("[upgrade]%s, line:%d,couldn't find otaurl node", __func__, __LINE__);
	                goto err;
	            }
				break;
			} else {
            	ALOGD("[upgrade]%s, line:%d,couldn't find value node", __func__, __LINE__);
				goto err;
			}
        } else {
            ALOGD("[upgrade]%s, line:%d,couldn't find entity node", __func__, __LINE__);
            goto err;
        }
    }
    if (root != NULL) {
        cJSON_Delete(root);
        root = NULL;
    }
    chint_set_upgradeStatus(UPGRADE_STATE_DOWNLOADING);
    return 0;
err:
    if (root != NULL) {
        cJSON_Delete(root);
        root = NULL;
    }
	ALOGE(" pase json failed.");
    return -1;
	
}

static int sendDownLoadDoneMessage(void) {
	int sendByte = 0;
	char TdcSendBuf[64] = {0};
	int clint_fd;
	int ret;

	struct sockaddr_un CltAddr;
	struct sockaddr_un SrvAddr;

	clint_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	ALOGD(" [YS] clint_fd %d", clint_fd);
	if (clint_fd < 0) {
		ALOGE(" Cannot create communication socket");
		return -1;
	}

	//set server addr_param
	SrvAddr.sun_family = AF_UNIX;//IPV4
	strncpy(SrvAddr.sun_path, OTA_DOMAIN, sizeof(SrvAddr.sun_path) - 1);

	ret=connect(clint_fd,(struct sockaddr*)&SrvAddr,sizeof(SrvAddr));
    if(ret==-1){
        perror("cannot connect to the server");
        close(clint_fd);
        return 1;
    }

	ALOGE("sendDownLoadDoneMessage , otaClient_fd = %d",clint_fd);
	strcpy(TdcSendBuf,"downloadDone");
	if (clint_fd > 0) {
		sendByte = send(clint_fd, TdcSendBuf, strlen(TdcSendBuf), 0);
		if (sendByte <= 0) {
			ALOGE("Send download message failed %s . Retry",strerror(errno));
			sendByte = send(clint_fd, TdcSendBuf, strlen(TdcSendBuf), 0);
			if ( sendByte <= 0) {
				ALOGE("Send download message failed %s . Return",strerror(errno));
				return -2;
			}
		} else {
			ALOGD("Send download message suss : %d ",sendByte);
			return 0;
		}
	} else {
		ALOGE("Client fd is invalid, can not send message to client");
		return -1;
	}
	return 0;
}

static int sendMessage(char cmd) {
	int result = -1;
	switch (cmd) {
		case DOWNLOAD_DONE:
			result = sendDownLoadDoneMessage();
			break;
		default:
			ALOGE("Unknow cmd");
			break;
	}
	return result;
}

static void waitUpgradeCmd() {
	while(!receive_upgrade_cmd) {
		sleep(3);
	}
}

void *socket_ota_thread(void *arg) {	
	int iRet = 0;
	int iRecvLen = 0;
	int pollResult = -1;
	int iCltAddrLen = 0;
	char TdcRecvBuf[256] = {0};
	char TdcSendBuf[DATELEN] = {0};
	struct sockaddr_un CltAddr;
	struct sockaddr_un SrvAddr;
	struct pollfd fds[1];

	unlink(OTA_DOMAIN);
	
	TdcServer_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	ALOGD(" === TdcServer_fd = %d", TdcServer_fd);
	if (TdcServer_fd < 0) {
		ALOGE(" Cannot create communication socket");
		return NULL;
	}

	//set server addr_param
	SrvAddr.sun_family = AF_UNIX;//IPV4
	strncpy(SrvAddr.sun_path, OTA_DOMAIN, sizeof(SrvAddr.sun_path) - 1);

	//bind sockfd & addr
	iRet = bind(TdcServer_fd, (struct sockaddr*)&SrvAddr, sizeof(SrvAddr));
	if (-1 == iRet) {
		ALOGD("cannot bind server socket");
		close(TdcServer_fd);
		unlink(OTA_DOMAIN);
		return NULL;
	}

	//listen sockfd 
	iRet = listen(TdcServer_fd, MAXClIENT);
	if (-1 == iRet) {
		ALOGD("cannot listen the client connect request");
		close(TdcServer_fd);
		unlink(OTA_DOMAIN);
		return NULL;
	}

	//have connect request use accept
	iCltAddrLen = sizeof(CltAddr);
	system("chmod 666 /data/ota.domain");
	
	otaClient_fd = accept(TdcServer_fd, (struct sockaddr*)&CltAddr, (socklen_t*)&iCltAddrLen);
	if(otaClient_fd <= 0) {
		ALOGD("cannot accept client connect request: %s\n",strerror(errno));
		close(TdcServer_fd);
		unlink(OTA_DOMAIN);
		return NULL;
	}
	
	ALOGD ("Thread sockfd = %d\n",otaClient_fd);
	
	fds[0].fd = otaClient_fd;
	fds[0].events = POLLIN;

	while(1) {
		memset(TdcRecvBuf, 0, 256);

		pollResult = poll(fds, 1, -1);
		if (pollResult > 0) {
			//ALOGD("Poll successfully");
		} else {
			ALOGD("Poll error %s",strerror(errno));
		}

		if (fds[0].revents == POLLIN) {
			iRecvLen = recv(otaClient_fd, TdcRecvBuf, 256, 0);
			ALOGD("Message from client fd: %d,	%s\n", otaClient_fd, TdcRecvBuf);
		
			if (!strcmp(TdcRecvBuf,"downloadDone")) {
				enter_recovery_update();
			} else {
			    sleep(5);
			}
		}
	}

	close(otaClient_fd);
	return NULL;
}

static int setupOtaSocket(void) {
	int iRet = -1;
	iRet = pthread_create(&ota_tid, NULL, socket_ota_thread, NULL);
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
	int ret = -1,i = 0,download_count = 0;
	char* url = NULL;
	char* p_md5Data = NULL;
	FILE* fp = NULL;
	char rm_cmd[32] = {0};
	char cap_md5[64] = {0};
	char system_ota_file_md5[64] = {0};

	if ((access(__save_file_path,F_OK)) != -1) {
		sprintf(rm_cmd,"rm %s",__save_file_path);
		system(rm_cmd);
	}

	globalDeviceInfo.receive_login_data = receive_login_data;

	if (getMacAddr(globalDeviceInfo.macAddr) != 0) {
		ALOGE("Get mac addr failed: %s, retry ",strerror(errno));
		sleep(5);
		if (getMacAddr(globalDeviceInfo.macAddr) != 0) {
			ALOGE("Get mac addr failed: %s,exit the OTA service ",strerror(errno));
			return -1;
		}
	}

	get_version(globalDeviceInfo.version,SELECT_BUILD_DATE);
	strcpy(globalDeviceInfo.os,_10INCH_OS_INDEX);
	
	generate_interface_string(&globalDeviceInfo);
	ALOGD("new url: %s",globalDeviceInfo.interfaceString);

	while (1) {
		if (setupSocketSuccess == 0) {
			if (setupOtaSocket() != 0) {
				ALOGE("Setup socket failed: %s, retry ",strerror(errno));
				if (setupOtaSocket() != 0) {
					ALOGE("Setup socket failed again: %s",strerror(errno));
					sleep(5);
					continue;
				} else {
					setupSocketSuccess = 1;
				}
			} else {
				setupSocketSuccess = 1;
			}
		}

		while (0 == checkNet()) {
			ALOGE(" network not connect ");
			sleep(5);
			continue;
		}
		ALOGI("network  connected ");
		ALOGD(" mac:%s\n\r\r\rversion:%s \n",globalDeviceInfo.macAddr,globalDeviceInfo.version);

		ret = connect_server(&globalDeviceInfo);
		if (ret != 0) {
			ALOGE("Connect_server failed! sleep 30 mins, %s",strerror(errno));
			for (i = 0;i < DELAY_30_MINS;i++) {
				if (chint_get_upgradeStatus() != UPGRADE_STATE_DOWNLOADING) {
					sleep(1);
				} else {
					ALOGD("Get download message from Apk, wake up %d",__LINE__);
					break;
				}
			}
			if (i >= DELAY_30_MINS) {
				i = 0;
				continue;
			}
		} else {
			sleep(WAIT_DEVINFO_TIME);
			ALOGD("After 3s get response_connect_server_json:\n\r%s",response_connect_server_json);
			if (parseJson(response_connect_server_json) != 0) {
				ALOGE("Get download information failed, delay one day!");
				receive_devinfo_shift = 0;
				memset(response_connect_server_json,0,sizeof(response_connect_server_json));
				//sleep(DELAY_ONE_DAY);
				for (i = 0;i < DELAY_ONE_DAY;i++) {
					if (chint_get_upgradeStatus() != UPGRADE_STATE_DOWNLOADING) {
						sleep(1);
					} else {
						ALOGD("Get download message from Apk, wake up");
						break;
					}
				}
			}
			memset(response_connect_server_json,0,sizeof(response_connect_server_json));
			receive_devinfo_shift = 0;

			if (i >= DELAY_ONE_DAY) {
				i = 0;
				continue;
			}
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

		for (download_count = 0; download_count < DOWNLOAD_RETRY_TIMES; download_count++) {
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
		ALOGD("%s %d g_dl_finished:%d dlevent:%d", __func__, __LINE__,
			g_dl_finished, g_dl_event);

			aml_downloader_uninit(pdlinfo);
			ALOGD("M... aml_downloader_uninit");

			if (g_dl_event != em_downloader_event_finish) {
				ALOGE("Download error or abort. retry times: %d\n",download_count);
				sleep(180);
			} else {
				ALOGD("Download complete.");
				break;
			}
		}

		if (download_count >= DOWNLOAD_RETRY_TIMES) {
			ALOGE("Download had retried 3 times and download failed. Sleep 6 hours");
			chint_set_upgradeStatus(UPGRADE_STATE_ABORT);

			for (i = 0;i < DELAY_6_HOURS;i++) {
				if (chint_get_upgradeStatus() != UPGRADE_STATE_DOWNLOADING) {
					sleep(1);
				} else {
					ALOGD("Get download message from Apk, wake up %d",__LINE__);
					break;
				}
			}
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
		ALOGD("MD5 server:%s",globalDeviceInfo.otaMd5);
		ALOGD("MD5 file  :%s\ncap_md5: %s", system_ota_file_md5,cap_md5);

		if ( 0 == strncmp(system_ota_file_md5, globalDeviceInfo.otaMd5, MD5_LEN) ||
			0 == strncmp(cap_md5,globalDeviceInfo.otaMd5, MD5_LEN)) {
			ALOGD("MD5 same, upgrading!");
			while (sendMessage(DOWNLOAD_DONE) != 0) {
				ALOGD("Main thread send message failed ,retry after 30mins");
				sleep(DELAY_30_MINS);
			}
			// waitUpgradeCmd();
			// receive_upgrade_cmd = 0;
			// if (!strcmp(globalDeviceInfo.otaUpgrade,"1")) {
			// 	ALOGD("Start to upgrade.");
			// 	upgrade_cmd = false;
			// 	enter_recovery_update();
			// } else {
			// 	ALOGD("Can not get app message delay: %d.",atoi(globalDeviceInfo.delayTime));
			// 	sleep(atoi(globalDeviceInfo.delayTime));
			// 	continue;
			// }
		} else {
			ALOGD("MD5 different, return!");
			remove(__save_file_path);
			continue;
		}
		//break;
	}
	return 0;
}

