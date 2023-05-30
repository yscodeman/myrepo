#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <errno.h>

#include "ota_interface.h"

#define READ_DATA_SIZE	1024
#define MD5_SIZE		16
#define MD5_STR_LEN		(MD5_SIZE * 2)

int connect_server(deviceInfo *di) {
	int ret = -1;
	char result[2048] = {0};
	CURLcode res;
	CURL* curl = curl_easy_init();

	if (NULL == curl)
		return -1;

	ALOGD("url=\n%s\n",di->interfaceString);
	curl_easy_setopt(curl, CURLOPT_URL, di->interfaceString);

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);//忽略证书检查
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL);
	curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 10 );
  curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 30 );
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, di->receive_login_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)result);

	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	//curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3);
	//curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3);
	 
	res = curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	return res;

}

int checkNet(void)
{
    if (system("wpa_cli status | grep wpa_state=COMPLETED") == 0) {
        return 1;
    } else {
        return 0;
    }
}

int getMacAddr(char* mac) {
    int sockfd;
    struct ifreq tmp;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if ( sockfd < 0)
    {
        perror("create socket fail \n");
        return -1;
    }

    memset(&tmp,0,sizeof(struct ifreq));
    strncpy(tmp.ifr_name,"wlan0",sizeof(tmp.ifr_name)-1);

    if ( (ioctl(sockfd,SIOCGIFHWADDR,&tmp)) < 0 ) {
        ALOGI("mac ioctl error %s\n",strerror(errno));
        return -1;
    }
    sprintf(mac, "%02X%02X%02X%02X%02X%02X",
            (unsigned char)tmp.ifr_hwaddr.sa_data[0],
            (unsigned char)tmp.ifr_hwaddr.sa_data[1],
            (unsigned char)tmp.ifr_hwaddr.sa_data[2],
            (unsigned char)tmp.ifr_hwaddr.sa_data[3],
            (unsigned char)tmp.ifr_hwaddr.sa_data[4],
            (unsigned char)tmp.ifr_hwaddr.sa_data[5]
            );
    ALOGI("local mac:%s\n", mac);
    close(sockfd);
    return 0;
}

int calculateStringMd5(unsigned char *dest_str, unsigned int dest_len,
                           char *md5_str)
{
    int i;
    unsigned char md5_value[MD5_SIZE];
    CHINT_MD5_CTX md5;
    // init md5
    chintMD5Init(&md5);
    chintMD5Update(&md5, dest_str, dest_len);
    chintMD5Final(&md5, md5_value);
    // convert md5 value to md5 string
    for (i = 0; i < MD5_SIZE; i++) {
        snprintf(md5_str + i * 2, 2 + 1, "%02x", md5_value[i]);
    }
    i = 0;

#if 0
    while (md5_str[i] != '\0') {
        if (md5_str[i] >= 'a' && md5_str[i] <= 'z') {
            md5_str[i] = md5_str[i] - 'a' + 'A';
        }
        i++;
    }
#endif
    return 0;
}


void generate_interface_string(deviceInfo* di) {
	char _interface[256] = {0};
	char signString[256] = {0};
	char singMd5[256] = {0};

	sprintf(signString,"ota.weling.net.cn/api/ota/getvercurrentver" \
						"%sdevicemac%sos%s" \
						"50f460be2c16440aa8474f2de1d2e74f",di->version,di->macAddr,di->os);

	calculateStringMd5(signString,strlen(signString),singMd5);
	printf("signString:\n\r%s\n",signString);
	printf("singMd5:\n\r%s\n",singMd5);

	sprintf(_interface,"https://ota.weling.net.cn/api/ota/getver?" \
			"devicemac=%s&currentver=%s" \
			"&os=%s&" \
			"sign=%s",di->macAddr,di->version,di->os,singMd5);

	ALOGD("interface:\n\r%s",_interface);
	strcpy(di->interfaceString,_interface);
}


int getTimeStamp(char* str)
{
    time_t timestamp;

    timestamp = time(NULL);
    sprintf(str, "%ld", timestamp);

    return 0;
}

int calculateFileMd5(const char *file_path, char *md5_str) {
	int i;
	int fd;
	int ret;
	unsigned char data[READ_DATA_SIZE] = {0};
	unsigned char md5_value[MD5_SIZE] = {0};
	CHINT_MD5_CTX md5;
 
	fd = open(file_path, O_RDONLY); 
	if (-1 == fd) {
		perror("open");
		return -1;
	}
 
	chintMD5Init(&md5);

	while (1) {
		ret = read(fd, data, READ_DATA_SIZE);
		if (-1 == ret) {
			perror("read");
			return -1;
		}
 
		chintMD5Update(&md5, data, ret);
 
		if (0 == ret || ret < READ_DATA_SIZE) {
			break;
		}
	}
 
	close(fd);
 
	chintMD5Final(&md5, md5_value);
 
	for(i = 0; i < MD5_SIZE; i++) {
		snprintf(md5_str + i*2, 2+1, "%02x", md5_value[i]);
	}
	md5_str[MD5_STR_LEN] = '\0'; // add end
 
	return 0;
}


