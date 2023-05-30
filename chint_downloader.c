
// #define LOG_TAG "chint_downloader"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <cutils/log.h>
#include <curl/curl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "chint_downloader.h"

// #define LOG_TAG "otaMain"

typedef enum {
    em_status_unknown = 0,
    em_status_start,
    em_status_pause,
    em_status_finish,
    em_status_failed,
} download_status;

struct _st_aml_dlinfo {
    aml_downloader_cb event_cb;
    char res_url[1024];
    char userpassword[64];
    char filefullpath[256];
    CURL *curl;
    FILE *pf;
    pthread_t threadid;
    download_status status;
    bool abortflag;
};

unsigned long get_file_size(const char *path)
{
    unsigned long filesize = -1;
    struct stat statbuff;

    if (stat(path, &statbuff) < 0) {
		return filesize;
    } else{
		filesize = statbuff.st_size;
    }
    return filesize;
}


/************************************************************
** FunctionName : aml_downloader_init
** Description  : 初始化下载
** Input Param  :
** Output Param :
** Return Value :
**************************************************************/
st_aml_dlinfo *aml_downloader_init()
{
    st_aml_dlinfo *pdlinfo = (st_aml_dlinfo *)malloc(sizeof(st_aml_dlinfo));

    if (pdlinfo != NULL) {
        memset(pdlinfo, 0, sizeof(st_aml_dlinfo));
    }

    return pdlinfo;
}


/************************************************************
** FunctionName : aml_downloader_init
** Description  : 反初始化下载
** Input Param  :
** Output Param :
** Return Value :
**************************************************************/
void aml_downloader_uninit(st_aml_dlinfo *pst_dlinfo)
{
    assert(pst_dlinfo != NULL);

    pst_dlinfo->abortflag = true;
    pthread_join(pst_dlinfo->threadid, NULL);

    if (pst_dlinfo->curl != NULL) {
        curl_easy_cleanup(pst_dlinfo->curl);
        usleep(200 * 1000);
    }

    free(pst_dlinfo);
}


/************************************************************
** FunctionName : aml_downloader_setcallback
** Description  : 设置下载事件回调
** Input Param  :
** Output Param :
** Return Value :
**************************************************************/
void aml_downloader_setcallback(st_aml_dlinfo *pst_dlinfo, aml_downloader_cb cb)
{
    assert(pst_dlinfo != NULL);

    pst_dlinfo->event_cb = cb;
}

/************************************************************
** FunctionName : aml_downloader_seturl
** Description  : 设置下载url
** Input Param  :
					res_url: url
					userpassword: ftp用户名和密码，格式为   username:password  (用:隔开)
** Output Param :
** Return Value : true: success,  false: failed
**************************************************************/
bool aml_downloader_seturl(st_aml_dlinfo *pst_dlinfo, const char *res_url, const char *userpassword)
{
    assert(pst_dlinfo != NULL);
    if (res_url != NULL) {
        strncpy(pst_dlinfo->res_url, res_url, sizeof(pst_dlinfo->res_url) - 1);
    } else {
        return false;
    }

    if (userpassword != NULL) {
        strncpy(pst_dlinfo->userpassword, userpassword, sizeof(pst_dlinfo->userpassword) - 1);
    }

    return true;
}

/************************************************************
** FunctionName : aml_downloader_setsavepath
** Description  : 设置下载文件存放绝对路径
** Input Param  :
** Output Param :
** Return Value : true: success,  false: failed
**************************************************************/
bool aml_downloader_setsavepath(st_aml_dlinfo *pst_dlinfo, const char *filefullpath)
{
    assert(pst_dlinfo != NULL);

    if (filefullpath != NULL) {
        strncpy(pst_dlinfo->filefullpath, filefullpath, sizeof(pst_dlinfo->filefullpath) - 1);
    } else {
        return false;
    }

    return true;
}

int on_progress(void *param,
                double t, /* dltotal */
                double d, /* dlnow */
                double ultotal,
                double ulnow)
{
    st_aml_dlinfo *pst_dlinfo = (st_aml_dlinfo *)param;

    if (t > 0) {
        double prog = d * 100.0 / t;
        if (pst_dlinfo->event_cb) {
            pst_dlinfo->event_cb(em_downloader_event_progress, (void*)&prog);
        }
    }

    if (pst_dlinfo->abortflag) {
        return -1;
    }
    return 0;
}


void *download_task(void *param)
{
    unsigned long size;
    char range[32];

    st_aml_dlinfo *pst_dlinfo = (st_aml_dlinfo *)param;

    pst_dlinfo->pf = fopen(pst_dlinfo->filefullpath, "ab");
    if (pst_dlinfo->pf == NULL) {
        ALOGE(" [download_task] open filefullpath failed,  %s \n ",strerror(errno));
        if (pst_dlinfo->event_cb) {
            pst_dlinfo->event_cb(em_downloader_event_error, "create file error!");
        }
        return NULL;
    }

    size = get_file_size(pst_dlinfo->filefullpath);

    pst_dlinfo->curl = curl_easy_init();
    if (pst_dlinfo->curl == NULL) {
        pst_dlinfo->event_cb(em_downloader_event_error, "init curl error!");
        return NULL;
    }

    curl_easy_setopt(pst_dlinfo->curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(pst_dlinfo->curl, CURLOPT_URL, pst_dlinfo->res_url);
    if (strlen(pst_dlinfo->userpassword) > 0) {
        curl_easy_setopt(pst_dlinfo->curl, CURLOPT_USERPWD, pst_dlinfo->userpassword);
    }
    curl_easy_setopt( pst_dlinfo->curl, CURLOPT_LOW_SPEED_LIMIT, 10);
    curl_easy_setopt( pst_dlinfo->curl, CURLOPT_LOW_SPEED_TIME, 30);
    curl_easy_setopt(pst_dlinfo->curl, CURLOPT_WRITEDATA, pst_dlinfo->pf);
    curl_easy_setopt(pst_dlinfo->curl, CURLOPT_CONNECTTIMEOUT, 10);
    curl_easy_setopt(pst_dlinfo->curl, CURLOPT_NOPROGRESS, false);

    if (size != 0) {
        sprintf(range, "%lu%s", size, "-");
        ALOGD("  ============ range: %s\n", range);
        curl_easy_setopt(pst_dlinfo->curl, CURLOPT_RANGE, range);
    }

    curl_easy_setopt(pst_dlinfo->curl, CURLOPT_PROGRESSFUNCTION, on_progress);
    curl_easy_setopt(pst_dlinfo->curl, CURLOPT_PROGRESSDATA, (void*)pst_dlinfo);

    pst_dlinfo->status = em_status_start;
    pst_dlinfo->abortflag = false;

    CURLcode errcode = curl_easy_perform(pst_dlinfo->curl);
    const char *str_err = curl_easy_strerror(errcode);

    if (errcode != CURLE_OK) {
        if (pst_dlinfo->abortflag) {
            pst_dlinfo->status = em_status_failed;
            if (pst_dlinfo->event_cb) {
                pst_dlinfo->event_cb(em_downloader_event_abort, (void*)str_err);
            }
        } else {
            ALOGI("%s %d curl_easy_perform failed: code:%d(%s)\n", __func__, __LINE__, errcode, str_err);
            pst_dlinfo->status = em_status_failed;

            if (pst_dlinfo->event_cb) {
                pst_dlinfo->event_cb(em_downloader_event_error, (void*)str_err);
            }
        }
    } else {
        pst_dlinfo->status = em_status_finish;

        if (pst_dlinfo->event_cb) {
            pst_dlinfo->event_cb(em_downloader_event_finish, (void*)NULL);
        }
    }
    curl_global_cleanup();

    fflush(pst_dlinfo->pf);
    fclose(pst_dlinfo->pf);

    return NULL;
}

/************************************************************
** FunctionName : aml_downloader_start
** Description  : 启动下载线程
** Input Param  :
** Output Param :
** Return Value : true: success,  false: failed
**************************************************************/
bool aml_downloader_start(st_aml_dlinfo *pst_dlinfo)
{
    assert(pst_dlinfo != NULL);

    if ((strlen(pst_dlinfo->filefullpath) <= 0) || (strlen(pst_dlinfo->res_url) <= 0)) {
        return false;
    }

    int ret = pthread_create(&pst_dlinfo->threadid, NULL,  download_task, (void*)pst_dlinfo);
    if (ret != 0) {
        return false;
    }

    return true;
}

/************************************************************
** FunctionName : aml_downloader_abort
** Description  : 放弃下载
** Input Param  :
** Output Param :
** Return Value : true: success,  false: failed
**************************************************************/
bool aml_downloader_abort(st_aml_dlinfo *pst_dlinfo)
{
    pst_dlinfo->abortflag = true;
    return true;
}



