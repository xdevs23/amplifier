/*
 * Copyright (C) 2016 The CyanogenMod Project
 * Copyright (C) 2018 The LineageOS Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "audio_amplifier"
#define LOG_NDEBUG 0

#include <dlfcn.h>
#include <stdint.h>
#include <sys/types.h>

#include <cutils/log.h>
#include <cutils/str_parms.h>

#include <hardware/audio_amplifier.h>
#include <hardware/hardware.h>

#include <system/audio.h>
#include <tinyalsa/asoundlib.h>
#include <tinycompress/tinycompress.h>
#include <msm8916/platform.h>
#include <audio_hw.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/ioctl.h>

#include <linux/ioctl.h>
#define __force
#define __bitwise
#define __user
#include <sound/asound.h>

#define PRESET_RINGTONE 1
#define PRESET_BYPASS 2
#define PRESET_PLAYBACK 3
#define PRESET_ALARM 4

#define CARD 0
#define DEVICE 1

typedef struct tfa9895_amplifier {
    amplifier_device_t amp;
    int mixer_fd;
    unsigned int mi2s_clk_id;
    bool calibrating;
    bool writing;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    pthread_t watch_thread;
    void *lib_ptr;
    int (*speaker_on)();
    int (*speaker_off)();
    int (*calibrate)();
    int (*switch_para)(int);
    bool on;
    int preset;
    bool preset_changed;
} tfa9895_amplifier_t;

struct pcm_config pcm_config_deep_buffer = {
    .channels = 2,
    .rate = DEFAULT_OUTPUT_SAMPLING_RATE,
    .period_size = DEEP_BUFFER_OUTPUT_PERIOD_SIZE,
    .period_count = DEEP_BUFFER_OUTPUT_PERIOD_COUNT,
    .format = PCM_FORMAT_S16_LE,
    .start_threshold = DEEP_BUFFER_OUTPUT_PERIOD_COUNT / 4,
    .stop_threshold = INT_MAX,
    .avail_min = DEEP_BUFFER_OUTPUT_PERIOD_SIZE / 4,
};

#define MI2S_CLK_CTL "PRI_MI2S Clock"
#define MI2S_MIXER "PRI_MI2S_RX Audio Mixer MultiMedia2"

static int mi2s_interface_en(bool enable)
{
    enum mixer_ctl_type type;
    struct mixer_ctl *ctl;
    struct mixer *mixer = mixer_open(0);

    if (mixer == NULL) {
        ALOGE("Error opening mixer 0");
        return -1;
    }

    ctl = mixer_get_ctl_by_name(mixer, MI2S_MIXER);
    if (ctl == NULL) {
        mixer_close(mixer);
        ALOGE("Could not find %s", MI2S_MIXER);
        return -1;
    }

    type = mixer_ctl_get_type(ctl);
    if (type != MIXER_CTL_TYPE_BOOL) {
        ALOGE("%s is not supported", MI2S_MIXER);
        mixer_close(mixer);
        return -1;
    }

    mixer_ctl_set_value(ctl, 0, enable);
    mixer_close(mixer);
    return 0;
}

void *write_dummy_data(void *param)
{
    char *buffer;
    int size;
    struct pcm *pcm;
    tfa9895_amplifier_t *tfa9895 = (tfa9895_amplifier_t *) param;

    if (mi2s_interface_en(true)) {
        ALOGE("Failed to enable %s", MI2S_MIXER);
        return NULL;
    }

    pcm = pcm_open(CARD, DEVICE, PCM_OUT | PCM_MONOTONIC, &pcm_config_deep_buffer);
    if (!pcm || !pcm_is_ready(pcm)) {
        ALOGE("pcm_open failed: %s", pcm_get_error(pcm));
        if (pcm) {
            goto err_close_pcm;
        }
        goto err_disable_mi2s;
    }

    size = DEEP_BUFFER_OUTPUT_PERIOD_SIZE * 8;
    buffer = calloc(size, 1);
    if (!buffer) {
        ALOGE("failed to allocate buffer");
        goto err_close_pcm;
    }

    do {
        if (pcm_write(pcm, buffer, size)) {
            ALOGE("pcm_write failed");
        }
        pthread_mutex_lock(&tfa9895->mutex);
        tfa9895->writing = true;
        pthread_cond_signal(&tfa9895->cond);
        pthread_mutex_unlock(&tfa9895->mutex);
    } while (tfa9895->calibrating);

    free(buffer);
err_close_pcm:
    pcm_close(pcm);
err_disable_mi2s:
    mi2s_interface_en(false);
    ALOGV("--%s:%d", __func__, __LINE__);
    return NULL;
}

static int amp_dev_close(hw_device_t *device)
{
    tfa9895_amplifier_t *tfa9895 = (tfa9895_amplifier_t *) device;

    ALOGV("%s", __func__);

    if (tfa9895) {
        if (tfa9895->mixer_fd >= 0) {
            close(tfa9895->mixer_fd);
        }
        pthread_join(tfa9895->watch_thread, NULL);
        pthread_cond_destroy(&tfa9895->cond);
        pthread_mutex_destroy(&tfa9895->mutex);
        dlclose(tfa9895->lib_ptr);
        free(tfa9895);
    }

    return 0;
}

static int amp_calibrate(tfa9895_amplifier_t *tfa9895)
{
    pthread_t write_thread;

    ALOGV("%s", __func__);

    tfa9895->calibrating = true;
    pthread_create(&write_thread, NULL, write_dummy_data, tfa9895);
    pthread_mutex_lock(&tfa9895->mutex);
    while(!tfa9895->writing) {
        pthread_cond_wait(&tfa9895->cond, &tfa9895->mutex);
    }
    pthread_mutex_unlock(&tfa9895->mutex);
    tfa9895->calibrate();
    tfa9895->calibrating = false;
    pthread_join(write_thread, NULL);
    return 0;
}

static int amp_set_mode(struct amplifier_device *device, audio_mode_t mode)
{
    int preset;
    tfa9895_amplifier_t *tfa9895 = (tfa9895_amplifier_t *) device;

    pthread_mutex_lock(&tfa9895->mutex);

    switch (mode) {
        case AUDIO_MODE_RINGTONE:
            preset = PRESET_RINGTONE;
            break;
        case AUDIO_MODE_IN_CALL:
        case AUDIO_MODE_IN_COMMUNICATION:
        case AUDIO_MODE_NORMAL:
            preset = PRESET_PLAYBACK;
            break;
        default:
            preset = PRESET_BYPASS;
            break;
    }

    ALOGV("%s: mode=%d old preset=%d new preset=%d", __func__, mode, tfa9895->preset, preset);

    if (preset == tfa9895->preset) {
        goto out;
    }

    tfa9895->preset = preset;
    tfa9895->preset_changed = true;

out:
    pthread_mutex_unlock(&tfa9895->mutex);
    return 0;
}

static void *amp_watch(void *param)
{
    struct snd_ctl_event event;
    tfa9895_amplifier_t *tfa9895 = (tfa9895_amplifier_t *) param;

    while(read(tfa9895->mixer_fd, &event, sizeof(struct snd_ctl_event)) > 0) {
        if (event.data.elem.id.numid == tfa9895->mi2s_clk_id) {
            struct snd_ctl_elem_value ev;
            ev.id.numid = tfa9895->mi2s_clk_id;
            if (ioctl(tfa9895->mixer_fd, SNDRV_CTL_IOCTL_ELEM_READ, &ev) < 0)
                continue;
            ALOGV("%s %s event = %d!", __func__, MI2S_CLK_CTL, ev.value.enumerated.item[0]);
            pthread_mutex_lock(&tfa9895->mutex);
            if (ev.value.enumerated.item[0]) {
                tfa9895->speaker_on();
                tfa9895->on = true;

                if (tfa9895->preset_changed) {
                    tfa9895->switch_para(tfa9895->preset);
                    tfa9895->preset_changed = false;
                }
            } else if (tfa9895->on) {
                tfa9895->speaker_off();
                tfa9895->on = false;
            }
            pthread_mutex_unlock(&tfa9895->mutex);
        }
    }
    return NULL;
}

static int amp_init(tfa9895_amplifier_t *tfa9895)
{
    size_t i;
    int subscribe = 1;
    struct snd_ctl_elem_list elist;
    struct snd_ctl_elem_id *eid = NULL;
    tfa9895->mixer_fd = open("/dev/snd/controlC0", O_RDWR);
    if (tfa9895->mixer_fd < 0) {
        ALOGE("failed to open");
        goto fail;
    }

    memset(&elist, 0, sizeof(elist));
    if (ioctl(tfa9895->mixer_fd, SNDRV_CTL_IOCTL_ELEM_LIST, &elist) < 0) {
        ALOGE("failed to get alsa control list");
        goto fail;
    }

    eid = calloc(elist.count, sizeof(struct snd_ctl_elem_id));
    if (!eid) {
        ALOGE("failed to allocate snd_ctl_elem_id");
        goto fail;
    }

    elist.space = elist.count;
    elist.pids = eid;

    if (ioctl(tfa9895->mixer_fd, SNDRV_CTL_IOCTL_ELEM_LIST, &elist) < 0) {
        ALOGE("failed to get alsa control list");
        goto fail;
    }

    for (i = 0; i < elist.count; i++) {
        struct snd_ctl_elem_info ei;
        ei.id.numid = eid[i].numid;
        if (ioctl(tfa9895->mixer_fd, SNDRV_CTL_IOCTL_ELEM_INFO, &ei) < 0) {
            ALOGE("failed to get alsa control %d info", eid[i].numid);
            goto fail;
        }

        if (!strcmp(MI2S_CLK_CTL, (const char *)ei.id.name)) {
            ALOGI("Found %s! %d", MI2S_CLK_CTL, ei.id.numid);
            tfa9895->mi2s_clk_id = ei.id.numid;
            break;
        }
    }

    if (i == elist.count) {
        ALOGE("could not find %s", MI2S_CLK_CTL);
        goto fail;
    }

    if (ioctl(tfa9895->mixer_fd, SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS, &subscribe) < 0) {
        ALOGE("failed to subscribe to %s events", MI2S_CLK_CTL);
        goto fail;
    }

    pthread_create(&tfa9895->watch_thread, NULL, amp_watch, tfa9895);

    return 0;
fail:
    if (eid)
        free(eid);
    if (tfa9895->mixer_fd >= 0)
        close(tfa9895->mixer_fd);
    return -ENODEV;
}

static int amp_module_open(const hw_module_t *module, const char *name,
        hw_device_t **device)
{
    if (strcmp(name, AMPLIFIER_HARDWARE_INTERFACE)) {
        ALOGE("%s:%d: %s does not match amplifier hardware interface name\n",
                __func__, __LINE__, name);
        return -ENODEV;
    }

    tfa9895_amplifier_t *tfa9895 = calloc(1, sizeof(tfa9895_amplifier_t));
    if (!tfa9895) {
        ALOGE("%s:%d: Unable to allocate memory for amplifier device\n",
                __func__, __LINE__);
        return -ENOMEM;
    }

    tfa9895->amp.common.tag = HARDWARE_DEVICE_TAG;
    tfa9895->amp.common.module = (hw_module_t *) module;
    tfa9895->amp.common.version = AMPLIFIER_DEVICE_API_VERSION_2_0;
    tfa9895->amp.common.close = amp_dev_close;
    tfa9895->amp.set_mode = amp_set_mode;

    tfa9895->on = false;
    tfa9895->preset = -1;
    tfa9895->preset_changed = false;

    tfa9895->lib_ptr = dlopen("libFIHNxp.so", RTLD_NOW);
    if (!tfa9895->lib_ptr) {
        ALOGE("%s:%d: Unable to open libFIHNxp.so: %s",
                __func__, __LINE__, dlerror());
        free(tfa9895);
        return -ENODEV;
    }

    *(void **)&tfa9895->calibrate = dlsym(tfa9895->lib_ptr, "FIH_tfa9895_init");
    *(void **)&tfa9895->speaker_on = dlsym(tfa9895->lib_ptr, "FIH_tfa9895_power_on");
    *(void **)&tfa9895->speaker_off = dlsym(tfa9895->lib_ptr, "FIH_tfa9895_power_off");
    *(void **)&tfa9895->switch_para = dlsym(tfa9895->lib_ptr, "FIH_tfa9895_switch_para");


    if (!tfa9895->calibrate || !tfa9895->speaker_off ||
            !tfa9895->speaker_on || !tfa9895->switch_para) {
        ALOGE("%s:%d: Unable to find required symbols", __func__, __LINE__);
        dlclose(tfa9895->lib_ptr);
        free(tfa9895);
        return -ENODEV;
    }

    pthread_mutex_init(&tfa9895->mutex, NULL);
    pthread_cond_init(&tfa9895->cond, NULL);

    amp_calibrate(tfa9895);
    amp_init(tfa9895);
    amp_set_mode((struct amplifier_device *)tfa9895, AUDIO_MODE_NORMAL);

    *device = (hw_device_t *) tfa9895;

    return 0;
}

static struct hw_module_methods_t hal_module_methods = {
    .open = amp_module_open,
};

amplifier_module_t HAL_MODULE_INFO_SYM = {
    .common = {
        .tag = HARDWARE_MODULE_TAG,
        .module_api_version = AMPLIFIER_MODULE_API_VERSION_0_1,
        .hal_api_version = HARDWARE_HAL_API_VERSION,
        .id = AMPLIFIER_HARDWARE_MODULE_ID,
        .name = "Ether Amplifier HAL",
        .author = "The LineageOS Project",
        .methods = &hal_module_methods,
    },
};
