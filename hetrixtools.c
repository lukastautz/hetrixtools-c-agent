/*
Copyright 2025 Lukas Tautz

This file is part of (unofficial) HetrixTools C agent.

(unofficial) HetrixTools C agent is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/


#ifdef __dietlibc__
#define _GNU_SOURCE /* for u_intN_t */
#define __bitwise /**/
#endif

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <ctype.h>

#include "BearSSL/inc/bearssl.h"

#include "config.h"

typedef u_int8_t   uint8;
typedef u_int16_t  uint16;
typedef u_int32_t  uint32;
typedef u_int64_t  uint64;
typedef int8_t     int8;
typedef int16_t    int16;
typedef int32_t    int32;
typedef int64_t    int64;

typedef struct jiffies_spent_s {
    uint64 user;
    uint64 nice;
    uint64 system;
    uint64 idle;
    uint64 iowait;
    uint64 irq;
    uint64 softirq;
    uint64 steal;
    uint64 guest;
    uint64 guest_nice;
    uint64 work; /* = user+nice+system+(soft)irq+guest+guest_nice */
    uint64 total;
} jiffies_spent;

typedef struct {
    char linux_version[72];
    uint32 uptime;
    char cpu_model[64];
    uint16 cpu_speed;
    uint16 cpu_cores;
    double cpu_usage;
    double cpu_iowait;
    uint64 ram_size;
    double ram_usage;
    uint64 swap_size;
    double swap_usage;
    uint64 disk_total;
    uint64 disk_used;
    uint64 rx_bytes;
    uint64 tx_bytes;
} system_metrics;

char file_buf[8192], data_buf[512], http_buf[768], disk[32], disk_base64[64], cpu_base64[96], linux_version_base64[100], iobuf[BR_SSL_BUFSIZE_BIDI], token[32];
system_metrics metrics;
jiffies_spent cpu_start, cpu_end;
uint64 net_rx_start, net_tx_start, net_rx_end, net_tx_end, cpu_total_diff, cpu_iowait_diff, cpu_work_diff;
br_ssl_client_context sc;
br_x509_minimal_context xc;
br_sslio_context ioc;
const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define str_append(d, l, s) str_append_len(d, l, s, strlen(s))
#define PTR_IS_IN_BUF(ptr, buf) (ptr < (buf + sizeof(buf)))

uint16 get_cores_from_sysfs(void) {
    int fd = open("/sys/devices/system/cpu/online", O_RDONLY);
    char *pos;
    uint8 len;
    if (fd == -1 || (len = read(fd, file_buf, sizeof(file_buf))) < 1)
        return 0;
    close(fd);
    file_buf[len] = '\0';
    if ((pos = strchr(file_buf, '-')))
        return atoi(pos + 1) + 1;
    return atoi(file_buf) + 1;
}

void get_current_jiffies_and_cpu_count(jiffies_spent *dest, system_metrics *metrics) {
    uint64 tmp;
    char *ptr = file_buf;
    dest->total = 0;
    int fd = open("/proc/stat", O_RDONLY);
    if (fd == -1 || read(fd, file_buf, sizeof(file_buf)) < 100) {
        memset(dest, 0, sizeof(*dest));
        return;
    }
    close(fd);
    ptr += 3; // skip "cpu"
    while (isspace(*++ptr) && PTR_IS_IN_BUF(ptr, file_buf));
    if (!PTR_IS_IN_BUF(ptr, file_buf)) {
        memset(dest, 0, sizeof(*dest));
        return;
    }
    for (uint8 i = 0; i < 10; ++i) {
        tmp = (uint64)atol(ptr);
        dest->total += tmp;
        memcpy((uint64 *)((uint64)dest + (uint64)(8 * i)), &tmp, 8);
        while (!isspace(*++ptr) && PTR_IS_IN_BUF(ptr, file_buf));
        if (!PTR_IS_IN_BUF(ptr, file_buf)) {
            memset(dest, 0, sizeof(*dest));
            return;
        }
        while (isspace(*++ptr) && PTR_IS_IN_BUF(ptr, file_buf));
        if (!PTR_IS_IN_BUF(ptr, file_buf)) {
            memset(dest, 0, sizeof(*dest));
            return;
        }
    }
    dest->work = dest->user + dest->nice + dest->system + dest->guest + dest->guest_nice + dest->irq + dest->softirq;
    if (!metrics->cpu_cores) {
        metrics->cpu_cores = 1;
        for (;;) {
            while (*ptr != '\n')
                ++ptr;
            if (*++ptr == 'c')
                ++metrics->cpu_cores;
            else
                return;
        }
    }
}

void get_network_stats(uint64 *rx, uint64 *tx) {
    int fd = open("/proc/net/dev", O_RDONLY);
    if (fd == -1 || read(fd, file_buf, sizeof(file_buf)) < 100) {
        *rx = 0; *tx = 0;
        close(fd);
        return;
    }
    close(fd);
    char *ptr = file_buf, *line_start, *field;
    uint8 pos, line_count = 0;
    *rx = *tx = 0;
    while (line_count < 2 && PTR_IS_IN_BUF(ptr, file_buf)) {
        if (*ptr == '\n')
            ++line_count;
        ++ptr;
    }
    while (PTR_IS_IN_BUF(ptr, file_buf)) {
        line_start = ptr;
        while (*ptr != '\n' && PTR_IS_IN_BUF(ptr, file_buf)) 
            ++ptr;
        if (!PTR_IS_IN_BUF(ptr, file_buf))
            break;
        *ptr = '\0';
        if (!strstr(line_start, "lo:")) {
            field = line_start;
            while (*field != ':' && *field)
                ++field;
            if (!*field)
                continue;
            ++field;
            while (isspace(*field))
                ++field;
            *rx += (uint64)atoll(field);
            pos = 1;
            while (pos < 9) {
                while (!isspace(*field) && *field)
                    ++field;
                if (!*field)
                    break;
                while (isspace(*field))
                    ++field;
                ++pos;
            }
            if (pos == 9)
                *tx += (uint64)atoll(field);
        }
        ++ptr;
    }
}

uint32 get_uptime(void) {
    int fd = open("/proc/uptime", O_RDONLY);
    if (fd == -1 || read(fd, file_buf, sizeof(file_buf)) < 8) {
        close(fd);
        return 0;
    }
    close(fd);
    return (uint32)atol(file_buf);
}

void get_cpu_info(system_metrics *metrics) {
    int fd = open("/proc/cpuinfo", O_RDONLY);
    if (fd == -1 || read(fd, file_buf, sizeof(file_buf)) < 100) {
        metrics->cpu_speed = 0;
        memcpy(metrics->cpu_model, "Unknown", sizeof("Unknown"));
        close(fd);
        return;
    }
    close(fd);
    char *ptr = file_buf;
    if ((ptr = strstr(file_buf, "model name")) && (ptr = strstr(ptr, ": "))) {
        ptr += 2;
        char *end = strchr(ptr, '\n');
        if (end) {
            uint8 len = end - ptr;
            if (len > sizeof(metrics->cpu_model) - 1)
                len = sizeof(metrics->cpu_model) - 1;
            memcpy(metrics->cpu_model, ptr, len);
            metrics->cpu_model[len] = '\0';
        }
    }
    if ((ptr = strstr(file_buf, "cpu MHz")) && (ptr = strstr(ptr, ": ")))
        metrics->cpu_speed = (uint16)atoi(ptr + 2);
}

void get_memory_info(system_metrics *metrics) {
    char *ptr = file_buf + strlen("MemTotal:");
    int fd = open("/proc/meminfo", O_RDONLY);
    uint16 len;
    if (fd == -1 || (len = read(fd, file_buf, sizeof(file_buf))) < 100) {
        metrics->ram_size = 0;
        metrics->ram_usage = 0.0;
        close(fd);
        return;
    }
    close(fd);
    file_buf[len] = '\0';
    while (isspace(*++ptr) && PTR_IS_IN_BUF(ptr, file_buf));
    metrics->ram_size = (uint64)atoll(ptr);
    while (*++ptr != 'F' && PTR_IS_IN_BUF(ptr, file_buf)); // Free
    while (*++ptr != 'A' && PTR_IS_IN_BUF(ptr, file_buf)); // Available
    ptr += strlen("vailable:");
    while (isspace(*++ptr) && PTR_IS_IN_BUF(ptr, file_buf));
    if (metrics->ram_size )
        metrics->ram_usage = 100.0 * ((double)(metrics->ram_size - (uint64)atoll(ptr)) / metrics->ram_size);
    else
        metrics->ram_usage = 0;
    if (ptr = strstr(file_buf, "SwapTotal:")) {
        ptr += strlen("SwapTotal:");
        while (isspace(*ptr))
            ++ptr;
        metrics->swap_size = (uint64)atoll(ptr);
    } else 
        metrics->swap_size = 0;
    if (metrics->swap_size && (ptr = strstr(file_buf, "SwapFree:"))) {
        ptr += strlen("SwapFree:");
        while (isspace(*ptr))
            ++ptr;
        metrics->swap_usage = 100.0 * ((double)(metrics->swap_size - (uint64)atoll(ptr)) / metrics->swap_size);
    } else
        metrics->swap_usage = 0.0;
}

void get_disk_info(system_metrics *metrics) {
    struct statvfs stat;
    if (statvfs("/", &stat)) {
        metrics->disk_total = metrics->disk_used = 0;
        return;
    }
    metrics->disk_total = (uint64)stat.f_blocks * stat.f_frsize;
    metrics->disk_used = metrics->disk_total - ((uint64)stat.f_bfree * stat.f_frsize);
}

void str_append_len(char *dest, uint16 *dest_len, const char *src, uint16 len) {
    memcpy(dest + *dest_len, src, len);
    *dest_len += len;
    dest[*dest_len] = '\0';
}

uint8 itoa(uint64 n, char *s) {
    uint8 i = 0, y = 0, z;
    do
        s[i] = n % 10 + '0', ++i;
    while ((n /= 10) > 0);
    z = i - 1;
    for (char c; y < z; ++y, --z)
        c = s[y], s[y] = s[z], s[z] = c;
    return i;
}

uint8 itoa_fill(uint32 n, char *dest, uint8 fill_to) {
    uint8 i = 0, z = 0, j;
    char tmp;
    while (n) {
        dest[i++] = (n % 10) + '0';
        n /= 10;
    }
    while (i < fill_to)
        dest[i++] = '0';
    j = i - 1;
    while (z < j) {
        tmp = dest[z], dest[z] = dest[j], dest[j] = tmp;
        ++z, --j;
    }
    return i;
}

void str_append_uint(char *dest, uint16 *dest_len, uint64 value) {
    *dest_len += itoa(value, dest + *dest_len);
    dest[*dest_len] = '\0';
}

void str_append_percent(char *dest, uint16 *dest_len, double value) {
    uint8 tmp = value;
    *dest_len += itoa(value, dest + *dest_len);
    dest[(*dest_len)++] = '.';
    tmp = 100 * (value - (double)tmp);
    *dest_len += itoa_fill(tmp, dest + *dest_len, 2);
    dest[*dest_len] = '\0';
}

uint8 base64_encode(const unsigned char *input, uint8 len, char *to) {
    uint8 outlen = 4 * ((len + 2) / 3);
    if (!to)
        return 0;
    uint8 i, j;
    uint32 a, b, c, t;
    for (i = j = 0; i < len; ) {
        a = i < len ? input[i++] : 0;
        b = i < len ? input[i++] : 0;
        c = i < len ? input[i++] : 0;
        t = (a << 16) + (b << 8) + c;
        to[j++] = base64_table[(t >> 18) & 0x3F];
        to[j++] = base64_table[(t >> 12) & 0x3F];
        to[j++] = base64_table[(t >> 6) & 0x3F];
        to[j++] = base64_table[t & 0x3F];
    }
    uint8 table[] = {0, 2, 1};
    for (i = 0; i < table[len % 3]; ++i)
        to[outlen - 1 - i] = '=';
    to[outlen] = '\0';
    return outlen;
}

int sock_read(void *ctx, unsigned char *buf, size_t len) {
    return read(*(int *)ctx, buf, len);
}
int sock_write(void *ctx, const unsigned char *buf, size_t len) {
    return write(*(int *)ctx, buf, len);
}

int setup_bearssl_connection(int *fd) {
    struct addrinfo hints, *addrinfo, *cur;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    if (getaddrinfo(CONFIG_API_HOST, "443", &hints, &addrinfo))
        return -2;
    for (cur = addrinfo; cur; cur = cur->ai_next) {
        *fd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (*fd < 0)
            continue;
        if (!connect(*fd, cur->ai_addr, cur->ai_addrlen))
            break;
        close(*fd);
    }
    freeaddrinfo(addrinfo);
    if (!cur)
        return -3;
    br_ssl_client_reset(&sc, CONFIG_API_HOST, 0);
    br_sslio_init(&ioc, &sc.eng, sock_read, fd, sock_write, fd);
    return 0;
}

int send_https_request(const char *data, uint16 len) {
    int fd, err = setup_bearssl_connection(&fd);
    if (err)
        return err;
    uint16 req_len = 0;
    str_append(http_buf, &req_len, "POST " CONFIG_API_PATH " HTTP/1.1\r\nHost: " CONFIG_API_HOST "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ");
    str_append_uint(http_buf, &req_len, len);
    str_append(http_buf, &req_len, "\r\nConnection: close\r\n\r\n");
    str_append_len(http_buf, &req_len, data, len);
    if (br_sslio_write_all(&ioc, http_buf, req_len)) {
        br_sslio_close(&ioc);
        close(fd);
        return -4;
    }
    if (br_sslio_flush(&ioc)) {
        br_sslio_close(&ioc);
        close(fd);
        return -5;
    }
    br_sslio_close(&ioc);
    close(fd);
    return 0;
}

int collect_and_send(void) {
    metrics.cpu_cores = get_cores_from_sysfs();
    get_current_jiffies_and_cpu_count(&cpu_start, &metrics);
    get_network_stats(&net_rx_start, &net_tx_start);
    sleep(60);
    get_current_jiffies_and_cpu_count(&cpu_end, &metrics);
    get_network_stats(&net_rx_end, &net_tx_end);
    metrics.uptime = get_uptime();
    struct utsname un;
    if (uname(&un) == 0) {
        uint16 len = 0;
        str_append(metrics.linux_version, &len, "Linux ");
        str_append(metrics.linux_version, &len, un.release);
    } else
        memcpy(metrics.linux_version, "Linux Unknown", sizeof("Linux Unknown"));
    get_cpu_info(&metrics);
    cpu_total_diff = (cpu_end.total - cpu_start.total);
#ifndef CONFIG_SWITCH_IOWAIT_STEAL
    cpu_iowait_diff = (cpu_end.iowait - cpu_start.iowait);
#else
    cpu_iowait_diff = (cpu_end.steal - cpu_start.steal);
#endif
    cpu_work_diff = (cpu_end.work - cpu_start.work);
    if (cpu_total_diff > 0) {
        metrics.cpu_usage = 100.0 * ((double)cpu_work_diff / (double)cpu_total_diff);
        metrics.cpu_iowait = 100.0 * ((double)cpu_iowait_diff / (double)cpu_total_diff);
    } else
        metrics.cpu_usage = metrics.cpu_iowait = 0.0;
    get_memory_info(&metrics);
    get_disk_info(&metrics);
    metrics.rx_bytes = (net_rx_end - net_rx_start) / 60;
    metrics.tx_bytes = (net_tx_end - net_tx_start) / 60;
    uint16 disk_len = 0, cpu_len, linux_version_len, data_len = 0;
    str_append(disk, &disk_len, ",");
    str_append_uint(disk, &disk_len, metrics.disk_total);
    str_append(disk, &disk_len, ",");
    str_append_uint(disk, &disk_len, metrics.disk_used);
    str_append(disk, &disk_len, ";");
    disk_len = base64_encode((unsigned char *)disk, disk_len, disk_base64);
    cpu_len = base64_encode((unsigned char *)metrics.cpu_model, strlen(metrics.cpu_model), cpu_base64);
    linux_version_len = base64_encode((unsigned char *)metrics.linux_version, strlen(metrics.linux_version), linux_version_base64);
    str_append(data_buf, &data_len, "v=1.5.2&a=1&s=");
    str_append_len(data_buf, &data_len, token, sizeof(token));
    str_append(data_buf, &data_len, "&d=");
    str_append_len(data_buf, &data_len, linux_version_base64, linux_version_len);
    str_append(data_buf, &data_len, "|");
    str_append_uint(data_buf, &data_len, metrics.uptime);
    str_append(data_buf, &data_len, "|");
    str_append_len(data_buf, &data_len, cpu_base64, cpu_len);
    str_append(data_buf, &data_len, "|");
    str_append_uint(data_buf, &data_len, metrics.cpu_speed);
    str_append(data_buf, &data_len, "|");
    str_append_uint(data_buf, &data_len, metrics.cpu_cores);
    str_append(data_buf, &data_len, "|");
    str_append_percent(data_buf, &data_len, metrics.cpu_usage);
    str_append(data_buf, &data_len, "|");
    str_append_percent(data_buf, &data_len, metrics.cpu_iowait);
    str_append(data_buf, &data_len, "|");
    str_append_uint(data_buf, &data_len, metrics.ram_size);
    str_append(data_buf, &data_len, "|");
    str_append_percent(data_buf, &data_len, metrics.ram_usage);
    str_append(data_buf, &data_len, "|");
    str_append_uint(data_buf, &data_len, metrics.swap_size);
    str_append(data_buf, &data_len, "|");
    str_append_percent(data_buf, &data_len, metrics.swap_usage);
    str_append(data_buf, &data_len, "|");
    str_append_len(data_buf, &data_len, disk_base64, disk_len);
    str_append(data_buf, &data_len, "|");
    str_append_uint(data_buf, &data_len, metrics.rx_bytes);
    str_append(data_buf, &data_len, "|");
    str_append_uint(data_buf, &data_len, metrics.tx_bytes);
    str_append(data_buf, &data_len, "|");
    return send_https_request(data_buf, data_len);
}

int main(void) {
    int fd = open(CONFIG_TOKEN_PATH, O_RDONLY);
    if (fd == -1 || read(fd, token, sizeof(token)) < sizeof(token)) {
        close(fd);
        write(2, "Error reading token!\n", strlen("Error reading token!\n"));
        return 1;
    }
    close(fd);
    br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);
    br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof(iobuf), 1);
    for (;;)
        collect_and_send();
    return 0;
}