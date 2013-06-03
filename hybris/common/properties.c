/*
 * Copyright (c) 2012 Carsten Munk <carsten.munk@gmail.com>
 *               2008 The Android Open Source Project
 *               2013 Simon Busch <morphis@gravedo.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#define __USE_GNU
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <poll.h>

#define PROP_NAME_MAX 32
#define PROP_VALUE_MAX 92

#define PROP_SERVICE_NAME "property_service"

#define PROP_MSG_SETPROP 1

static const char property_service_socket[] = "/dev/socket/" PROP_SERVICE_NAME;

typedef struct
{
	unsigned cmd;
	char name[PROP_NAME_MAX];
	char value[PROP_VALUE_MAX];
} prop_msg;

static char *find_key(const char *key)
{
	FILE *f = fopen("/system/build.prop", "r");
	char buf[1024];
	char *mkey, *value;

	if (!f)
		return NULL;

	while (fgets(buf, 1024, f) != NULL) {
		if (strchr(buf, '\r'))
			*(strchr(buf, '\r')) = '\0';
		if (strchr(buf, '\n'))
			*(strchr(buf, '\n')) = '\0';

		mkey = strtok(buf, "=");

		if (!mkey)
			continue;

		value = strtok(NULL, "=");
		if (!value)
			continue;

		if (strcmp(key, mkey) == 0) {
			fclose(f);
			return strdup(value);
		}
	}

	fclose(f);
	return NULL;
}

static char *find_key_kernel_cmdline(const char *key)
{
	char cmdline[1024];
	char *ptr;
	int fd;

	fd = open("/proc/cmdline", O_RDONLY);
	if (fd >= 0) {
		int n = read(fd, cmdline, 1023);
		if (n < 0) n = 0;

		/* get rid of trailing newline, it happens */
		if (n > 0 && cmdline[n-1] == '\n') n--;

		cmdline[n] = 0;
		close(fd);
	} else {
		cmdline[0] = 0;
	}

	ptr = cmdline;

	while (ptr && *ptr) {
		char *x = strchr(ptr, ' ');
		if (x != 0) *x++ = 0;

		char *name = ptr;
		ptr = x;

		char *value = strchr(name, '=');
		int name_len = strlen(name);

		if (value == 0) continue;
		*value++ = 0;
		if (name_len == 0) continue;

		if (!strncmp(name, "androidboot.", 12) && name_len > 12) {
			const char *boot_prop_name = name + 12;
			char prop[PROP_NAME_MAX];
			snprintf(prop, sizeof(prop), "ro.%s", boot_prop_name);
			if (strcmp(prop, key) == 0)
				return strdup(value);
		}
	}

	return NULL;
}

int property_get(const char *key, char *value, const char *default_value)
{
	char *ret = NULL; 

	//printf("property_get: %s\n", key);

	/* default */
	ret = find_key(key);

#if 0
 if (strcmp(key, "ro.kernel.qemu") == 0)
 {
    ret = "0";
 }  
 else if (strcmp(key, "ro.hardware") == 0)
 { 
    ret = "tenderloin";
 } 
 else if (strcmp(key, "ro.product.board") == 0)
 {
    ret = "tenderloin";
 }
 else if (strcmp(key, "ro.board.platform") == 0)
 { 
    ret = "msm8660";
 }
 else if (strcmp(key, "ro.arch") == 0)
 {
    ret = "armeabi";
 }
 else if (strcmp(key, "debug.composition.type") == 0)
 {
    ret = "c2d"; 
 }
 else if (strcmp(key, "debug.sf.hw") == 0)
 {
   ret = "1";
 }
 else if (strcmp(key, "debug.gr.numframebuffers") == 0)
 { 
   ret = "1"; 
 }  
#endif
	if (ret == NULL) {
		/* Property might be available via /proc/cmdline */
		ret = find_key_kernel_cmdline(key);
	}

	if (ret) {
		printf("found %s for %s\n", key, ret);
		strcpy(value, ret);
		free(ret);
		return strlen(value);
	} else if (default_value != NULL) {
		strcpy(value, default_value);
		return strlen(value);
	}

	return 0;
}

static int send_prop_msg(prop_msg *msg)
{
	struct pollfd pollfds[1];
	union {
		struct sockaddr_un addr;
		struct sockaddr addr_g;
	} addr;
	socklen_t alen;
	size_t namelen;
	int s;
	int r;
	int result = -1;

	s = socket(AF_LOCAL, SOCK_STREAM, 0);
	if(s < 0) {
		return result;
	}

	memset(&addr, 0, sizeof(addr));
	namelen = strlen(property_service_socket);
	strlcpy(addr.addr.sun_path, property_service_socket, sizeof addr.addr.sun_path);
	addr.addr.sun_family = AF_LOCAL;
	alen = namelen + offsetof(struct sockaddr_un, sun_path) + 1;

	if(TEMP_FAILURE_RETRY(connect(s, &addr.addr_g, alen) < 0)) {
		close(s);
		return result;
	}

	r = TEMP_FAILURE_RETRY(send(s, msg, sizeof(prop_msg), 0));

	if(r == sizeof(prop_msg)) {
		// We successfully wrote to the property server but now we
		// wait for the property server to finish its work.  It
		// acknowledges its completion by closing the socket so we
		// poll here (on nothing), waiting for the socket to close.
		// If you 'adb shell setprop foo bar' you'll see the POLLHUP
		// once the socket closes.  Out of paranoia we cap our poll
		// at 250 ms.
		pollfds[0].fd = s;
		pollfds[0].events = 0;
		r = TEMP_FAILURE_RETRY(poll(pollfds, 1, 250 /* ms */));
		if (r == 1 && (pollfds[0].revents & POLLHUP) != 0) {
			result = 0;
		} else {
			// Ignore the timeout and treat it like a success anyway.
			// The init process is single-threaded and its property
			// service is sometimes slow to respond (perhaps it's off
			// starting a child process or something) and thus this
			// times out and the caller thinks it failed, even though
			// it's still getting around to it.  So we fake it here,
			// mostly for ctl.* properties, but we do try and wait 250
			// ms so callers who do read-after-write can reliably see
			// what they've written.  Most of the time.
			// TODO: fix the system properties design.
			result = 0;
		}
	}

	close(s);
	return result;
}

int property_set(const char *key, const char *value)
{
	int err;
	int tries = 0;
	int update_seen = 0;
	prop_msg msg;

	if(key == 0) return -1;
	if(value == 0) value = "";
	if(strlen(key) >= PROP_NAME_MAX) return -1;
	if(strlen(value) >= PROP_VALUE_MAX) return -1;

	memset(&msg, 0, sizeof msg);
	msg.cmd = PROP_MSG_SETPROP;
	strlcpy(msg.name, key, sizeof msg.name);
	strlcpy(msg.value, value, sizeof msg.value);

	err = send_prop_msg(&msg);
	if(err < 0) {
		return err;
	}

	return 0;
}

// vim:ts=4:sw=4:noexpandtab
