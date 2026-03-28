/*
mod_doscontrol for Apache 2.4
Version: v1.0.0 [2026.0328]
Description: Advanced DOS/spam detection module for Apache 2.4 with
configurable responses, logging, and per-URI/VirtualHost settings.

Copyright (c) 2026 Kamil BuriXon Burek

Based on mod_evasive by Jonathan A. Zdziarski
Copyright (c) 2002 Jonathan A. Zdziarski

This module is derived from mod_evasive and extends its functionality with:
- configurable response code (403 / 429)
- configurable logging and cache system
- support for configuration inside VirtualHost
- per-URI configuration
- additional improvements and Apache 2.4 adaptation

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 3
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

See the LICENSE file for details.
See the NOTICE file for attribution and additional information.
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

#include "apr_strings.h"
#include "apr_time.h"
#include "apr_file_io.h"
#include "apr_lib.h"
#include "apr_tables.h"

#ifndef HTTP_TOO_MANY_REQUESTS
#warning "HTTP_TOO_MANY_REQUESTS not defined. Setting up..."
#define HTTP_TOO_MANY_REQUESTS 429
#endif

module AP_MODULE_DECLARE_DATA doscontrol_module;

// BEGIN DEFAULTS
#define MAILER					"/bin/mail %s"
#define DEFAULT_HTTP_RESPONSE	403
#define DEFAULT_HASH_TBL_SIZE	3097ul
#define DEFAULT_PAGE_COUNT		10
#define DEFAULT_SITE_COUNT		50
#define DEFAULT_PAGE_INTERVAL	1
#define DEFAULT_SITE_INTERVAL	1
#define DEFAULT_BLOCKING_PERIOD	30
#define DEFAULT_BLOCK_DELAY		0
#define DEFAULT_MAIN_LOG		"/var/log/apache2/mod_doscontrol.log"
#define DEFAULT_CACHE_DIR		"/tmp/mod_doscontrol"
#define LOG_TAG					"mod_doscontrol"
// END DEFAULTS

// BEGIN NTT 
// This part is mostly/entirely from the original mod_evasive20.c by J. Zdziarski
enum { ntt_num_primes = 28 };

static unsigned long ntt_prime_list[ntt_num_primes] =
{
	53ul,         97ul,         193ul,       389ul,       769ul,
	1543ul,       3079ul,       6151ul,      12289ul,     24593ul,
	49157ul,      98317ul,      196613ul,    393241ul,    786433ul,
	1572869ul,    3145739ul,    6291469ul,   12582917ul,  25165843ul,
	50331653ul,   100663319ul,  201326611ul, 402653189ul, 805306457ul,
	1610612741ul, 3221225473ul, 4294967291ul
};

struct ntt {
	long size;
	long items;
	struct ntt_node **tbl;
};

struct ntt_node {
	char *key;
	time_t timestamp;
	long count;
	struct ntt_node *next;
};

struct ntt_c {
	long iter_index;
	struct ntt_node *iter_next;
};
// END NTT

// GLOBALS, HELPERS, FUNCIONS
struct dd_pattern_node {
	char *pattern;
	struct dd_pattern_node *next;
};

typedef struct dos_server_config {
	apr_pool_t *pool;

	unsigned long hash_table_size;
	int page_count;
	int page_interval;
	int site_count;
	int site_interval;
	int blocking_period;
	int block_delay_ms;
	int block_delay_ms_set;
	int response_code;

	int hash_table_size_set;
	int page_count_set;
	int page_interval_set;
	int site_count_set;
	int site_interval_set;
	int blocking_period_set;
	int response_code_set;

	char *email_notify;
	char *main_log;
	char *cache_dir;
	char *system_command;

	int email_notify_set;
	int main_log_set;
	int cache_dir_set;
	int system_command_set;

	struct dd_pattern_node *ip_whitelist_patterns;
	struct dd_pattern_node *ua_whitelist_patterns;
	struct dd_pattern_node *custom_level_patterns[10];
	int custom_level_counts[10];
	int custom_level_count_set[10];

	struct ntt *hit_list;
	int hit_list_cleanup_registered;
} dos_server_config;

static const char *whitelist(cmd_parms *cmd, void *dconfig, const char *ip);
static const char *get_whitelist_ip(cmd_parms *cmd, void *dconfig, const char *value);
static const char *get_whitelist_ua(cmd_parms *cmd, void *dconfig, const char *value);
static const char *get_custom_level_count(cmd_parms *cmd, void *dconfig, const char *value);
static const char *get_custom_level_add(cmd_parms *cmd, void *dconfig, const char *value);
static int access_checker(request_rec *r);
static struct ntt_node *c_ntt_next(struct ntt *ntt, struct ntt_c *c);
static long dd_get_long_value(const char *value, long fallback);

static dos_server_config *dd_get_server_config(server_rec *s)
{
	if (s == NULL) {
		return NULL;
	}
	return ap_get_module_config(s->module_config, &doscontrol_module);
}
// get config settings / connection parameters
static dos_server_config *dd_get_request_config(request_rec *r)
{
	if (r == NULL || r->server == NULL) {
		return NULL;
	}
	return dd_get_server_config(r->server);
}
// delay generated when blocking
static const char *get_block_delay(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);
	long n = dd_get_long_value(value, 0);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (n < 0) {
		n = 0;
	}

	cfg->block_delay_ms = (int)n;
	cfg->block_delay_ms_set = 1;

	return NULL;
}
// server/virtualhost names
static const char *dd_server_name(request_rec *r)
{
	if (r && r->server && r->server->server_hostname && *r->server->server_hostname) {
		return r->server->server_hostname;
	}
	return "default";
}
// client IP
static const char *dd_client_ip(request_rec *r)
{
	if (r && r->useragent_ip && *r->useragent_ip) {
		return r->useragent_ip;
	}
	/*
		useragent_ip generated by mod_remoteip

		 unlike remote_ip/client_ip, it returns an address including http headers (e.g. X-Forwarded-For with proxy)
		 mod_remoteip is used by virtually every Apache 2.4 instance these days. It's often loaded by default.
		 This eliminates the need to manually parse headers when a client connects via proxy.
	*/
	if (r && r->connection && r->connection->client_ip && *r->connection->client_ip) {
		return r->connection->client_ip;
	}
	// fallback in case of missing mod_remoteip (missing useragent_ip)
	return "unknown";
}
// requested URI
static const char *dd_request_uri(request_rec *r)
{
	if (r && r->uri && *r->uri) {
		return r->uri;
	}
	return "/";
}
// client User-Agent (needed to create and check DOSWhitelistUA)
static const char *dd_request_user_agent(request_rec *r)
{
	const char *ua = NULL;

	if (r != NULL) {
		ua = apr_table_get(r->headers_in, "User-Agent");
	}

	if (ua != NULL && *ua != '\0') {
		return ua;
	}

	return "";
}
// setting the response code when blocking
static const char *dd_status_text(int code)
{
	if (code == HTTP_TOO_MANY_REQUESTS) {
		return "Too Many Requests";
	}
	return "Forbidden";
}
// timestamp formay - YYYY-MM-DD HH:MM:SS
static void dd_format_timestamp(apr_time_t now, char *buf, apr_size_t len)
{
	apr_time_exp_t xt;

	apr_time_exp_lt(&xt, now);
	apr_snprintf(buf, len,
		"%04d-%02d-%02d %02d:%02d:%02d",
		xt.tm_year + 1900,
		xt.tm_mon + 1,
		xt.tm_mday,
		xt.tm_hour,
		xt.tm_min,
		xt.tm_sec);
}
// creating/checking cache dir
static void dd_ensure_directory(const char *dir)
{
	char tmp[1024];
	char *p;
	struct stat st;

	if (dir == NULL || *dir == '\0') {
		return;
	}

	apr_cpystrn(tmp, dir, sizeof(tmp));

	for (p = tmp + 1; *p; ++p) {
		if (*p == '/') {
			*p = '\0';
			if (stat(tmp, &st) != 0) {
				if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
					return;
				}
			}
			*p = '/';
		}
	}

	if (stat(tmp, &st) != 0) {
		if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
			return;
		}
	}
}
// append subsequent logs
static void dd_append_line_to_file(const char *path, const char *line)
{
	FILE *f;

	if (path == NULL || *path == '\0' || line == NULL || *line == '\0') {
		return;
	}

	f = fopen(path, "a");
	if (f == NULL) {
		return;
	}

	fprintf(f, "%s\n", line);
	fclose(f);
}
// log format and recording
static void dd_log_main(request_rec *r, const dos_server_config *cfg, const char *event, const char *detail)
{
	char ts[64];
	apr_time_t now;
	const char *path;
	const char *line;

	if (r == NULL) {
		return;
	}

	now = apr_time_now();
	dd_format_timestamp(now, ts, sizeof(ts));

	path = (cfg != NULL && cfg->main_log != NULL && *cfg->main_log != '\0')
		? cfg->main_log
		: DEFAULT_MAIN_LOG;

	line = apr_psprintf(r->pool,
		"[%s] [%s]; server=\"%s\"; client=\"%s\"; uri=\"%s\"; %s",
		ts,
		event != NULL ? event : "unknown",
		dd_server_name(r),
		dd_client_ip(r),
		dd_request_uri(r),
		detail != NULL ? detail : "");
		// I found this format quite consistent and readable

	dd_append_line_to_file(path, line);
	ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "%s", line);
}

static char *dd_sanitize_token(apr_pool_t *p, const char *src)
{
	char *out;
	char *d;

	if (src == NULL || *src == '\0') {
		return apr_pstrdup(p, "unknown");
	}

	out = apr_pstrdup(p, src);
	for (d = out; *d; ++d) {
		if (!apr_isalnum(*d)) {
			*d = '_';
		}
	}

	return out;
}
// manage atack cache
static void dd_write_attack_cache(request_rec *r, const dos_server_config *cfg, const char *ip)
{
	char filename[1024];
	char *safe_ip;
	const char *dir;
	struct stat st;
	FILE *file;

	if (r == NULL || ip == NULL) {
		return;
	}

	dir = (cfg != NULL && cfg->cache_dir != NULL && *cfg->cache_dir != '\0')
		? cfg->cache_dir
		: DEFAULT_CACHE_DIR;

	dd_ensure_directory(dir);

	safe_ip = dd_sanitize_token(r->pool, ip);
	apr_snprintf(filename, sizeof(filename), "%s/dos-%s", dir, safe_ip);

	if (stat(filename, &st) != 0) {
		file = fopen(filename, "w");
		if (file != NULL) {
			fprintf(file, "%d\n", (int)getpid());
			fprintf(file, "%ld\n", (long)time(NULL));
			fclose(file);
		}

		// recording in logs
		dd_log_main(r, cfg, "CACHE",
			apr_psprintf(r->pool,
				"action=\"create\" file=\"%s\" pid=%d",
				filename,
				(int)getpid()));
	}
	else {
		file = fopen(filename, "a");
		if (file != NULL) {
			fprintf(file, "%ld\n", (long)time(NULL));
			fclose(file);
		}
	}
}
// helper : SysyemCommand
static char *dd_expand_command(apr_pool_t *p, const char *tmpl, const char *ip)
{
	const char *cur;
	const char *chunk_start;
	char *result;

	if (tmpl == NULL || *tmpl == '\0') {
		return NULL;
	}

	result = apr_pstrdup(p, "");
	cur = tmpl;
	chunk_start = tmpl;

	while (*cur) {
		if (cur[0] == '%' && cur[1] == 's') {
			result = apr_pstrcat(p,
				result,
				apr_pstrndup(p, chunk_start, cur - chunk_start),
				ip,
				NULL);
			cur += 2;
			chunk_start = cur;
			continue;
		}

		if (cur[0] == '%' && cur[1] == '%') {
			result = apr_pstrcat(p,
				result,
				apr_pstrndup(p, chunk_start, cur - chunk_start),
				"%",
				NULL);
			cur += 2;
			chunk_start = cur;
			continue;
		}

		++cur;
	}

	result = apr_pstrcat(p, result, chunk_start, NULL);
	return result;
}

static int dd_char_eq(int a, int b, int ignore_case)
{
	if (ignore_case) {
		return tolower((unsigned char)a) == tolower((unsigned char)b);
	}
	return a == b;
}
// pattern/wordcard matching for URI/User-Agent
static int dd_glob_match(const char *pattern, const char *text, int ignore_case)
{
	const char *p = pattern;
	const char *t = text;
	const char *star = NULL;
	const char *star_text = NULL;

	if (pattern == NULL || text == NULL) {
		return 0;
	}

	// * for unknown length unknown strings
	while (*t) {
		if (*p == '*') {
			star = p++;
			star_text = t;
			continue;
		}

		// ? for a single unknown symbol
		if (*p == '?' || dd_char_eq((unsigned char)*p, (unsigned char)*t, ignore_case)) {
			++p;
			++t;
			continue;
		}

		if (star != NULL) {
			p = star + 1;
			t = ++star_text;
			continue;
		}

		return 0;
	}

	while (*p == '*') {
		++p;
	}

	return *p == '\0';
}
// matching for URI
static int dd_uri_pattern_matches(const char *pattern, const char *uri)
{
	size_t plen;

	if (pattern == NULL || uri == NULL) {
		return 0;
	}

	plen = strlen(pattern);

	if (plen >= 2 && pattern[plen - 2] == '/' && pattern[plen - 1] == '*') {
		size_t base_len = plen - 2;

		if (strncmp(pattern, uri, base_len) == 0) {
			if (uri[base_len] == '\0' || uri[base_len] == '/') {
				return 1;
			}
		}

		return 0;
	}

	return dd_glob_match(pattern, uri, 0);
}
// pattern/wordcard matching for CIDR IP ranges
static int dd_ipv4_cidr_match(const char *pattern, const char *ip)
{
	char buf[128];
	char *slash;
	struct in_addr ip_addr;
	struct in_addr net_addr;
	unsigned long prefix;
	uint32_t mask;
	uint32_t ip_u;
	uint32_t net_u;

	if (pattern == NULL || ip == NULL) {
		return 0;
	}

	if (strlen(pattern) >= sizeof(buf)) {
		return 0;
	}

	apr_cpystrn(buf, pattern, sizeof(buf));
	slash = strchr(buf, '/');
	if (slash == NULL) {
		return 0;
	}

	*slash = '\0';
	++slash;

	if (inet_pton(AF_INET, ip, &ip_addr) != 1) {
		return 0;
	}

	if (inet_pton(AF_INET, buf, &net_addr) != 1) {
		return 0;
	}

	prefix = strtoul(slash, NULL, 10);
	if (prefix > 32) {
		return 0;
	}

	if (prefix == 0) {
		mask = 0;
	}
	else {
		mask = 0xFFFFFFFFu << (32 - prefix);
	}

	ip_u = ntohl(ip_addr.s_addr);
	net_u = ntohl(net_addr.s_addr);

	return (ip_u & mask) == (net_u & mask);
}
// matching for URI
static int dd_ip_pattern_matches(const char *pattern, const char *ip)
{
	if (pattern == NULL || ip == NULL) {
		return 0;
	}

	if (strchr(pattern, '*') != NULL || strchr(pattern, '?') != NULL) {
		return dd_glob_match(pattern, ip, 0);
	}

	if (strchr(pattern, '/') != NULL) {
		return dd_ipv4_cidr_match(pattern, ip);
	}

	return strcmp(pattern, ip) == 0;
}

static int dd_ua_pattern_matches(const char *pattern, const char *ua)
{
	if (pattern == NULL || ua == NULL) {
		return 0;
	}

	return dd_glob_match(pattern, ua, 1);
}
// adding IP to the list
static const char *dd_add_pattern_to_list(apr_pool_t *p, struct dd_pattern_node **list, const char *pattern)
{
	struct dd_pattern_node *node;
	struct dd_pattern_node **tail;

	if (pattern == NULL || *pattern == '\0') {
		return NULL;
	}

	node = apr_pcalloc(p, sizeof(*node));
	if (node == NULL) {
		return "Out of memory";
	}

	node->pattern = apr_pstrdup(p, pattern);
	if (node->pattern == NULL) {
		return "Out of memory";
	}

	node->next = NULL;

	tail = list;
	while (*tail != NULL) {
		tail = &(*tail)->next;
	}
	*tail = node;

	return NULL;
}

static struct dd_pattern_node *dd_clone_pattern_list(apr_pool_t *p, const struct dd_pattern_node *src)
{
	struct dd_pattern_node *head = NULL;
	struct dd_pattern_node **tail = &head;

	while (src != NULL) {
		struct dd_pattern_node *node = apr_pcalloc(p, sizeof(*node));
		if (node == NULL) {
			return head;
		}

		node->pattern = apr_pstrdup(p, src->pattern != NULL ? src->pattern : "");
		node->next = NULL;

		*tail = node;
		tail = &node->next;
		src = src->next;
	}

	return head;
}

static struct dd_pattern_node *dd_merge_pattern_lists(apr_pool_t *p, const struct dd_pattern_node *parent, const struct dd_pattern_node *child)
{
	struct dd_pattern_node *head = dd_clone_pattern_list(p, parent);
	struct dd_pattern_node **tail = &head;

	while (*tail != NULL) {
		tail = &(*tail)->next;
	}

	while (child != NULL) {
		struct dd_pattern_node *node = apr_pcalloc(p, sizeof(*node));
		if (node == NULL) {
			return head;
		}

		node->pattern = apr_pstrdup(p, child->pattern != NULL ? child->pattern : "");
		node->next = NULL;

		*tail = node;
		tail = &node->next;
		child = child->next;
	}

	return head;
}
//  whitelist configuration (IP)
static int dd_is_whitelisted_ip(const dos_server_config *cfg, const char *ip)
{
	struct dd_pattern_node *node;

	if (cfg == NULL || ip == NULL || *ip == '\0') {
		return 0;
	}

	for (node = cfg->ip_whitelist_patterns; node != NULL; node = node->next) {
		if (dd_ip_pattern_matches(node->pattern, ip)) {
			return 1;
		}
	}

	return 0;
}
//  whitelist configuration (User-Agent)
static int dd_is_whitelisted_ua(const dos_server_config *cfg, const char *ua)
{
	struct dd_pattern_node *node;

	if (cfg == NULL || ua == NULL || *ua == '\0') {
		return 0;
	}

	for (node = cfg->ua_whitelist_patterns; node != NULL; node = node->next) {
		if (dd_ua_pattern_matches(node->pattern, ua)) {
			return 1;
		}
	}

	return 0;
}
// get CustomLevel from config
static void dd_resolve_custom_limits(const dos_server_config *cfg, const char *uri, int *page_limit, int *site_limit)
{
	size_t best_specificity = 0;
	int best_level = -1;
	int i;

	if (page_limit != NULL) {
		*page_limit = (cfg != NULL) ? cfg->page_count : DEFAULT_PAGE_COUNT;
	}
	if (site_limit != NULL) {
		*site_limit = (cfg != NULL) ? cfg->site_count : DEFAULT_SITE_COUNT;
	}

	if (cfg == NULL || uri == NULL || *uri == '\0') {
		return;
	}

	for (i = 0; i < 10; ++i) {
		struct dd_pattern_node *node;

		if (cfg->custom_level_counts[i] <= 0) {
			continue;
		}

		for (node = cfg->custom_level_patterns[i]; node != NULL; node = node->next) {
			if (dd_uri_pattern_matches(node->pattern, uri)) {
				size_t spec = strlen(node->pattern);

				if (best_level < 0 || spec > best_specificity || (spec == best_specificity && i < best_level)) {
					best_level = i;
					best_specificity = spec;
					if (page_limit != NULL) {
						*page_limit = cfg->custom_level_counts[i];
					}
					if (site_limit != NULL) {
						*site_limit = cfg->custom_level_counts[i];
					}
				}
				break;
			}
		}
	}
}
// NTT stuff
static struct ntt_node *ntt_node_create(const char *key)
{
	char *node_key;
	struct ntt_node *node;

	node = (struct ntt_node *)malloc(sizeof(struct ntt_node));
	if (node == NULL) {
		return NULL;
	}

	node_key = strdup(key);
	if (node_key == NULL) {
		free(node);
		return NULL;
	}

	node->key = node_key;
	node->timestamp = time(NULL);
	node->count = 0;
	node->next = NULL;
	return node;
}
// NTT stuff
long ntt_hashcode(struct ntt *ntt, const char *key)
{
	unsigned long val = 0;

	for (; *key; ++key) {
		val = 5 * val + (unsigned char)*key;
	}

	return (long)(val % ntt->size);
}
// NTT stuff
struct ntt *ntt_create(long size)
{
	long i = 0;
	struct ntt *ntt = (struct ntt *)malloc(sizeof(struct ntt));

	if (ntt == NULL) {
		return NULL;
	}

	while (i < ntt_num_primes - 1 && ntt_prime_list[i] < size) {
		i++;
	}

	ntt->size = ntt_prime_list[i];
	ntt->items = 0;
	ntt->tbl = (struct ntt_node **)calloc((size_t)ntt->size, sizeof(struct ntt_node *));
	if (ntt->tbl == NULL) {
		free(ntt);
		return NULL;
	}

	return ntt;
}
// NTT stuff
struct ntt_node *ntt_find(struct ntt *ntt, const char *key)
{
	long hash_code;
	struct ntt_node *node;

	if (ntt == NULL) {
		return NULL;
	}

	hash_code = ntt_hashcode(ntt, key);
	node = ntt->tbl[hash_code];

	while (node != NULL) {
		if (strcmp(key, node->key) == 0) {
			return node;
		}
		node = node->next;
	}

	return NULL;
}
// NTT stuff
struct ntt_node *ntt_insert(struct ntt *ntt, const char *key, time_t timestamp)
{
	long hash_code;
	struct ntt_node *parent;
	struct ntt_node *node;
	struct ntt_node *new_node = NULL;

	if (ntt == NULL) {
		return NULL;
	}

	hash_code = ntt_hashcode(ntt, key);
	parent = NULL;
	node = ntt->tbl[hash_code];

	while (node != NULL) {
		if (strcmp(key, node->key) == 0) {
			new_node = node;
			break;
		}

		parent = node;
		node = node->next;
	}

	if (new_node != NULL) {
		new_node->timestamp = timestamp;
		new_node->count = 0;
		return new_node;
	}

	new_node = ntt_node_create(key);
	if (new_node == NULL) {
		return NULL;
	}

	new_node->timestamp = timestamp;
	new_node->count = 0;
	ntt->items++;

	if (parent != NULL) {
		parent->next = new_node;
		return new_node;
	}

	ntt->tbl[hash_code] = new_node;
	return new_node;
}
// NTT stuff
int ntt_delete(struct ntt *ntt, const char *key)
{
	long hash_code;
	struct ntt_node *parent = NULL;
	struct ntt_node *node;
	struct ntt_node *del_node = NULL;

	if (ntt == NULL) {
		return -1;
	}

	hash_code = ntt_hashcode(ntt, key);
	node = ntt->tbl[hash_code];

	while (node != NULL) {
		if (strcmp(key, node->key) == 0) {
			del_node = node;
			break;
		}

		parent = node;
		node = node->next;
	}

	if (del_node != NULL) {
		if (parent != NULL) {
			parent->next = del_node->next;
		}
		else {
			ntt->tbl[hash_code] = del_node->next;
		}

		free(del_node->key);
		free(del_node);
		ntt->items--;

		return 0;
	}

	return -5;
}
// NTT stuff
struct ntt_node *c_ntt_first(struct ntt *ntt, struct ntt_c *c)
{
	c->iter_index = 0;
	c->iter_next = NULL;
	return c_ntt_next(ntt, c);
}

struct ntt_node *c_ntt_next(struct ntt *ntt, struct ntt_c *c)
{
	long index;
	struct ntt_node *node = c->iter_next;

	if (ntt == NULL) {
		return NULL;
	}

	if (node != NULL) {
		c->iter_next = node->next;
		return node;
	}

	while (c->iter_index < ntt->size) {
		index = c->iter_index++;
		if (ntt->tbl[index] != NULL) {
			c->iter_next = ntt->tbl[index]->next;
			return ntt->tbl[index];
		}
	}

	return NULL;
}
// NTT stuff
int ntt_destroy(struct ntt *ntt)
{
	struct ntt_node *node, *next;
	struct ntt_c c;

	if (ntt == NULL) {
		return -1;
	}

	node = c_ntt_first(ntt, &c);
	while (node != NULL) {
		next = c_ntt_next(ntt, &c);
		ntt_delete(ntt, node->key);
		node = next;
	}

	free(ntt->tbl);
	free(ntt);

	return 0;
}
// APR stuff
static apr_status_t dd_destroy_server_state(void *data)
{
	dos_server_config *cfg = (dos_server_config *)data;

	if (cfg != NULL && cfg->hit_list != NULL) {
		ntt_destroy(cfg->hit_list);
		cfg->hit_list = NULL;
	}

	return APR_SUCCESS;
}
//  load default data if not found in config
//  prepare runtime configuration from config
static void *create_server_config(apr_pool_t *p, server_rec *s)
{
	dos_server_config *cfg = apr_pcalloc(p, sizeof(*cfg));
	int i;

	(void)s;

	if (cfg == NULL) {
		return NULL;
	}

	cfg->pool = p;

	cfg->hash_table_size = DEFAULT_HASH_TBL_SIZE;
	cfg->page_count = DEFAULT_PAGE_COUNT;
	cfg->page_interval = DEFAULT_PAGE_INTERVAL;
	cfg->site_count = DEFAULT_SITE_COUNT;
	cfg->site_interval = DEFAULT_SITE_INTERVAL;
	cfg->blocking_period = DEFAULT_BLOCKING_PERIOD;
	cfg->block_delay_ms = DEFAULT_BLOCK_DELAY;
	cfg->response_code = DEFAULT_HTTP_RESPONSE;

	cfg->hash_table_size_set = 0;
	cfg->page_count_set = 0;
	cfg->page_interval_set = 0;
	cfg->site_count_set = 0;
	cfg->site_interval_set = 0;
cfg->blocking_period_set = 0;
	cfg->block_delay_ms_set = 0;
	cfg->response_code_set = 0;

	cfg->email_notify = NULL;
	cfg->main_log = NULL;
	cfg->cache_dir = NULL;
	cfg->system_command = NULL;

	cfg->email_notify_set = 0;
	cfg->main_log_set = 0;
	cfg->cache_dir_set = 0;
	cfg->system_command_set = 0;

	cfg->ip_whitelist_patterns = NULL;
	cfg->ua_whitelist_patterns = NULL;

	for (i = 0; i < 10; ++i) {
		cfg->custom_level_patterns[i] = NULL;
		cfg->custom_level_counts[i] = 0;
		cfg->custom_level_count_set[i] = 0;
	}

	cfg->hit_list = NULL;
	cfg->hit_list_cleanup_registered = 0;

	return cfg;
}
// connect configurations (default + RSRC + VirtualHost)
static void *merge_server_config(apr_pool_t *p, void *basev, void *addv)
{
	dos_server_config *base = (dos_server_config *)basev;
	dos_server_config *add = (dos_server_config *)addv;
	dos_server_config *cfg = apr_pcalloc(p, sizeof(*cfg));
	int i;

	if (cfg == NULL) {
		return NULL;
	}

	cfg->pool = p;

	cfg->hash_table_size = (add != NULL && add->hash_table_size_set) ? add->hash_table_size : base->hash_table_size;
	cfg->page_count = (add != NULL && add->page_count_set) ? add->page_count : base->page_count;
	cfg->page_interval = (add != NULL && add->page_interval_set) ? add->page_interval : base->page_interval;
	cfg->site_count = (add != NULL && add->site_count_set) ? add->site_count : base->site_count;
	cfg->site_interval = (add != NULL && add->site_interval_set) ? add->site_interval : base->site_interval;
	cfg->blocking_period = (add != NULL && add->blocking_period_set) ? add->blocking_period : base->blocking_period;
	cfg->block_delay_ms = (add != NULL && add->block_delay_ms_set) ? add->block_delay_ms : base->block_delay_ms;
	cfg->block_delay_ms_set = (base != NULL && base->block_delay_ms_set) || (add != NULL && add->block_delay_ms_set);
	cfg->response_code = (add != NULL && add->response_code_set) ? add->response_code : base->response_code;

	cfg->hash_table_size_set = (base != NULL && base->hash_table_size_set) || (add != NULL && add->hash_table_size_set);
	cfg->page_count_set = (base != NULL && base->page_count_set) || (add != NULL && add->page_count_set);
	cfg->page_interval_set = (base != NULL && base->page_interval_set) || (add != NULL && add->page_interval_set);
	cfg->site_count_set = (base != NULL && base->site_count_set) || (add != NULL && add->site_count_set);
	cfg->site_interval_set = (base != NULL && base->site_interval_set) || (add != NULL && add->site_interval_set);
	cfg->blocking_period_set = (base != NULL && base->blocking_period_set) || (add != NULL && add->blocking_period_set);
	cfg->response_code_set = (base != NULL && base->response_code_set) || (add != NULL && add->response_code_set);

	cfg->email_notify = (add != NULL && add->email_notify_set) ? apr_pstrdup(p, add->email_notify)
		: (base != NULL ? apr_pstrdup(p, base->email_notify) : NULL);
	cfg->main_log = (add != NULL && add->main_log_set) ? apr_pstrdup(p, add->main_log)
		: (base != NULL ? apr_pstrdup(p, base->main_log) : NULL);
	cfg->cache_dir = (add != NULL && add->cache_dir_set) ? apr_pstrdup(p, add->cache_dir)
		: (base != NULL ? apr_pstrdup(p, base->cache_dir) : NULL);
	cfg->system_command = (add != NULL && add->system_command_set) ? apr_pstrdup(p, add->system_command)
		: (base != NULL ? apr_pstrdup(p, base->system_command) : NULL);

	cfg->email_notify_set = (cfg->email_notify != NULL);
	cfg->main_log_set = (cfg->main_log != NULL);
	cfg->cache_dir_set = (cfg->cache_dir != NULL);
	cfg->system_command_set = (cfg->system_command != NULL);

	cfg->ip_whitelist_patterns = dd_merge_pattern_lists(p,
		base != NULL ? base->ip_whitelist_patterns : NULL,
		add != NULL ? add->ip_whitelist_patterns : NULL);

	cfg->ua_whitelist_patterns = dd_merge_pattern_lists(p,
		base != NULL ? base->ua_whitelist_patterns : NULL,
		add != NULL ? add->ua_whitelist_patterns : NULL);

	for (i = 0; i < 10; ++i) {
		cfg->custom_level_patterns[i] = dd_merge_pattern_lists(p,
			base != NULL ? base->custom_level_patterns[i] : NULL,
			add != NULL ? add->custom_level_patterns[i] : NULL);

		cfg->custom_level_counts[i] = (add != NULL && add->custom_level_count_set[i])
			? add->custom_level_counts[i]
			: (base != NULL ? base->custom_level_counts[i] : 0);

		cfg->custom_level_count_set[i] = (base != NULL && base->custom_level_count_set[i])
			|| (add != NULL && add->custom_level_count_set[i]);
	}

	cfg->hit_list = NULL;
	cfg->hit_list_cleanup_registered = 0;

	return cfg;
}
// BEGIN RSRC READ/PARSE
static long dd_get_long_value(const char *value, long fallback)
{
	char *endptr = NULL;
	long n;

	if (value == NULL || *value == '\0') {
		return fallback;
	}

	errno = 0;
	n = strtol(value, &endptr, 0);

	if (errno != 0 || endptr == value) {
		return fallback;
	}

	return n;
}

static const char *get_hash_tbl_size(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);
	long n = dd_get_long_value(value, -1);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (n <= 0) {
		cfg->hash_table_size = DEFAULT_HASH_TBL_SIZE;
		cfg->hash_table_size_set = 1;
	}
	else {
		cfg->hash_table_size = (unsigned long)n;
		cfg->hash_table_size_set = 1;
	}

	return NULL;
}

static const char *get_page_count(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);
	long n = dd_get_long_value(value, -1);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (n <= 0) {
		cfg->page_count = DEFAULT_PAGE_COUNT;
	}
	else {
		cfg->page_count = (int)n;
	}
	cfg->page_count_set = 1;

	return NULL;
}

static const char *get_site_count(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);
	long n = dd_get_long_value(value, -1);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (n <= 0) {
		cfg->site_count = DEFAULT_SITE_COUNT;
	}
	else {
		cfg->site_count = (int)n;
	}
	cfg->site_count_set = 1;

	return NULL;
}

static const char *get_page_interval(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);
	long n = dd_get_long_value(value, -1);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (n <= 0) {
		cfg->page_interval = DEFAULT_PAGE_INTERVAL;
	}
	else {
		cfg->page_interval = (int)n;
	}
	cfg->page_interval_set = 1;

	return NULL;
}

static const char *get_site_interval(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);
	long n = dd_get_long_value(value, -1);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (n <= 0) {
		cfg->site_interval = DEFAULT_SITE_INTERVAL;
	}
	else {
		cfg->site_interval = (int)n;
	}
	cfg->site_interval_set = 1;

	return NULL;
}

static const char *get_blocking_period(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);
	long n = dd_get_long_value(value, -1);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (n <= 0) {
		cfg->blocking_period = DEFAULT_BLOCKING_PERIOD;
	}
	else {
		cfg->blocking_period = (int)n;
	}
	cfg->blocking_period_set = 1;

	return NULL;
}

static const char *get_response_code(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);
	long n = dd_get_long_value(value, -1);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (n != HTTP_FORBIDDEN && n != HTTP_TOO_MANY_REQUESTS) {
		return "DOSResponseCode accepts only 403 or 429";
	}

	cfg->response_code = (int)n;
	cfg->response_code_set = 1;

	return NULL;
}

static const char *get_main_log(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (value != NULL && value[0] != '\0') {
		cfg->main_log = apr_pstrdup(cmd->pool, value);
		cfg->main_log_set = 1;
	}

	return NULL;
}

static const char *get_cache_dir(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (value != NULL && value[0] != '\0') {
		cfg->cache_dir = apr_pstrdup(cmd->pool, value);
		cfg->cache_dir_set = 1;
	}

	return NULL;
}

static const char *get_log_dir(cmd_parms *cmd, void *dconfig, const char *value)
{
	return get_cache_dir(cmd, dconfig, value);
}

static const char *get_email_notify(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (value != NULL && value[0] != '\0') {
		cfg->email_notify = apr_pstrdup(cmd->pool, value);
		cfg->email_notify_set = 1;
	}

	return NULL;
}

static const char *get_system_command(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (value != NULL && value[0] != '\0') {
		cfg->system_command = apr_pstrdup(cmd->pool, value);
		cfg->system_command_set = 1;
	}

	return NULL;
}

static const char *get_custom_level_count(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);
	int idx = (int)(long)cmd->info;
	long n = dd_get_long_value(value, -1);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (idx < 0 || idx >= 10) {
		return "Invalid CustomLevelCount index (expected 1..10)";
	}

	if (n <= 0) {
		cfg->custom_level_counts[idx] = 0;
	}
	else {
		cfg->custom_level_counts[idx] = (int)n;
	}
	cfg->custom_level_count_set[idx] = 1;

	return NULL;
}

static const char *get_custom_level_add(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);
	int idx = (int)(long)cmd->info;

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	if (idx < 0 || idx >= 10) {
		return "Invalid CustomLevelAdd index (expected 1..10)";
	}

	return dd_add_pattern_to_list(cmd->pool, &cfg->custom_level_patterns[idx], value);
}

static const char *get_whitelist_ip(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	return dd_add_pattern_to_list(cmd->pool, &cfg->ip_whitelist_patterns, value);
}

static const char *get_whitelist_ua(cmd_parms *cmd, void *dconfig, const char *value)
{
	dos_server_config *cfg = ap_get_module_config(cmd->server->module_config, &doscontrol_module);

	(void)dconfig;

	if (cfg == NULL) {
		return "Internal config error";
	}

	return dd_add_pattern_to_list(cmd->pool, &cfg->ua_whitelist_patterns, value);
}

static const char *whitelist(cmd_parms *cmd, void *dconfig, const char *ip)
{
	return get_whitelist_ip(cmd, dconfig, ip);
}
// END RSRC READ/PARSE

// HANDLE RSRC PARAMS
static const command_rec access_cmds[] =
{
	AP_INIT_TAKE1("DOSHashTableSize", get_hash_tbl_size, NULL, RSRC_CONF, "Set size of hash table"),
	AP_INIT_TAKE1("DOSPageCount", get_page_count, NULL, RSRC_CONF, "Set maximum page hit count per interval"),
	AP_INIT_TAKE1("DOSSiteCount", get_site_count, NULL, RSRC_CONF, "Set maximum site hit count per interval"),
	AP_INIT_TAKE1("DOSPageInterval", get_page_interval, NULL, RSRC_CONF, "Set page interval"),
	AP_INIT_TAKE1("DOSSiteInterval", get_site_interval, NULL, RSRC_CONF, "Set site interval"),
	AP_INIT_TAKE1("DOSBlockingPeriod", get_blocking_period, NULL, RSRC_CONF, "Set blocking period for detected DoS IPs"),
	AP_INIT_TAKE1("DOSBlockDelay", get_block_delay, NULL, RSRC_CONF, "Delay blocked responses in milliseconds"),
	AP_INIT_TAKE1("DOSResponseCode", get_response_code, NULL, RSRC_CONF, "Set response code for blocked requests: 403 or 429"),
	AP_INIT_TAKE1("DOSMainLog", get_main_log, NULL, RSRC_CONF, "Set general activity log file"),
	AP_INIT_TAKE1("DOSCacheDir", get_cache_dir, NULL, RSRC_CONF, "Set incident cache directory"),
	AP_INIT_TAKE1("DOSEmailNotify", get_email_notify, NULL, RSRC_CONF, "Set email notification"),
	AP_INIT_TAKE1("DOSSystemCommand", get_system_command, NULL, RSRC_CONF, "Set system command on DoS"),
	AP_INIT_ITERATE("DOSWhitelistIP", get_whitelist_ip, NULL, RSRC_CONF, "IP-address whitelist patterns"),
	AP_INIT_ITERATE("DOSWhitelistUA", get_whitelist_ua, NULL, RSRC_CONF, "User-Agent whitelist patterns"),
	AP_INIT_TAKE1("DOSCustomLevelCount1", get_custom_level_count, (void *)0, RSRC_CONF, "Set custom level 1 count"),
	AP_INIT_TAKE1("DOSCustomLevelCount2", get_custom_level_count, (void *)1, RSRC_CONF, "Set custom level 2 count"),
	AP_INIT_TAKE1("DOSCustomLevelCount3", get_custom_level_count, (void *)2, RSRC_CONF, "Set custom level 3 count"),
	AP_INIT_TAKE1("DOSCustomLevelCount4", get_custom_level_count, (void *)3, RSRC_CONF, "Set custom level 4 count"),
	AP_INIT_TAKE1("DOSCustomLevelCount5", get_custom_level_count, (void *)4, RSRC_CONF, "Set custom level 5 count"),
	AP_INIT_TAKE1("DOSCustomLevelCount6", get_custom_level_count, (void *)5, RSRC_CONF, "Set custom level 6 count"),
	AP_INIT_TAKE1("DOSCustomLevelCount7", get_custom_level_count, (void *)6, RSRC_CONF, "Set custom level 7 count"),
	AP_INIT_TAKE1("DOSCustomLevelCount8", get_custom_level_count, (void *)7, RSRC_CONF, "Set custom level 8 count"),
	AP_INIT_TAKE1("DOSCustomLevelCount9", get_custom_level_count, (void *)8, RSRC_CONF, "Set custom level 9 count"),
	AP_INIT_TAKE1("DOSCustomLevelCount10", get_custom_level_count, (void *)9, RSRC_CONF, "Set custom level 10 count"),
	AP_INIT_ITERATE("DOSCustomLevelAdd1", get_custom_level_add, (void *)0, RSRC_CONF, "Add URI pattern to custom level 1"),
	AP_INIT_ITERATE("DOSCustomLevelAdd2", get_custom_level_add, (void *)1, RSRC_CONF, "Add URI pattern to custom level 2"),
	AP_INIT_ITERATE("DOSCustomLevelAdd3", get_custom_level_add, (void *)2, RSRC_CONF, "Add URI pattern to custom level 3"),
	AP_INIT_ITERATE("DOSCustomLevelAdd4", get_custom_level_add, (void *)3, RSRC_CONF, "Add URI pattern to custom level 4"),
	AP_INIT_ITERATE("DOSCustomLevelAdd5", get_custom_level_add, (void *)4, RSRC_CONF, "Add URI pattern to custom level 5"),
	AP_INIT_ITERATE("DOSCustomLevelAdd6", get_custom_level_add, (void *)5, RSRC_CONF, "Add URI pattern to custom level 6"),
	AP_INIT_ITERATE("DOSCustomLevelAdd7", get_custom_level_add, (void *)6, RSRC_CONF, "Add URI pattern to custom level 7"),
	AP_INIT_ITERATE("DOSCustomLevelAdd8", get_custom_level_add, (void *)7, RSRC_CONF, "Add URI pattern to custom level 8"),
	AP_INIT_ITERATE("DOSCustomLevelAdd9", get_custom_level_add, (void *)8, RSRC_CONF, "Add URI pattern to custom level 9"),
	AP_INIT_ITERATE("DOSCustomLevelAdd10", get_custom_level_add, (void *)9, RSRC_CONF, "Add URI pattern to custom level 10"),
	{ NULL }
};
// HELPERS
// email
static void dd_send_email_notice(request_rec *r, const dos_server_config *cfg, const char *ip)
{
	char mailcmd[2048];
	FILE *file;
	const char *email;

	if (cfg == NULL) {
		return;
	}

	email = cfg->email_notify;
	if (email == NULL || *email == '\0') {
		return;
	}

	apr_snprintf(mailcmd, sizeof(mailcmd), MAILER, email);
	file = popen(mailcmd, "w");
	if (file != NULL) {
		fprintf(file, "To: %s\n", email);
		fprintf(file, "Subject: HTTP BLACKLIST %s\n\n", ip);
		fprintf(file, "mod_doscontrol HTTP Blacklisted %s\n", ip);
		pclose(file);
		dd_log_main(r, cfg, "MAIL",
			apr_psprintf(r->pool,
				"action=\"sent\" to=\"%s\" client=\"%s\"",
				email,
				ip));
	}
	else {
		dd_log_main(r, cfg, "MAIL",
			apr_psprintf(r->pool,
				"action=\"failed\" to=\"%s\" client=\"%s\" error=\"%s\"",
				email,
				ip,
				strerror(errno)));
	}
}
// exec system command
static void dd_run_system_command(request_rec *r, const dos_server_config *cfg, const char *ip)
{
	char *cmd;

	if (cfg == NULL || cfg->system_command == NULL || *cfg->system_command == '\0') {
		return;
	}

	cmd = dd_expand_command(r->pool, cfg->system_command, ip);
	if (cmd == NULL || *cmd == '\0') {
		return;
	}

	dd_log_main(r, cfg, "COMMAND",
		apr_psprintf(r->pool,
			"action=\"system\"; command=\"%s\"; client=\"%s\"",
			cmd,
			ip));

	system(cmd);
}
// get log file
static const char *dd_effective_main_log(const dos_server_config *cfg)
{
	if (cfg != NULL && cfg->main_log != NULL && *cfg->main_log != '\0') {
		return cfg->main_log;
	}
	return DEFAULT_MAIN_LOG;
}
// get block delay
static int dd_effective_block_delay_ms(const dos_server_config *cfg)
{
	return (cfg != NULL) ? cfg->block_delay_ms : 0;
}
static void dd_apply_block_delay(const dos_server_config *cfg)
{
	int delay_ms = dd_effective_block_delay_ms(cfg);

	if (delay_ms > 0) {
		apr_sleep((apr_interval_time_t)delay_ms * 1000);
	}
}
// get cache dir
static const char *dd_effective_cache_dir(const dos_server_config *cfg)
{
	if (cfg != NULL && cfg->cache_dir != NULL && *cfg->cache_dir != '\0') {
		return cfg->cache_dir;
	}
	return DEFAULT_CACHE_DIR;
}
// get pagecount
static int dd_effective_page_count(const dos_server_config *cfg)
{
	return (cfg != NULL) ? cfg->page_count : DEFAULT_PAGE_COUNT;
}
// get site count
static int dd_effective_site_count(const dos_server_config *cfg)
{
	return (cfg != NULL) ? cfg->site_count : DEFAULT_SITE_COUNT;
}
// take all other parameters similarly...
static int dd_effective_page_interval(const dos_server_config *cfg)
{
	return (cfg != NULL) ? cfg->page_interval : DEFAULT_PAGE_INTERVAL;
}
static int dd_effective_site_interval(const dos_server_config *cfg)
{
	return (cfg != NULL) ? cfg->site_interval : DEFAULT_SITE_INTERVAL;
}
static int dd_effective_blocking_period(const dos_server_config *cfg)
{
	return (cfg != NULL) ? cfg->blocking_period : DEFAULT_BLOCKING_PERIOD;
}
static int dd_effective_response_code(const dos_server_config *cfg)
{
	return (cfg != NULL) ? cfg->response_code : DEFAULT_HTTP_RESPONSE;
}
static void dd_ensure_hit_list(request_rec *r, dos_server_config *cfg)
{
	(void)r;

	if (cfg == NULL) {
		return;
	}

	if (cfg->hit_list == NULL) {
		cfg->hit_list = ntt_create((long)((cfg->hash_table_size > 0) ? cfg->hash_table_size : DEFAULT_HASH_TBL_SIZE));
		if (cfg->hit_list != NULL && !cfg->hit_list_cleanup_registered && cfg->pool != NULL) {
			apr_pool_cleanup_register(cfg->pool, cfg, dd_destroy_server_state, apr_pool_cleanup_null);
			cfg->hit_list_cleanup_registered = 1;
		}
	}
}
//  check/get connection parameters
//  compare with whitelist/block, decide
static int access_checker(request_rec *r)
{
	int ret = OK;
	dos_server_config *cfg;

	if (r == NULL) {
		return OK;
	}

	cfg = dd_get_request_config(r);
	if (cfg == NULL) {
		return OK;
	}

	if (r->prev == NULL && r->main == NULL) {
		char hash_key[2048];
		struct ntt_node *n;
		time_t t = time(NULL);
		const char *ip = dd_client_ip(r);
		const char *uri = dd_request_uri(r);
		const char *ua = dd_request_user_agent(r);
		int effective_page_count = dd_effective_page_count(cfg);
		int effective_site_count = dd_effective_site_count(cfg);

		dd_ensure_hit_list(r, cfg);
		if (cfg->hit_list == NULL) {
			return OK;
		}

		dd_resolve_custom_limits(cfg, uri, &effective_page_count, &effective_site_count);

		if (dd_is_whitelisted_ip(cfg, ip)) {
			dd_log_main(r, cfg, "ALLOW",
				apr_psprintf(r->pool,
					"action=\"whitelist_ip\" client=\"%s\" uri=\"%s\"",
					ip,
					uri));
			return OK;
		}

		if (dd_is_whitelisted_ua(cfg, ua)) {
			dd_log_main(r, cfg, "ALLOW",
				apr_psprintf(r->pool,
					"action=\"whitelist_ua\" client=\"%s\" ua=\"%s\" uri=\"%s\"",
					ip,
					ua,
					uri));
			return OK;
		}

		n = ntt_find(cfg->hit_list, ip);
		if (n != NULL && t - n->timestamp < dd_effective_blocking_period(cfg)) {
			ret = dd_effective_response_code(cfg);
			n->timestamp = time(NULL);
		}
		else {
			apr_snprintf(hash_key, sizeof(hash_key), "%s_%s", ip, uri);
			n = ntt_find(cfg->hit_list, hash_key);
			if (n != NULL) {
				if (t - n->timestamp < dd_effective_page_interval(cfg) && n->count >= effective_page_count) {
					ret = dd_effective_response_code(cfg);
					ntt_insert(cfg->hit_list, ip, time(NULL));
				}
				else {
					if (t - n->timestamp >= dd_effective_page_interval(cfg)) {
						n->count = 0;
					}
				}

				n->timestamp = t;
				n->count++;
			}
			else {
				ntt_insert(cfg->hit_list, hash_key, t);
			}

			apr_snprintf(hash_key, sizeof(hash_key), "%s_SITE", ip);
			n = ntt_find(cfg->hit_list, hash_key);
			if (n != NULL) {
				if (t - n->timestamp < dd_effective_site_interval(cfg) && n->count >= effective_site_count) {
					ret = dd_effective_response_code(cfg);
					ntt_insert(cfg->hit_list, ip, time(NULL));
				}
				else {
					if (t - n->timestamp >= dd_effective_site_interval(cfg)) {
						n->count = 0;
					}
				}

				n->timestamp = t;
				n->count++;
			}
			else {
				ntt_insert(cfg->hit_list, hash_key, t);
			}
		}

		if (ret == dd_effective_response_code(cfg)) {
			char detail[2048];
			const char *client = dd_client_ip(r);
			const char *dir = dd_effective_cache_dir(cfg);

			dd_apply_block_delay(cfg);
			dd_write_attack_cache(r, cfg, client);

			apr_snprintf(detail, sizeof(detail),
				"action=\"block\" client=\"%s\" uri=\"%s\" response_code=%d response_text=\"%s\" page_count=%d page_interval=%d site_count=%d site_interval=%d blocking_period=%d block_delay_ms=%d cache_dir=\"%s\"",
				client,
				uri,
				dd_effective_response_code(cfg),
				dd_status_text(dd_effective_response_code(cfg)),
				effective_page_count,
				dd_effective_page_interval(cfg),
				effective_site_count,
				dd_effective_site_interval(cfg),
				dd_effective_blocking_period(cfg),
				dd_effective_block_delay_ms(cfg),
				dir);

			dd_log_main(r, cfg, "BLOCK", detail);

			if (cfg->email_notify != NULL) {
				dd_send_email_notice(r, cfg, client);
			}

			if (cfg->system_command != NULL) {
				dd_run_system_command(r, cfg, client);
			}
		}
	}

	if (ret == dd_effective_response_code(cfg)
		&& (ap_satisfies(r) != SATISFY_ANY || !ap_some_auth_required(r))) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"client denied by server configuration: %s",
			r->filename);
	}

	return ret;
}

static void register_hooks(apr_pool_t *p)
{
	(void)p;
	ap_hook_access_checker(access_checker, NULL, NULL, APR_HOOK_MIDDLE);
}
// run...
module AP_MODULE_DECLARE_DATA doscontrol_module =
{
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	create_server_config,
	merge_server_config,
	access_cmds,
	register_hooks
};
