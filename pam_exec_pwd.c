// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/*
 *  pam_exec_pwd.c
 *  Copyright (C) 2007 SGDN
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <dirent.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define CONFIG "/etc/security/exec.conf"
#define CONFIG_DIR "/etc/security/exec.conf.d"
#define LINELEN 1024
#define MAX_GROUPS 64
#define _UNUSED __attribute__((unused))

/* pam module flags */
#define OFLAG_SESSOPEN		0x0001 	/* being run at session_open */
#define OFLAG_SESSCLOSE		0x0002 	/* being run at session_close */
#define OFLAG_SERVICE_MASK	0x00ff

#define OFLAG_CLOSE_RUN_ALL	0x0100 	/* run all cmds at session close, */
					/* even if errors are encountered */
/* module options */
struct pamexec_opts {
	int flags;
	char *passwd;
};

/* config entry flags */
#define EFLAG_SESSOPEN	0x0001	/* run at session_open */
#define EFLAG_SESSCLOSE	0x0002	/* run at session_close */
#define EFLAG_INVERT	0x0100	/* inverted match */
#define EFLAG_GROUP	0x0200	/* name is a group name */
#define EFLAG_ALL	0x0400	/* run cmd for all users */
#define EFLAG_PASSWD	0x1000	/* pass user's passwd to spawned cmd */
#define EFLAG_USER	0x2000	/* run cmd under user's uid */

/* config entry */
struct pamexec_entry {
	char *name;
	int flags;
	char *cmd;
	char *arg;	/* a single argument is supported */
};

/*****************************************************************************/
/*                                logging                                    */
/*****************************************************************************/

#define OPENLOG()	openlog(NULL, LOG_PID, LOG_AUTHPRIV);
#define CLOSELOG()	closelog()

#define ERROR(fmt, args...) do { \
	syslog(LOG_ERR, "pam_exec_pwd error: " fmt "\n", ##args); \
} while (0)

#define ERROR_ERRNO(fmt, args...) do { \
	syslog(LOG_ERR, "pam_exec_pwd error: " fmt ": %s\n", ##args, \
				strerror(errno)); \
} while (0)

#define ERROR_PAM(fmt, pamh, errnum, args...) do { \
	syslog(LOG_ERR, "pam_exec_pwd pam error: " fmt ": %s\n", ##args, \
				pam_strerror(pamh, errnum)); \
} while (0)

#define LOG(fmt, args...) do { \
	syslog(LOG_INFO, "pam_exec_pwd: " fmt "\n", ##args); \
} while (0)

/*****************************************************************************/
/*                                parsing                                    */
/*****************************************************************************/

		/* pam stack parsing */
static int
pamexec_getopts(struct pamexec_opts *opts, int argc, const char **argv)
{
	int i;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "close_run_all")) {
			opts->flags |= OFLAG_CLOSE_RUN_ALL;
		} else {
			ERROR("unrecognized option: %s", argv[i]);
			return -1;
		}
	}

	return 0;
}

		/* config entries parsing */

static inline int
_readflags(int *flags, const char *str)
{
	const char *ptr;

	for (ptr = str; *ptr; ptr++) {
		switch (*ptr) {
			case 'o':
				*flags |= EFLAG_SESSOPEN;
				break;
			case 'c':
				*flags |= EFLAG_SESSCLOSE;
				break;
			case 'p':
				*flags |= EFLAG_PASSWD;
				break;
			case 'u':
				*flags |= EFLAG_USER;
				break;
			default:
				ERROR("Unrecognized flag: %c", *ptr);
				return -1;
		}
	}
	return 0;
}

typedef enum {
	ParseNull,
	ParseNOK,
	ParseOK
} parse_ret_t;

/* Set *all* fields of @entry from conf file line @line */

static parse_ret_t
pamexec_parse(char *line, struct pamexec_entry *entry)
{
	char *ptr, *name, *flags, *cmd;

	if ((ptr = strchr(line, '#')))
		*ptr = '\0';

	if ((ptr = strchr(line, '\n')))
		*ptr = '\0';

	ptr = line;
	while (isspace(*ptr))
		ptr++;

	if (!(*ptr))
		return ParseNull;

	name = strsep(&ptr, " \t");
	if (!name)
		return ParseNOK;

	while (isspace(*ptr))
		ptr++;
	flags = strsep(&ptr, " \t");
	if (!flags)
		return ParseNOK;

	while (isspace(*ptr))
		ptr++;
	cmd = strsep(&ptr, " \t");
	if (!cmd)
		return ParseNOK;

	entry->flags = 0;

	if (*name == '*' && *(name+1) == '\0') {
		entry->flags |= EFLAG_ALL;
	} else {
		if (*name == '-' && *(name+1)) {
			entry->flags |= EFLAG_INVERT;
			name++;
		}
		if (*name == '@' && *(name+1)) {
			entry->flags |= EFLAG_GROUP;
			name++;
		}
	}

	if (_readflags(&(entry->flags), flags))
		return ParseNOK;

	/* NB : no copy */
	entry->name = name;
	entry->cmd = cmd;

	if (ptr) {
		while (isspace(*ptr))
			ptr++;
		if (*ptr)
			entry->arg = ptr;
		else
			entry->arg = NULL;
	} else {
		entry->arg = NULL;
	}

	return ParseOK;
}

/*****************************************************************************/
/*                            entry checking                                 */
/*****************************************************************************/

typedef enum {
	CheckMatch,
	CheckNoMatch,
	CheckError
} check_ret_t;


static inline check_ret_t
pamexec_check(const struct pamexec_entry *entry,
		const struct pamexec_opts *opts,
		const char *user,
		const gid_t *groups, size_t grplen)
{
	switch (opts->flags & OFLAG_SERVICE_MASK) {
		case OFLAG_SESSOPEN:
			if (!(entry->flags & EFLAG_SESSOPEN))
				return CheckNoMatch;
			break;
		case OFLAG_SESSCLOSE:
			if (!(entry->flags & EFLAG_SESSCLOSE))
				return CheckNoMatch;
			break;
		default:
			ERROR("unsupported service type: %d",
					opts->flags & OFLAG_SERVICE_MASK);
			return CheckError;
	}

	if (entry->flags & EFLAG_ALL)
		return CheckMatch;

	if (entry->flags & EFLAG_GROUP) {
		size_t i;
		struct group *grp = getgrnam(entry->name);
		if (!grp) {
			ERROR_ERRNO("getgrnam (%s)", entry->name);
			return CheckError;
		}

#define Matched ( (entry->flags & EFLAG_INVERT) ? CheckNoMatch : CheckMatch)
#define NotMatched ( (entry->flags & EFLAG_INVERT) ? CheckMatch : CheckNoMatch)

		for (i = 0; i < grplen; ++i) {
			if (groups[i] == grp->gr_gid)
				return Matched;
		}
	} else {
		if (!strcmp(entry->name, user))
			return Matched;
	}

	return NotMatched;
#undef Matched
#undef NotMatched
}

int filter_files(const struct dirent* f) { return f->d_type == DT_REG; }

/*****************************************************************************/
/*                            command spawning                               */
/*****************************************************************************/

static inline char *
_envvar(const char *var, const char *val)
{
	ssize_t slen;
	size_t len = strlen(var) + strlen(val);
	char *str = malloc(len+2);
	if (!str) {
		ERROR("out of memory ?");
		return NULL;
	}

	slen = snprintf(str, len+2, "%s=%s", var, val);
	if (slen < 0) {
		ERROR("snprintf error ??");
		free(str);
		return NULL;
	}
	if ((size_t)slen >= len + 2) {
		ERROR("snprintf error ?");
		free(str);
		return NULL;
	}
	return str;
}

#define ROOT_PATH 	"/bin:/sbin:/usr/bin:/usr/sbin"
#define USER_PATH	"/bin:/usr/bin:/usr/local/bin"

/* Freeing in case of error is done by the caller. @envp fields
 * must be allocated in order.
 */
static inline int
_setup_envp(char **envp, const struct pamexec_entry *entry,
		const struct pamexec_opts *opts, const struct passwd *pwd)
{
	if ((entry->flags & EFLAG_USER) && pwd->pw_uid)
		envp[0] = _envvar("PATH", USER_PATH);
	else
		envp[0] = _envvar("PATH", ROOT_PATH);
	if (!envp[0])
		return -1;

	envp[1] = _envvar("USER", pwd->pw_name);
	if (!envp[1])
		return -1;

	/* Note: entries requiring a password should be placed
	 * before those requiring no password in the config file,
	 * to avoid running only the password-less commands in case
	 * the user's password cannot be retrieved. */
	if (entry->flags & EFLAG_PASSWD) {
		if (!opts->passwd) {
			ERROR("cannot find user's password");
			return -1;
		}
		envp[2] = _envvar("PASSWD", opts->passwd);
		if (!envp[2])
			return -1;
	}

	return 0;
}

static int
pamexec_spawn(const struct pamexec_entry *entry,
		const struct pamexec_opts *opts,
		const struct passwd *pwd)
{
	pid_t pid, wret;
	int status;
	char **ptr;
	int ret = -1;

	char *argv[] = {
		NULL,		/* cmd */
		NULL,		/* possible arg */
		NULL
	};

	char *envp[] = {
		NULL,		/* PATH */
		NULL,		/* USER */
		NULL,		/* PASSWD */
		NULL
	};

	argv[0] = entry->cmd;
	argv[1] = entry->arg;

	if (_setup_envp(envp, entry, opts, pwd))
		goto out_free;

	switch (pid = fork()) {
		case 0:
			if (entry->flags & EFLAG_USER) {
				if (setgid(pwd->pw_gid)) {
					ERROR_ERRNO("setgid");
					exit(EXIT_FAILURE);
				}
				if (setuid(pwd->pw_uid)) {
					ERROR_ERRNO("setuid");
					exit(EXIT_FAILURE);
				}
			}
			ret = execve(entry->cmd, argv, envp);
			ERROR_ERRNO("execve");
			exit(EXIT_FAILURE);
		case -1:
			ERROR_ERRNO("fork");
			goto out_free;
		default:
			wret = waitpid(pid, &status, 0);
			if (wret == -1) {
				ERROR_ERRNO("waitpid");
				goto out_free;
			}
			if (wret != pid) {
				ERROR("waitpid: wrong pid??");
				goto out_free;
			}
			if (!WIFEXITED(status) || WEXITSTATUS(status)) {
				ERROR("error in spawned command: %s",
								entry->cmd);
				goto out_free;
			}

			ret = 0;
	}

	/* Fall through */
out_free:
	/* Clear passwd */
	if (envp[2])
		memset(envp[2], 0, strlen(envp[2]));
	for (ptr = envp; *ptr; ptr++)
		free(*ptr);
	return ret;
}

/*****************************************************************************/
/*                            full module run                                */
/*****************************************************************************/

typedef enum {
	RunOK,
	RunEnd,
	RunConfError,
	RunCheckError,
	RunSpawnError,
	RunError
} run_ret_t;

static run_ret_t
_run_one(FILE *conf, const struct pamexec_opts *opts, const struct passwd *pwd,
		const gid_t *groups, size_t grplen)
{
	char line[LINELEN];
	char *ptr;
	struct pamexec_entry entry;
	parse_ret_t pret;
	check_ret_t cret;

	ptr = fgets(line, LINELEN, conf);
	if (!ptr) {
		if (feof(conf))
			return RunEnd;
		ERROR("read error");
		return RunConfError;
	}
	if (strlen(ptr) == LINELEN -1) {
		ERROR("config line is too long");
		return RunConfError;
	}

	switch (pret = pamexec_parse(line, &entry)) {
		case ParseNull:
			return RunOK;
		case ParseOK:
			break;
		case ParseNOK:
			return RunConfError;
		default:
			ERROR("unexpected parse return: %d", pret);
			return RunError;
	}

	switch (cret = pamexec_check(&entry, opts, pwd->pw_name,
						groups, grplen)) {
		case CheckNoMatch:
			return RunOK;
		case CheckMatch:
			break;
		case CheckError:
			return RunCheckError;
		default:
			ERROR("unexpected check return: %d", cret);
			return RunError;
	}

	if (pamexec_spawn(&entry, opts, pwd))
		return RunSpawnError;
	else
		return RunOK;
}

static inline const char *
_run_errorstr(run_ret_t ret)
{
	switch (ret) {
		case RunOK:
		case RunEnd:
			return "success (unexpected!)";
		case RunConfError:
			return "parse error";
		case RunCheckError:
			return "check error";
		case RunSpawnError:
			return "command error";
		case RunError:
			return "unspecified error";
		default:
			return "unexpected (!) error";
	}
}

#define OFLAG_MASK_GO_ON	(OFLAG_SESSCLOSE|OFLAG_CLOSE_RUN_ALL)
#define error_go_on(opts) \
	((opts->flags & OFLAG_MASK_GO_ON) == OFLAG_MASK_GO_ON)


static int
pamexec_run_file(int fd, const struct pamexec_opts *opts,
		struct passwd* pwd, const gid_t *groups,int ngroups,
	   	const char* filename)
{
	run_ret_t rret;
	FILE *conf;
	int line = 0, errcount = 0, ret=0;

	if (!(conf = fdopen(fd, "r"))) {
		ERROR_ERRNO("fopen");
		if (close(fd))
			ERROR_ERRNO("close");
		return -1;
	}

	ret = -1;

	for (;;) {
		++line;
		rret = _run_one(conf, opts, pwd, groups, ngroups);
		if (rret == RunOK)
			continue;
		if (rret == RunEnd)
			break;
		ERROR("%s at line %d of %s", _run_errorstr(rret),
							line, filename);
		errcount++;
		if (error_go_on(opts))
			continue;

		goto out;
	}

	if (!errcount)
		ret = 0;

	/* Fall through */
out:
	if (fclose(conf))
		ERROR_ERRNO("fclose");

	return ret;
}

static int
pamexec_run(const char *user, const struct pamexec_opts *opts)
{
	gid_t groups[MAX_GROUPS];
	struct passwd *pwd;
	int ret, fd, dirfd;
	int isconfdir = 1, isconffile = 1, isconf =0;
	int ngroups = MAX_GROUPS;
	int errcount=0;
	struct dirent** dir;

	memset(groups, 0, sizeof(groups));
	pwd = getpwnam(user);
	if (!pwd) {
		ERROR_ERRNO("getpwnam");
		return -1;
	}
	ret = getgrouplist(pwd->pw_name, pwd->pw_gid, groups, &ngroups);
	if (ret == -1) {
		ERROR("getgrouplist: too many groups");
		return -1;
	}
	dirfd = open(CONFIG_DIR, O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
	if(dirfd == -1){
		if(errno==ENOENT){
			isconfdir = 0;
		}
		else {
			ERROR_ERRNO("opendir");
		}
	}

	fd = open(CONFIG, O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
	if (fd == -1) {
		if(errno==ENOENT){
			isconffile = 0;
		} else {
			ERROR_ERRNO("open");
		}
	}

	if(isconffile) {
		isconf = 1;
		ret = pamexec_run_file(fd, opts, pwd, groups, ngroups, CONFIG);
		if(ret != 0){
			errcount++;
			if(!error_go_on(opts))
				return ret;
		}
	}

	if(isconfdir) {
		int i, n = scandir(CONFIG_DIR, &dir, filter_files, alphasort);
		if(n==-1){
			ERROR_ERRNO("scandir");
			goto out;
		}

		for(i= 0;i<n;i++){
			fd = openat(dirfd, dir[i]->d_name, O_RDONLY|O_NOFOLLOW);
			if(fd == -1){
				ERROR_ERRNO("open");
				continue;
			}
			isconf = 1;
			ret = pamexec_run_file(fd, opts, pwd, groups,
					ngroups, dir[i]->d_name);
			if(ret != 0){
				errcount++;
				if(!error_go_on(opts))
					return ret;
			}
		}
		free(dir);
		close(dirfd);
	}

out:
	if(!isconf){
		ERROR("No config files found");
		return -1;
	}
	if(errcount)
		return -1;

	return 0;
}

/*****************************************************************************/
/*                            PAM interface                                  */
/*****************************************************************************/

static void
pamexec_cleanup_authtok(pam_handle_t *pamh _UNUSED,
			void *data, int errcode _UNUSED)
{
	if (data) {
		memset(data, 0, strlen(data));
		free(data);
	}
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
				int argc, const char **argv)
{
	char *authtok, *ptr;
	int ret;

	OPENLOG();
	if (!pamh) {
		ERROR("empty pamh");
		ret = PAM_AUTH_ERR;
		goto out;
	}

	ptr = NULL;
	ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **)(void *)&ptr);
	if (ret != PAM_SUCCESS) {
		ERROR_PAM("pam_get_item", pamh, ret);
		ret = PAM_AUTH_ERR;
		goto out;
	}
	/* NB: we do not return an error if authtok is empty, authentication is
	 * not our job per se, and it is still possible to run password-less
	 * scripts in that case.
	 */
	if (!ptr) {
		ret = PAM_SUCCESS;
		goto out;
	}

	/* TODO: binary passwords ? */
	authtok = strdup(ptr);
	if (!authtok) {
		ERROR("out of memory?");
		ret = PAM_AUTH_ERR;
		goto out;
	}

	/* store the user's password in pam data to be later retrieved by the
	 * session code */
	ret = pam_set_data(pamh, "pamexec_authtok", authtok,
					pamexec_cleanup_authtok);
	if (ret != PAM_SUCCESS) {
		ERROR_PAM("pam_set_data", pamh, ret);
		ret = PAM_AUTH_ERR;
		goto out;
	}

	ret = PAM_SUCCESS;
	/* Fall through */
out:
	CLOSELOG();
	return ret;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
    				int argc, const char **argv)
{
	const char *user;
	char *authtok = NULL; /* shut up, gcc */
	struct pamexec_opts opts;
	int ret;

	memset(&opts, 0, sizeof(opts));
	OPENLOG();

	if (pamexec_getopts(&opts, argc, argv)) {
		ret = PAM_SERVICE_ERR;
		goto out;
	}

	ret = pam_get_user(pamh, &user, NULL);
	if (ret != PAM_SUCCESS) {
		ERROR_PAM("pam_get_user", pamh, ret);
		ret = PAM_SERVICE_ERR;
		goto out;
	}

	ret = pam_get_data(pamh, "pamexec_authtok",
				(const void **)(void *)&authtok);
	if (ret == PAM_SUCCESS) {
		opts.passwd = authtok;
	} else {
		/* No error, just logging for now */
		ERROR_PAM("pam_get_data", pamh, ret);
		opts.passwd = NULL;
	}
	opts.flags |= OFLAG_SESSOPEN;

	if (pamexec_run(user, &opts)) {
		ERROR("failed to run all commands for user %s "
				"at session opening", user);
		ret = PAM_SERVICE_ERR;
	} else {
		LOG("session open, all commands ok for user %s", user);
		ret = PAM_SUCCESS;
	}

	/* Cleanup passwd ASAP. Note that it won't be available to session
	 * close.
	 */
	if (opts.passwd) {
		memset(opts.passwd, 0, strlen(opts.passwd));
	}

	/* Fall through */
out:
	CLOSELOG();
	return ret;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
				int argc, const char **argv)
{
	const char *user;
	struct pamexec_opts opts;
	int ret;

	memset(&opts, 0, sizeof(opts));
	OPENLOG();

	if (pamexec_getopts(&opts, argc, argv)) {
		ret = PAM_SERVICE_ERR;
		goto out;
	}

	ret = pam_get_user(pamh, &user, NULL);
	if (ret != PAM_SUCCESS) {
		ERROR_PAM("pam_get_user", pamh, ret);
		ret = PAM_SERVICE_ERR;
		goto out;
	}

	opts.flags = OFLAG_SESSCLOSE;
	opts.passwd = NULL;

	if (pamexec_run(user, &opts)) {
		ERROR("failed to run all commands for user %s "
				"at session closing", user);
		ret = PAM_SERVICE_ERR;
	} else {
		LOG("session close, all commands ok for user %s", user);
		ret = PAM_SUCCESS;
	}

	/* Fall through */
out:
	CLOSELOG();
	return ret;
}

/* Placeholders */

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
				int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
				int argc, const char **argv)
{
	OPENLOG();
	ERROR("acct_mgmt is not supported");
	CLOSELOG();
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
				int argc, const char **argv)
{
	OPENLOG();
	ERROR("chauthtok is not supported");
	CLOSELOG();
	return PAM_SERVICE_ERR;
}

