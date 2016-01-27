/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -Wall -g -o mylogin login.linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define MAX_PASS_AGE 10
#define MAX_LOGIN_ATTEMPTS 5

void sighandler() {
	// Catch (some) termination signal
	if(signal(SIGINT, SIG_IGN) == SIG_ERR) {
		exit(EXIT_FAILURE);
	}
	if(signal(SIGQUIT, SIG_IGN) == SIG_ERR) {
		exit(EXIT_FAILURE);
	}
	if(signal(SIGTSTP, SIG_IGN) == SIG_ERR) {
		exit(EXIT_FAILURE);
	}
}

// Wrapper around fgets to replace ending \n by \0.
// From http://stackoverflow.com/a/4309845/2299303
char *fgets_wrapper(char *buffer, size_t buflen, FILE *fp) {
	if (fgets(buffer, buflen, fp) != 0) {
		size_t len = strlen(buffer);
		if (len > 0 && buffer[len-1] == '\n')
			buffer[len-1] = '\0';
		return buffer;
	}
	return 0;
}

int main(int argc, char *argv[]) {

	mypwent *passwddata;

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	char *c_pass;

	char *shellargv[] = {NULL};
	char *shellenv[] = {NULL};

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
				important);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if(fgets_wrapper(user, LENGTH, stdin) == 0)
			exit(EXIT_SUCCESS);


		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);

		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {
			// Ask for password, encrypt with salt
			c_pass = crypt(getpass("Password: "), passwddata->passwd_salt);

			if(c_pass == NULL) exit(EXIT_FAILURE);

			// Prevent bruteforcing
			if(passwddata->pwfailed > MAX_LOGIN_ATTEMPTS) {
				printf("Too many failed attempts, account is locked!\n");
				continue;
			}

			if (strcmp(c_pass, passwddata->passwd) == 0) {
				printf("You're in !\n");
				printf("Your uid: %d\n", passwddata->uid);
				printf("Failed attempts: %d\n", passwddata->pwfailed);

				// Password age
				passwddata->pwage++;
				if(passwddata->pwage > MAX_PASS_AGE)
					printf("You should change password!\n");

				// Reset num failed attempts
				passwddata->pwfailed = 0;

				// Store the updated entry
				if(mysetpwent(user, passwddata) != 0) {
					printf("Something went wrong saving passwddata!");
					exit(EXIT_FAILURE);
				}

				// Set uid
				if(setuid(passwddata->uid) != 0) {
					exit(EXIT_FAILURE);
				}

				// Start shell
				execve("/bin/sh", shellargv, shellenv);

				// execve only returns on failure
				exit(EXIT_FAILURE);
			} else {
				// Increase no_of_failed_attempts
				passwddata->pwfailed++;

				// Store the updated entry
				if(mysetpwent(user, passwddata) != 0) {
					printf("Something went wrong saving passwddata!");
					exit(EXIT_FAILURE);
				}
			}
		}
		printf("Login Incorrect \n");
	}
	return EXIT_SUCCESS;
}

