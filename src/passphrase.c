/* Code inspired from openssh
 *
 * - https://github.com/openssh/openssh-portable/blob/master/readpass.c#L113-L181
 * - https://github.com/openssh/openssh-portable/blob/master/openbsd-compat/readpassphrase.c
 */

#include <termios.h>
#include <signal.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#ifndef TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#endif

#ifndef _NSIG
# ifdef NSIG
#  define _NSIG NSIG
# else
#  define _NSIG 128
# endif
#endif

#include "debug.h"
#include "defs.h"

#define TTY_NAME "/dev/tty"

#define NSIGNALS 10

static volatile sig_atomic_t signo[_NSIG];
static void handler(int s){ signo[s] = 1; }

static int siglist[10] = { SIGALRM, SIGHUP, SIGPIPE, SIGPROF, SIGQUIT,
			   SIGINT, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU };

/*
 * Reads a passphrase from TTY_NAME with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered.
 * 
 * return 0 on success
 *       -1 when we need to restart
 *       >0 otherwise on error
 */
int
get_passphrase(const char *prompt, char *buf, size_t buflen)
{
  ssize_t nr = -1;
  int ttyfd = -1, save_errno = 0, i = 0, rc = 0;
  char ch, *p;
  struct termios term, oterm;
  struct sigaction sigs[10];
  struct sigaction sa;
  
  /* I suppose we could alloc on demand in this case (XXX). */
  if (buflen == 0) {
    errno = EINVAL;
    return 1;
  }

  for (i = 0; i < _NSIG; i++)
    signo[i] = 0;

  /*
   * Read and write to TTY_NAME if available.
   */
  if ((ttyfd = open(TTY_NAME, O_RDWR | O_NOCTTY)) == -1) {
    E("can't open %s: %s", TTY_NAME, strerror(errno));
    errno = ENOTTY;
    return 3;
  }

  if (!isatty(ttyfd)) {
    E("%s is not a tty", TTY_NAME);
    rc = 4;
    goto bailout;
  }

  /*
   * Turn off echo if possible.
   * If we are using a tty but are not the foreground pgrp this will
   * generate SIGTTOU, so do it *before* installing the signal handlers.
   */
  rc = tcgetattr(ttyfd, &oterm);
  if (!rc) {
    memcpy(&term, &oterm, sizeof(term));
    term.c_lflag &= ~(ECHO | ECHONL);
    rc = tcsetattr(ttyfd, TCSAFLUSH|TCSASOFT, &term);
  }

  if(rc) {
    E("Cannot get/set the TTY attributes");
    errno = EINVAL;
    rc = 5;
    goto bailout;
  }

  /*
   * Catch signals that would otherwise cause the user to end
   * up with echo turned off in the shell.  Don't worry about
   * things like SIGXCPU and SIGVTALRM for now.
   */
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;		/* don't restart system calls */
  sa.sa_handler = handler;

  for(i=0; i < 10; i++){ sigaction(siglist[i], &sa, &(sigs[i])); }
  
  /* Output the prompt */
  write(ttyfd, "\r", 1); /* Start a new line */
  write(ttyfd, prompt, strlen(prompt));

  p = buf;
  while ((nr = read(ttyfd, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
    if (buflen > 0) {
      *p++ = ch;
      buflen--;
    }
  }
  *p = '\0';
  save_errno = errno;

  write(ttyfd, "\n", 1);

  /* Restore old terminal settings and signals. */
  if (memcmp(&term, &oterm, sizeof(term)) != 0) {
    const int sigttou = signo[SIGTTOU];

    /* Ignore SIGTTOU generated when we are not the fg pgrp. */
    while (tcsetattr(ttyfd, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
	   errno == EINTR && !signo[SIGTTOU])
      continue;
    signo[SIGTTOU] = sigttou;
  }

  for(i=0; i < 10; i++){ sigaction(siglist[i], &(sigs[i]), NULL); }
  
  close(ttyfd);
  ttyfd = -1;
  
  /*
   * If we were interrupted by a signal, resend it to ourselves
   * now that we have restored the signal handlers.
   */
  for (i = 0; i < _NSIG; i++) {
    if (signo[i]) {
      kill(getpid(), i);
      switch (i) {
      case SIGTSTP:
      case SIGTTIN:
      case SIGTTOU:
	rc = -1; /* restart */
	D1("We need a restart");
	goto bailout;
      }
    }
  }
  
  if (save_errno)
    errno = save_errno;

  rc = (nr == -1 ? 5 : 0);

bailout:
  if(ttyfd > 0) close(ttyfd);
  return rc;
}
