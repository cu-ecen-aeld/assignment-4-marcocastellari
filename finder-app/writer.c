
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char** argv) {

	openlog("writer", LOG_PID | LOG_CONS, LOG_USER); // LOG_USER facility

	if (argc != 3) {
		syslog(LOG_ERR, "Invalid number of arguments [%d]", argc);
		syslog(LOG_ERR, "Usage:\n");
		syslog(LOG_ERR, "  Two argumets required. Usage: <writefile> <writestr>");
		return 1;
    }

    char const* writefile = argv[1];
    char const* writestr  = argv[2];

	FILE *fp = fopen(writefile, "w");
    if (fp == NULL) {
        syslog(LOG_ERR, "Failes to open file '%s' for writing: %s", writefile, strerror(errno));
        closelog();
        return 1;
    }

	syslog(LOG_DEBUG, "Writing '%s' to '%s'", writestr, writefile);

	if (fprintf(fp, "%s\n", writestr) < 0) {
        syslog(LOG_ERR, "Failed to write to file '%s': %s", writefile, strerror(errno));
        fclose(fp);
        closelog();
        return 1;
    }

    if (fclose(fp) != 0) {
        syslog(LOG_ERR, "Failed to close file '%s': %s", writefile, strerror(errno));
        closelog();
        return 1;
    }

	closelog();
	return 0;
}
