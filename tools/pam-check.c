/* Manual Linux-PAM probe. Passwords use libpam_misc's non-echoing conversation.
 * Run only against a reviewed, private configuration directory. This can load
 * real PAM modules; incorrect passwords may affect the configured failure tally.
 * Build: cc -Wall -Wextra -Werror tools/pam-check.c -o build/pam-check/probe \
 *           -lpam -lpam_misc
 */
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc != 4 || argv[3][0] != '/') {
        fprintf(stderr, "Usage: %s SERVICE USER ABSOLUTE_CONFDIR\n", argv[0]);
        return 2;
    }
    struct pam_conv conversation = {misc_conv, NULL};
    pam_handle_t *handle = NULL;
    int status = pam_start_confdir(argv[1], argv[2], &conversation, argv[3], &handle);
    if (status != PAM_SUCCESS) {
        fprintf(stderr, "PAM initialization failed: %d\n", status);
        return 1;
    }
    status = pam_authenticate(handle, 0);
    printf("Authentication: %s (%d)\n", pam_strerror(handle, status), status);
    if (status == PAM_SUCCESS) {
        status = pam_acct_mgmt(handle, 0);
        printf("Account check: %s (%d)\n", pam_strerror(handle, status), status);
    }
    int end_status = pam_end(handle, status);
    return status == PAM_SUCCESS && end_status == PAM_SUCCESS ? 0 : 1;
}
