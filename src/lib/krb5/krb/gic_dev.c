/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <sys/socket.h>
#include <sys/un.h>

#include "k5-int.h"
#include "com_err.h"
#include "init_creds_ctx.h"

#define DEVICE_SOCK_PATH "/tmp/krb5_device.sock"

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_device(krb5_context context,
                           krb5_creds *creds,
                           krb5_principal client,
                           krb5_deltat start_time,
                           char *in_tkt_service,
                           krb5_get_init_creds_opt *options)
{
    krb5_error_code ret;
    struct sockaddr_un remote;
    int len;
    int s;

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        ret = DEV_NO_DEVICE;
        goto cleanup;
    }

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, DEVICE_SOCK_PATH);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    if (connect(s, (struct sockaddr *)&remote, len) == -1) {
        ret = DEV_NO_DEVICE;
        goto cleanup;
    }

    /* TODO: Package and send over all args to the device over the
       newly opened socket. The device should call krb5int_get_init_creds
       with the arguments to set up the creds struct and pass this
       struct back to us. We should unbundle creds and return it. */

cleanup:
    /** Nothing here for now */

    return ret;
}
