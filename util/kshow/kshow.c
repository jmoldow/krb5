#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <krb5.h>

int main(int argc, char *argv[])
{
    char *service_name = argv[1];

    krb5_context context;
    krb5_error_code err;
    krb5_ccache ccache;
    krb5_principal me;
    krb5_creds in_creds, out_creds;

    // TODO: check the error code returned by each krb5_ function.

    krb5_init_context(&context);

    // krb5_cc_resolve(context, ccachestr, &ccache);
    krb5_cc_default(context, &ccache);
    krb5_cc_get_principal(context, ccache, &me);
    memset(&in_creds, 0, sizeof(in_creds));
    in_creds.client = me;
    krb5_parse_name(context, service_name, &in_creds.server);
    krb5_cc_retrieve_cred(context, ccache, KRB5_TC_MATCH_SRV_NAMEONLY,
                          &in_creds, &out_creds);

    printf("got cred with ticket length %x\n", out_creds.ticket.length);

    krb5_free_principal(context, in_creds.server);
    krb5_free_cred_contents(context, &out_creds);
    krb5_free_principal(context, me);
    krb5_cc_close(context, ccache);
    krb5_free_context(context);

    exit(0);
}
