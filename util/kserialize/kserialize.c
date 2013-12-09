#include <stdio.h>
#include <string.h>
#include <com_err.h>
#include <krb5.h>

#define CHECK(EXPR, CTX) if(ret=(EXPR)) {com_err("kserialize", ret, (CTX)); exit(1);}

int main(int argc, char *argv[])
{
    krb5_context context;
    krb5_ccache ccache;
    krb5_creds in_creds, out_creds;
    long ret = 0;

    if (argc < 4) {
        printf("Usage: kserialize ccache_file server_principal output_file\n");
        exit(1);
    }
    char *ccache_file = argv[1];
    char *service_name = argv[2];
    char *out_file = argv[3];

    memset(&in_creds, 0, sizeof(in_creds));
    CHECK(krb5_init_context(&context), "krb5_init_context");

    // Fetch the desired ticket from the system credential cache.
    CHECK(krb5_cc_resolve(context, ccache_file, &ccache), "krb5_cc_resolve");
    CHECK(krb5_cc_get_principal(context, ccache, &in_creds.client),
          "krb5_cc_get_principal");
    CHECK(krb5_parse_name(context, service_name, &in_creds.server),
          "krb5_parse_name");
    CHECK(krb5_cc_retrieve_cred(context, ccache, KRB5_TC_MATCH_SRV_NAMEONLY,
				&in_creds, &out_creds),
          "krb5_cc_retrieve_cred");
    CHECK(krb5_cc_close(context, ccache), "krb5_cc_close");

    // Write the ticket out to a file.
    CHECK(krb5_cc_resolve(context, out_file, &ccache), "krb5_cc_resolve");
    CHECK(krb5_cc_initialize(context, ccache, in_creds.client),
          "krb5_cc_initialize");
    CHECK(krb5_cc_store_cred(context, ccache, &out_creds),
          "krb5_cc_store_cred");
    CHECK(krb5_cc_close(context, ccache), "krb5_cc_close");

    // Clean up and exit.
    krb5_free_principal(context, in_creds.client);
    krb5_free_principal(context, in_creds.server);
    krb5_free_cred_contents(context, &out_creds);
    krb5_free_context(context);
    exit(0);
}
