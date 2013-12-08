#include <stdio.h>
#include <string.h>
#include <com_err.h>
#include <krb5.h>

#define CHECK(EXPR, CTX) if(ret=(EXPR)) {com_err("kunserialize", ret, (CTX)); exit(1);}

int main(int argc, char *argv[])
{
    krb5_context context;
    krb5_ccache ccache;
    krb5_creds creds;
    krb5_cc_cursor cursor;
    long ret = 0;

    if (argc < 3) {
        printf("Usage: kunserialize input_file ccache_file\n");
        exit(1);
    }
    char *in_file = argv[1];
    char *ccache_file = argv[2];

    CHECK(krb5_init_context(&context), "krb5_init_context");

    // Read the serialized ticket from the input file.
    CHECK(krb5_cc_resolve(context, in_file, &ccache), "krb5_cc_resolve");
    CHECK(krb5_cc_start_seq_get(context, ccache, &cursor),
          "krb5_cc_start_seq_get");
    CHECK(krb5_cc_next_cred(context, ccache, &cursor, &creds),
          "krb5_cc_next_cred");
    CHECK(krb5_cc_end_seq_get(context, ccache, &cursor),
          "krb5_cc_end_seq_get");
    CHECK(krb5_cc_close(context, ccache),
          "krb5_cc_close");

    // Write the ticket into the system credential cache.
    CHECK(krb5_cc_resolve(context, ccache_file, &ccache),
          "krb5_cc_resolve");
    CHECK(krb5_cc_store_cred(context, ccache, &creds),
          "krb5_cc_store_cred");
    CHECK(krb5_cc_close(context, ccache), "krb5_cc_close");

    // Clean up and exit.
    krb5_free_cred_contents(context, &creds);
    krb5_free_context(context);
    exit(0);
}
