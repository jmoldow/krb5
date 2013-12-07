#include <stdio.h>
#include <string.h>
#include <krb5.h>

#define CHECK(EXPR) if(EXPR) {printf("Error: " #EXPR "\n"); exit(1);}

int main(int argc, char *argv[])
{
    krb5_context context;
    krb5_ccache ccache;
    krb5_creds creds;
    krb5_cc_cursor cursor;

    if (argc < 2) {
        printf("Usage: kunserialize input_file\n");
        exit(1);
    }
    char *in_file = argv[1];

    CHECK(krb5_init_context(&context));

    // Read the serialized ticket from the input file.
    CHECK(krb5_cc_resolve(context, in_file, &ccache));
    CHECK(krb5_cc_start_seq_get(context, ccache, &cursor));
    CHECK(krb5_cc_next_cred(context, ccache, &cursor, &creds));
    CHECK(krb5_cc_end_seq_get(context, ccache, &cursor));
    CHECK(krb5_cc_close(context, ccache));

    // Write the ticket into the system credential cache.
    CHECK(krb5_cc_default(context, &ccache));
    CHECK(krb5_cc_store_cred(context, ccache, &creds));
    CHECK(krb5_cc_close(context, ccache));

    // Clean up and exit.
    krb5_free_cred_contents(context, &creds);
    krb5_free_context(context);
    exit(0);
}
