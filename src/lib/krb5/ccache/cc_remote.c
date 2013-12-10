#include "k5-int.h"
#include "cc-int.h"

#include <sys/socket.h>
#include <sys/types.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <dirent.h>

#define CHECK(EXPR) if((ret = (EXPR))) goto cleanup;
#define CHECK_LT0(EXPR) if((ret = (EXPR)) < 0) goto cleanup;

extern const krb5_cc_ops krb5_rcc_ops;
extern const krb5_cc_ops krb5_fcc_ops;

/* Fields are not modified after creation, so no lock is necessary. */
typedef struct rcc_data_st {
    char *residual;             /* network socket's host:port */
    char *host_name;            /* network socket host */
    char *portstr;              /* network socket port (as a string) */
    krb5_ccache fcc;            /* File cache for actual cache ops */
} rcc_data;

static krb5_error_code KRB5_CALLCONV
rcc_socket_parse(char const *residual, char **host_name, char **portstr);
static krb5_error_code KRB5_CALLCONV
rcc_socket_connect(krb5_ccache cache);

static const char * KRB5_CALLCONV
rcc_get_name(krb5_context context, krb5_ccache cache)
{
    rcc_data *data = cache->data;

    return data->residual;
}

/* Construct a cache object given a residual string and file ccache.  Take
 * ownership of fcc on success. */
static krb5_error_code
make_cache(const char *residual, krb5_ccache fcc, krb5_ccache *cache_out)
{
    krb5_ccache cache = NULL;
    rcc_data *data = NULL;
    char *residual_copy = NULL;
    char *host_name_copy = NULL;
    char *port_copy = NULL;

    cache = malloc(sizeof(*cache));
    if (cache == NULL)
        goto oom;
    data = malloc(sizeof(*data));
    if (data == NULL)
        goto oom;
    residual_copy = strdup(residual);
    if (residual_copy == NULL)
        goto oom;
    if (rcc_socket_parse(residual_copy, &host_name_copy, &port_copy))
        goto oom;
    data->residual = residual_copy;
    data->host_name = host_name_copy;
    data->portstr = port_copy;
    data->fcc = fcc;
    cache->ops = &krb5_rcc_ops;
    cache->data = data;
    cache->magic = KV5M_CCACHE;
    *cache_out = cache;
    return 0;

oom:
    free(cache);
    free(data);
    free(residual_copy);
    return ENOMEM;
}

static krb5_error_code KRB5_CALLCONV
rcc_resolve(krb5_context context, krb5_ccache *cache_out, const char *residual)
{
    krb5_error_code ret;
    krb5_ccache fcc;

    const char storage_name[128];

    *cache_out = NULL;

    /*
    ret = krb5_cc_default(context, &fcc);
    */
    /* Set fixed cache location so we can use remote as default */
    
    snprintf(storage_name, sizeof(storage_name), 
	     "FILE:/tmp/krb5cc_%ld", (long) getuid());
    if (!context || context->magic != KV5M_CONTEXT)
        ret = KV5M_CONTEXT;
    else ret = krb5_cc_resolve(context, storage_name, &fcc);
    
    if (ret)
        goto cleanup;

    ret = make_cache(residual, fcc, cache_out);
    if (ret)
        krb5_fcc_ops.close(context, fcc);

cleanup:
    return ret;
}

static krb5_error_code KRB5_CALLCONV
rcc_gen_new(krb5_context context, krb5_ccache *cache_out)
{
    /* TODO implement remote socket */

    /*
     * Return error because we can't guess socket
     * TODO If we decide to implement default socket,
     * add an implementation here.
     */
    return KRB5_CC_NOSUPP;
    /*
    krb5_error_code ret;
    krb5_ccache fcc = NULL;

    *cache_out = NULL;
    ret = krb5_fcc_ops.gen_new(context, &fcc);
    if (ret)
        goto cleanup;
    ret = make_cache(residual, fcc, cache_out);
    if (ret)
        goto cleanup;
    fcc = NULL;

cleanup:
    if (fcc != NULL)
        krb5_fcc_ops.destroy(context, fcc);
    return ret;
    */
}

static krb5_error_code KRB5_CALLCONV
rcc_init(krb5_context context, krb5_ccache cache, krb5_principal princ)
{
    krb5_error_code ret;
    char msg_buf[1024];
    char len_buf[128];
    int sock, i, tmp;

    rcc_data *data = cache->data;

    if ((sock = rcc_socket_connect(cache)) < 0)
    {
        ret = KRB5_CC_IO;
        goto cleanup;
    }

    // Talk to the agent
    snprintf(msg_buf, 1024, "kinit\n%s@%s\n", princ->data[0].data, princ->realm.data);
    snprintf(len_buf, 128, "%zd\n", strlen(msg_buf));
    printf("init: sending remote requests\n");
    CHECK_LT0(send(sock, len_buf, strlen(len_buf), 0));
    CHECK_LT0(send(sock, msg_buf, strlen(msg_buf), 0));
    // Iterate and fill buf
    i = 0;
    tmp = 1;
    while (i < 2)
    {
        tmp = recv(sock, (void*)(msg_buf+i), 4-i, 0);
        i += tmp;
    }
    msg_buf[i] = 0;
    printf("Received data: %s\n", msg_buf);

    if (strncmp(msg_buf, "OK", 2))
    {
        printf("Remote kinit failed.\n");
        ret = KRB5_CC_IO;
	goto cleanup;
    }

    printf("init: REMOTE success!\n");
    CHECK(krb5_fcc_ops.init(context, data->fcc, princ));

cleanup:
    close(sock);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
rcc_destroy(krb5_context context, krb5_ccache cache)
{
    rcc_data *data = cache->data;
    krb5_error_code ret;
    char msg_buf[1024];
    char len_buf[128];
    int sock;

    if ((sock = rcc_socket_connect(cache)) <  0) goto cleanup;
    snprintf(msg_buf, 1024, "kdestroy\n");
    snprintf(len_buf, 128, "%zd\n", strlen(msg_buf));
    printf("destroy: sending remote request\n");
    CHECK_LT0(send(sock, len_buf, strlen(len_buf), 0));
    CHECK_LT0(send(sock, msg_buf, strlen(msg_buf), 0));
cleanup:
    close(sock);

    ret = krb5_fcc_ops.destroy(context, data->fcc);
    free(data->residual);
    free(data);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
rcc_close(krb5_context context, krb5_ccache cache)
{
    rcc_data *data = cache->data;
    krb5_error_code ret;

    ret = krb5_fcc_ops.close(context, data->fcc);
    free(data->residual);
    free(data);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
rcc_store(krb5_context context, krb5_ccache cache, krb5_creds *creds)
{
    rcc_data *data = cache->data;

    return krb5_fcc_ops.store(context, data->fcc, creds);
}

/*
 * rcc_socket_parse - Parses a host_name:port residual
 *
 * residual: a host_name:port string, specified on the command line with
 * REMOTE:host_name:port
 *
 * host_name: a string pointer that, on successful return, will hold the host_name string
 *
 * port: an string pointer that, on successful return, will hold the port
 *
 * Returns 0 on success, and KRB5_CC_IO on failure.
 */
static krb5_error_code KRB5_CALLCONV
rcc_socket_parse(char const *residual, char **host_name, char **portstr)
{
    char *host_name_copy;
    char *portstr_copy;
    long int port_int;
    char *endptr;

    char *colon = strchr(residual, ':');
    if (!colon)
    {
        // No port provided.
        return KRB5_CC_IO;
    }

    // Copy and split the residual into host and port
    host_name_copy = strndup(residual, (colon - residual));
    if (!host_name_copy)
        goto cleanup;
    portstr_copy = colon + 1;
    port_int = strtol(portstr_copy, &endptr, 10);
    if (!port_int || *endptr)
    {
        // Parsing the port number failed, either because
        // there are no numbers after the colon (!port_int) or because
        // the port number does not end the string (*endptr != '\0').
        goto cleanup;
    }

    // Succeeded at parsing, overwrite pointers.
    *host_name = host_name_copy;
    *portstr = portstr_copy;
    return 0;

cleanup:
    free(host_name_copy);
    return KRB5_CC_IO;
}

/*
 * rcc_socket_connect - Connects to this remote ccache's network socket
 *
 * Returns the socket file descriptor on success, or KRB5_CC_IO on error.
 */
static krb5_error_code KRB5_CALLCONV
rcc_socket_connect(krb5_ccache cache)
{
    rcc_data *data = cache->data;
    struct addrinfo hints = {0}, *res;
    int sockfd;
    int e;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((e = getaddrinfo(data->host_name, data->portstr, &hints, &res)))
    {
        printf("getaddrinfo: %s\n", gai_strerror(e));
        return KRB5_CC_IO;
    }
    if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
        return KRB5_CC_IO;
    if (connect(sockfd, res->ai_addr, res->ai_addrlen))
        return KRB5_CC_IO;
    freeaddrinfo(res);

    return sockfd;
}

static krb5_error_code KRB5_CALLCONV
rcc_retrieve(krb5_context context, krb5_ccache cache, krb5_flags flags,
             krb5_creds *mcreds, krb5_creds *creds)
{
    rcc_data *data = cache->data;
    char msg_buf[1024];
    char len_buf[128];
    struct hostent *host;
    struct sockaddr_in sock_addr;
    int sock, ret, i, len;
    char *newline;
    char *princname;
    char tmpname[24] = "/tmp/rcc_retrieveXXXXXX";
    int tmp_fd;
    FILE *tmp = NULL;

    krb5_ccache tcc;
    krb5_creds tkt;
    krb5_cc_cursor cursor;

    // Attempt file retrieve
    printf("File retrieve\n");
    ret = krb5_fcc_ops.retrieve(context, data->fcc, flags, mcreds, creds);
    if (!ret)
        return ret;

    printf("Network retrieve\n");
    if ((sock = rcc_socket_connect(cache)) < 0) {
        ret = KRB5_CC_IO;
        goto cleanup;
    }

    // Talk to the agent
    krb5_unparse_name(context, mcreds->server, &princname);
    printf("principal: %s\n", princname);
    snprintf(msg_buf, 1024, "ticket\n%s", princname);
    snprintf(len_buf, 128, "%zd\n", strlen(msg_buf));
    CHECK_LT0(send(sock, len_buf, strlen(len_buf), 0));
    CHECK_LT0(send(sock, msg_buf, strlen(msg_buf), 0));
    // Iterate and fill buf until we reach a newline
    i = 0;
    msg_buf[0] = 0;
    while (i != 1024 && (newline = strchr(msg_buf, '\n')) == NULL) {
        ret = recv(sock, (void*)(msg_buf+i), 1024-i, 0);
        if (!strncmp(msg_buf, "FAIL", 4) || ret <= 0) {
            ret = KRB5_CC_IO;
            goto cleanup;
        }
        i += ret;
        msg_buf[i] = 0;
    }
    if (!newline) {
        ret = KRB5_CC_IO;
        goto cleanup;
    }
    *newline = 0;
    newline += 1;
    len = atoi(msg_buf);
    printf("Received len header: %d, %s\n", len, msg_buf);

    // Stream the socket data into a file. This file will be formatted
    // as a ccache file with exactly one ticket -- the one requested
    tmp_fd = mkstemp(tmpname);
    tmp = fdopen(tmp_fd, "w");
    CHECK_LT0(fwrite(newline, sizeof(char), i - strlen(msg_buf), tmp));
    len -= i - strlen(msg_buf);
    while (len > 0)
    {
        ret = recv(sock, msg_buf, 1024, 0);
        if (ret <= 0) {
            printf("Receiving ticket failed: socket error\n");
            ret = KRB5_CC_IO;
            goto cleanup;
        }
        ret = fputs(msg_buf, tmp);
        if (ret < 0)
            goto cleanup;
        len -= strlen(newline);
    }
    fclose(tmp);
    tmp = NULL;

    // Move the ticket from the tmp ccache into tkt
    CHECK(krb5_cc_resolve(context, tmpname, &tcc));
    CHECK(krb5_cc_start_seq_get(context, tcc, &cursor));
    CHECK(krb5_cc_next_cred(context, tcc, &cursor, &tkt));
    CHECK(krb5_cc_end_seq_get(context, tcc, &cursor));
    CHECK(krb5_cc_close(context, tcc));
    // Save the ticket into the fcc
    CHECK(krb5_fcc_ops.store(context, data->fcc, &tkt));
    // Remove the temporary ccache.
    unlink(tmpname);

    // Perform a file retrieve as usual
    ret = krb5_fcc_ops.retrieve(context, data->fcc, flags, mcreds, creds);

cleanup:
    if (tmp)
        fclose(tmp);
    close(sock);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
rcc_get_princ(krb5_context context, krb5_ccache cache,
              krb5_principal *princ_out)
{
    rcc_data *data = cache->data;

    return krb5_fcc_ops.get_princ(context, data->fcc, princ_out);
}

static krb5_error_code KRB5_CALLCONV
rcc_get_first(krb5_context context, krb5_ccache cache, krb5_cc_cursor *cursor)
{
    rcc_data *data = cache->data;

    return krb5_fcc_ops.get_first(context, data->fcc, cursor);
}

static krb5_error_code KRB5_CALLCONV
rcc_get_next(krb5_context context, krb5_ccache cache, krb5_cc_cursor *cursor,
             krb5_creds *creds)
{
    rcc_data *data = cache->data;

    return krb5_fcc_ops.get_next(context, data->fcc, cursor, creds);
}

static krb5_error_code KRB5_CALLCONV
rcc_end_get(krb5_context context, krb5_ccache cache, krb5_cc_cursor *cursor)
{
    rcc_data *data = cache->data;

    return krb5_fcc_ops.end_get(context, data->fcc, cursor);
}

static krb5_error_code KRB5_CALLCONV
rcc_remove_cred(krb5_context context, krb5_ccache cache, krb5_flags flags,
                krb5_creds *creds)
{
    rcc_data *data = cache->data;

    return krb5_fcc_ops.remove_cred(context, data->fcc, flags, creds);
}

static krb5_error_code KRB5_CALLCONV
rcc_set_flags(krb5_context context, krb5_ccache cache, krb5_flags flags)
{
    rcc_data *data = cache->data;

    return krb5_fcc_ops.set_flags(context, data->fcc, flags);
}

static krb5_error_code KRB5_CALLCONV
rcc_get_flags(krb5_context context, krb5_ccache cache, krb5_flags *flags_out)
{
    rcc_data *data = cache->data;

    return krb5_fcc_ops.get_flags(context, data->fcc, flags_out);
}

static krb5_error_code KRB5_CALLCONV
rcc_ptcursor_new(krb5_context context, krb5_cc_ptcursor *cursor_out)
{
    // Per-type cursor acts as an fcc cursor for the purposes of rcc.
    // TODO: Implement the ability to iterate over all available tickets?

    return krb5_fcc_ops.ptcursor_new(context, cursor_out);
}

static krb5_error_code KRB5_CALLCONV
rcc_ptcursor_next(krb5_context context, krb5_cc_ptcursor cursor,
                  krb5_ccache *cache_out)
{
    rcc_data *data = (*cache_out)->data;
    // Per-type cursor acts as an fcc cursor for the purposes of rcc.
    return krb5_fcc_ops.ptcursor_next(context, cursor, data->fcc);
}

static krb5_error_code KRB5_CALLCONV
rcc_ptcursor_free(krb5_context context, krb5_cc_ptcursor *cursor)
{
    // Per-type cursor acts as an fcc cursor for the purposes of rcc.
    return krb5_fcc_ops.ptcursor_free(context, cursor);
}

static krb5_error_code KRB5_CALLCONV
rcc_lastchange(krb5_context context, krb5_ccache cache,
               krb5_timestamp *time_out)
{
    rcc_data *data = cache->data;

    return krb5_fcc_ops.lastchange(context, data->fcc, time_out);
}

static krb5_error_code KRB5_CALLCONV
rcc_lock(krb5_context context, krb5_ccache cache)
{
    rcc_data *data = cache->data;

    return krb5_fcc_ops.lock(context, data->fcc);
}

static krb5_error_code KRB5_CALLCONV
rcc_unlock(krb5_context context, krb5_ccache cache)
{
    rcc_data *data = cache->data;

    return krb5_fcc_ops.unlock(context, data->fcc);
}

const krb5_cc_ops krb5_rcc_ops = {
    0,
    "REMOTE",
    rcc_get_name,
    rcc_resolve,
    rcc_gen_new,
    rcc_init,
    rcc_destroy,
    rcc_close,
    rcc_store,
    rcc_retrieve,
    rcc_get_princ,
    rcc_get_first,
    rcc_get_next,
    rcc_end_get,
    rcc_remove_cred,
    rcc_set_flags,
    rcc_get_flags,
    rcc_ptcursor_new,
    rcc_ptcursor_next,
    rcc_ptcursor_free,
    NULL, /* move */
    rcc_lastchange,
    NULL, /* wasdefault */
    rcc_lock,
    rcc_unlock,
    NULL, /* switch_to */
};
