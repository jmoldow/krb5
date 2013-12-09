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
    /* TODO implement remote socket */
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

    *cache_out = NULL;

    ret = krb5_cc_default(context, &fcc);
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
    return -1;
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
    int ret;
    char msg_buf[1024];
    char len_buf[128];
    int sock, i;

    rcc_data *data = cache->data;

    if ((sock = rcc_socket_connect(cache)) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    // Talk to the agent
    snprintf(msg_buf, 1024, "kinit\n%s@%s\n", princ->data[0].data, princ->realm.data);
    snprintf(len_buf, 128, "%zd\n", strlen(msg_buf));
    CHECK_LT0(send(sock, len_buf, strlen(len_buf), 0));
    CHECK_LT0(send(sock, msg_buf, strlen(msg_buf), 0));
    // Iterate and fill buf
    i = 0;
    ret = 1;
    while (i < 2)
    {
        ret = recv(sock, (void*)(msg_buf+i), 4-i, 0);
        i += ret;
    }
    msg_buf[i] = 0;

    CHECK(!strncmp(msg_buf, "OK", 2));

    CHECK(krb5_fcc_ops.init(context, data->fcc, princ));

cleanup:
    close(sock);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
rcc_destroy(krb5_context context, krb5_ccache cache)
{
    /* TODO implement remote socket */
    rcc_data *data = cache->data;
    krb5_error_code ret;

    ret = krb5_fcc_ops.destroy(context, data->fcc);
    free(data->residual);
    free(data);
    return ret;
}

static krb5_error_code KRB5_CALLCONV
rcc_close(krb5_context context, krb5_ccache cache)
{
    /* TODO implement remote socket */
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
 * Returns 0 on success, and -1 on failure.
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
        // No port provided. Should we allow a default port?
        return -1;
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
    return -1;
}

/*
 * rcc_socket_connect - Connects to this remote ccache's network socket
 *
 * Returns the socket file descriptor on success, or -1 on error.
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
        return -1;
    }
    if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
        return -1;
    if (connect(sockfd, res->ai_addr, res->ai_addrlen))
        return -1;
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
    int sock, ret, i, len;
    char *newline;
    char tmpname[24] = "/tmp/rcc_retrieveXXXXXX";
    int tmp_fd;
    FILE *tmp = NULL;

    krb5_ccache tcc;
    krb5_creds tkt;
    krb5_cc_cursor cursor;

    // Attempt file retrieve
    ret = krb5_fcc_ops.retrieve(context, data->fcc, flags, mcreds, creds);
    if (!ret)
        return ret;

    if ((sock = rcc_socket_connect(cache)) < 0)
        goto cleanup;

    // Talk to the agent
    // TODO: Get the service name
    snprintf(msg_buf, 1024, "ticket\n%s\n", "serviceA");
    snprintf(len_buf, 128, "%zd\n", strlen(msg_buf));
    CHECK_LT0(send(sock, len_buf, strlen(len_buf), 0));
    CHECK_LT0(send(sock, msg_buf, strlen(msg_buf), 0));
    // Iterate and fill buf until we reach a newline
    i = 0;
    msg_buf[0] = 0;
    while (i != 1024 && (newline = strchr(msg_buf, '\n')) == NULL)
    {
        ret = recv(sock, (void*)(msg_buf+i), 1024-i, 0);
        if (ret <= 0)
        {
            ret = -1;
            goto cleanup;
        }
        i += ret;
    }
    if (!newline)
    {
        ret = -1;
        goto cleanup;
    }
    *newline = 0;
    newline += 1;
    len = atoi(msg_buf);

    // Stream the socket data into a file. This file will be formatted
    // as a ccache file with exactly one ticket -- the one requested
    tmp_fd = mkstemp(tmpname);
    tmp = fdopen(tmp_fd, "w");
    CHECK_LT0(fputs(newline, tmp));
    len -= strlen(newline);
    while (len > 0)
    {
        ret = recv(sock, msg_buf, 1024, 0);
        if (ret <= 0)
        {
            ret = -1;
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
    /* TODO implement remote socket */
    rcc_data *data = cache->data;

    return krb5_fcc_ops.get_first(context, data->fcc, cursor);
}

static krb5_error_code KRB5_CALLCONV
rcc_get_next(krb5_context context, krb5_ccache cache, krb5_cc_cursor *cursor,
             krb5_creds *creds)
{
    /* TODO implement remote socket */
    rcc_data *data = cache->data;

    return krb5_fcc_ops.get_next(context, data->fcc, cursor, creds);
}

static krb5_error_code KRB5_CALLCONV
rcc_end_get(krb5_context context, krb5_ccache cache, krb5_cc_cursor *cursor)
{
    /* TODO implement remote socket */
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

/* TODO modify or remove */
struct dcc_ptcursor_data {
    char *primary;
    char *dirname;
    DIR *dir;
    krb5_boolean first;
};

/* Construct a cursor, taking ownership of dirname, primary, and dir on
 * success. */
static krb5_error_code
make_cursor(char *dirname, char *primary, DIR *dir,
            krb5_cc_ptcursor *cursor_out)
{
    /* TODO implement remote socket */
    krb5_cc_ptcursor cursor;
    struct dcc_ptcursor_data *data;

    *cursor_out = NULL;

    data = malloc(sizeof(*data));
    if (data == NULL)
        return ENOMEM;
    cursor = malloc(sizeof(*cursor));
    if (cursor == NULL) {
        free(data);
        return ENOMEM;
    }

    data->dirname = dirname;
    data->primary = primary;
    data->dir = dir;
    data->first = TRUE;
    cursor->ops = &krb5_rcc_ops;
    cursor->data = data;
    *cursor_out = cursor;
    return 0;
}

static krb5_error_code KRB5_CALLCONV
rcc_ptcursor_new(krb5_context context, krb5_cc_ptcursor *cursor_out)
{
    /* TODO implement remote socket */
    return -1;
    /*
    krb5_error_code ret;
    char *dirname = NULL, *primary_path = NULL, *primary = NULL;
    DIR *dir = NULL;

    *cursor_out = NULL;

    // Open the directory for the context's default cache.
    ret = get_context_default_dir(context, &dirname);
    if (ret || dirname == NULL)
        goto cleanup;
    dir = opendir(dirname);
    if (dir == NULL)
        goto cleanup;

    // Fetch the primary cache name if possible.
    ret = primary_pathname(dirname, &primary_path);
    if (ret)
        goto cleanup;
    ret = read_primary_file(context, primary_path, dirname, &primary);
    if (ret)
        krb5_clear_error_message(context);

    ret = make_cursor(dirname, primary, dir, cursor_out);
    if (ret)
        goto cleanup;
    dirname = primary = NULL;
    dir = NULL;

cleanup:
    free(dirname);
    free(primary_path);
    free(primary);
    if (dir)
        closedir(dir);
    // Return an empty cursor if we fail for any reason.
    if (*cursor_out == NULL)
        return make_cursor(NULL, NULL, NULL, cursor_out);
    return 0;
    */
}

static krb5_error_code KRB5_CALLCONV
rcc_ptcursor_next(krb5_context context, krb5_cc_ptcursor cursor,
                  krb5_ccache *cache_out)
{
    /* TODO implement remote socket */
    return -1;
    /*
    struct dcc_ptcursor_data *data = cursor->data;
    struct dirent *ent;
    char *residual;
    krb5_error_code ret;
    struct stat sb;

    *cache_out = NULL;
    if (data->dir == NULL)      // Empty cursor
        return 0;

    // Return the primary cache if we haven't yet.
    if (data->first) {
        data->first = FALSE;
        if (data->primary != NULL && stat(data->primary + 1, &sb) == 0)
            return rcc_resolve(context, cache_out, data->primary);
    }

    // Look for the next filename of the correct form, without repeating the
    // primary cache.
    while ((ent = readdir(data->dir)) != NULL) {
        if (!filename_is_cache(ent->d_name))
            continue;
        ret = subsidiary_residual(data->dirname, ent->d_name, &residual);
        if (ret)
            return ret;
        if (data->primary != NULL && strcmp(residual, data->primary) == 0) {
            free(residual);
            continue;
        }
        ret = rcc_resolve(context, cache_out, residual);
        free(residual);
        return ret;
    }

    // We exhausted the directory without finding a cache to yield.
    free(data->dir);
    data->dir = NULL;
    return 0;
    */
}

static krb5_error_code KRB5_CALLCONV
rcc_ptcursor_free(krb5_context context, krb5_cc_ptcursor *cursor)
{
    /* TODO implement remote socket */
    struct dcc_ptcursor_data *data = (*cursor)->data;

    if (data->dir)
        closedir(data->dir);
    free(data->dirname);
    free(data->primary);
    free(data);
    free(*cursor);
    *cursor = NULL;
    return 0;
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

static krb5_error_code KRB5_CALLCONV
rcc_switch_to(krb5_context context, krb5_ccache cache)
{
    /* TODO implement remote socket */
    return -1;
    /*
    rcc_data *data = cache->data;
    char *primary_path = NULL, *dirname = NULL, *filename = NULL;
    krb5_error_code ret;

    ret = split_path(context, data->residual + 1, &dirname, &filename);
    if (ret)
        return ret;

    ret = primary_pathname(dirname, &primary_path);
    if (ret)
        goto cleanup;

    ret = write_primary_file(primary_path, filename);

cleanup:
    free(primary_path);
    free(dirname);
    free(filename);
    return ret;
    */
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
    rcc_switch_to,
};
