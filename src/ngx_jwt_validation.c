#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/hmac.h>

typedef struct {
    ngx_flag_t jwt_validation_enable;
    ngx_http_complex_value_t *token;
    ngx_http_complex_value_t *token_second;
    ngx_str_t jwt_token_secret;
} ngx_http_jwt_validation_loc_conf_t;


static void *
ngx_http_jwt_validator_create_loc_conf(ngx_conf_t *cf);

static ngx_int_t
ngx_http_jwt_access_handler(ngx_http_request_t *r);

static ngx_command_t ngx_jwt_validation_commands[] = {

    {
        ngx_string("jwt_validation_enable"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_jwt_validation_loc_conf_t, jwt_validation_enable),
        NULL
    },
    {
        ngx_string("jwt_token_param"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
        NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_jwt_validation_loc_conf_t, token),
        NULL
    },
    {
        ngx_string("jwt_token_param_second"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
        NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_jwt_validation_loc_conf_t, token_second),
        NULL
    },
    {
        ngx_string("jwt_token_secret"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
        NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_jwt_validation_loc_conf_t, jwt_token_secret),
        NULL
    },
    ngx_null_command
};


static ngx_int_t
ngx_http_jwt_postconfiguration(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_jwt_access_handler;
    return NGX_OK;
}

static ngx_http_module_t ngx_http_jwt_validation_module_ctx = {
    NULL,
    ngx_http_jwt_postconfiguration,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_jwt_validator_create_loc_conf,
    NULL
};

ngx_module_t ngx_jwt_validation = {
    NGX_MODULE_V1,
    &ngx_http_jwt_validation_module_ctx, /* module context */
    ngx_jwt_validation_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_jwt_validator_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_jwt_validation_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwt_validation_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->jwt_validation_enable = NGX_CONF_UNSET;

    return conf;
}

static int cacl_hmac(
    const unsigned char *jwt_secret,
    const int jwt_secret_len,
    const unsigned char *jwt,
    const int len_jwt,
    unsigned char *sig,
    unsigned int *sig_len
) {
    const unsigned char *result = HMAC(
        EVP_sha256(),
        jwt_secret,
        jwt_secret_len,
        jwt,
        len_jwt,
        sig,
        sig_len
    );
    if (result == NULL) {
        return -1;
    }
    return 0;
}


static int get_last_char_pos(const ngx_str_t *str, char ch) {
    for (int i = str->len - 1; i >= 0; i--) {
        if (str->data[i] == ch) {
            return i;
        }
    }
    return -1;
}

static const char *jwt_prefix = "Bearer ";

static ngx_int_t
ngx_http_jwt_access_handler(ngx_http_request_t *r) {
    ngx_http_jwt_validation_loc_conf_t *hlcf = ngx_http_get_module_loc_conf(r, ngx_jwt_validation);

    if (hlcf == NULL || hlcf->jwt_validation_enable == NGX_CONF_UNSET) {
        return NGX_DECLINED;
    }

    ngx_str_t jwt_token = {.len = 0, .data = NULL};

    if (hlcf->token != NULL && ngx_http_complex_value(r, hlcf->token, &jwt_token) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (jwt_token.len == 0) {
        if (hlcf->token_second != NULL && ngx_http_complex_value(r, hlcf->token_second, &jwt_token) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (jwt_token.len == 0) {
        return NGX_HTTP_FORBIDDEN;
    }
    if (memcmp(jwt_token.data, jwt_prefix, strlen(jwt_prefix)) == 0) {
        jwt_token.data = jwt_token.data + strlen(jwt_prefix);
        jwt_token.len -= strlen(jwt_prefix);
    }
    const int last_dot = get_last_char_pos(&jwt_token, '.');
    if (last_dot == -1) {
        return NGX_HTTP_FORBIDDEN;
    }
    u_char *start_payload_pos = &jwt_token.data[last_dot + 1];
    const int payload_len = jwt_token.len - last_dot - 1;
    ngx_str_t payload_base64_str = {.len = payload_len, .data = start_payload_pos};
    ngx_str_t payload_bytes;
    payload_bytes.data = ngx_palloc(r->pool, payload_len * sizeof(u_char));
    payload_bytes.len = payload_len;
    if (payload_bytes.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    const ngx_int_t result_base64_decode = ngx_decode_base64url(&payload_bytes, &payload_base64_str);
    if (result_base64_decode == NGX_ERROR) {
        return NGX_HTTP_FORBIDDEN;
    }

    unsigned char expected_sig[EVP_MAX_MD_SIZE];
    ngx_str_t signature = {.len = 0, .data = expected_sig};
    const int hmac_result = cacl_hmac(
        hlcf->jwt_token_secret.data,
        hlcf->jwt_token_secret.len,
        jwt_token.data,
        last_dot,
        signature.data,
        (unsigned int *) &signature.len
    );

    if (hmac_result != NGX_OK) {
        return NGX_HTTP_FORBIDDEN;
    }
    if (signature.len != payload_bytes.len || ngx_memcmp(signature.data, payload_bytes.data, signature.len) != 0) {
        return NGX_HTTP_FORBIDDEN;
    };

    return NGX_DECLINED;
}
