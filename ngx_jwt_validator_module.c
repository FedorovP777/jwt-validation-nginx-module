#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include <stddef.h>
#include "jwt_validator.h"

typedef struct {
    ngx_int_t status;
    ngx_http_complex_value_t *text;
    ngx_str_t jwt_token_secret;
} ngx_http_jwt_validator_loc_conf_t;


static char *ngx_http_jwt_validator(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_jwt_validator_create_loc_conf(ngx_conf_t *cf);

static ngx_int_t
ngx_http_jwt_access_handler(ngx_http_request_t *r);

static ngx_command_t ngx_foo_commands[] = {

    {ngx_string("jwt_validator"), NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, ngx_http_jwt_validator, 0, 0, NULL},
    {
        ngx_string("jwt_token_param"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_jwt_validator_loc_conf_t, text),
        NULL
    },
    {
        ngx_string("jwt_token_secret_text"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_jwt_validator_loc_conf_t, jwt_token_secret),
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

static ngx_http_module_t ngx_http_jwt_validator_module_ctx = {
    NULL,
    ngx_http_jwt_postconfiguration,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_jwt_validator_create_loc_conf,
    NULL
};

ngx_module_t ngx_jwt_validator_module = {
    NGX_MODULE_V1,
    &ngx_http_jwt_validator_module_ctx, /* module context */
    ngx_foo_commands, /* module directives */
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

static char *ngx_http_jwt_validator(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    return NGX_CONF_OK;
}

static void *ngx_http_jwt_validator_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_jwt_validator_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwt_validator_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->status = NGX_CONF_UNSET;

    return conf;
}


static ngx_int_t
ngx_http_jwt_access_handler(ngx_http_request_t *r) {
    ngx_http_jwt_validator_loc_conf_t *hlcf = ngx_http_get_module_loc_conf(r, ngx_jwt_validator_module);
    ngx_str_t text;

    if (ngx_http_complex_value(r, hlcf->text, &text) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_log_debug1(NGX_LOG_DEBUG, r->connection->log, 0, "JWT Token %s", text.data);
    const int is_valid_jwt = verify_jwt(
        text.data,
        text.len,
        hlcf->jwt_token_secret.data,
        hlcf->jwt_token_secret.len
    );
    if (is_valid_jwt != 1) {
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_DECLINED;
}
