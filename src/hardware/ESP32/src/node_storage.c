/*
 * node_storage.c — persistence HAL. ESP-IDF NVS on target, a file on the host.
 */
#include "node_storage.h"

#include <stdio.h>
#include <string.h>

#if defined(ESP_PLATFORM)

/* ── ESP-IDF: NVS ────────────────────────────────────────────────────────── */

#include "nvs.h"
#include "nvs_flash.h"

#define NVS_NAMESPACE "iiot_node"

static nvs_handle_t g_nvs;
static int g_open = 0;

storage_status_t node_storage_init(void)
{
    esp_err_t err = nvs_flash_init();

    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        /*
         * A full or version-mismatched partition. Erasing loses the stored
         * epoch, so the next boot starts from zero and could reuse nonces
         * under a reloaded key. The session key is re-derived by a fresh
         * handshake after this, which gives a new key and makes the reset
         * safe -- but only because the handshake is unconditional at boot. If
         * key caching is ever added, this path must force a rekey explicitly.
         */
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) return STORAGE_ERR_IO;

    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &g_nvs) != ESP_OK)
        return STORAGE_ERR_IO;

    g_open = 1;
    return STORAGE_OK;
}

void node_storage_deinit(void)
{
    if (g_open) { nvs_close(g_nvs); g_open = 0; }
}

storage_status_t node_storage_get_u32(const char *key, uint32_t *out)
{
    esp_err_t err;

    if (!g_open || key == NULL || out == NULL) return STORAGE_ERR_IO;

    err = nvs_get_u32(g_nvs, key, out);
    if (err == ESP_ERR_NVS_NOT_FOUND) return STORAGE_NOT_FOUND;
    return (err == ESP_OK) ? STORAGE_OK : STORAGE_ERR_IO;
}

storage_status_t node_storage_set_u32(const char *key, uint32_t value)
{
    if (!g_open || key == NULL) return STORAGE_ERR_IO;

    if (nvs_set_u32(g_nvs, key, value) != ESP_OK) return STORAGE_ERR_IO;

    /* nvs_commit() is what makes the write survive a power cut. Without it
     * the value sits in a cache and the guarantee this module provides is
     * void. */
    return (nvs_commit(g_nvs) == ESP_OK) ? STORAGE_OK : STORAGE_ERR_IO;
}

void node_storage_host_reset(const char *path) { (void)path; }

#else

/* ── Host: a small text file ─────────────────────────────────────────────── */

#define MAX_ENTRIES 8
#define MAX_KEY     24

static char     g_path[512] = "node_storage.txt";
static char     g_keys[MAX_ENTRIES][MAX_KEY];
static uint32_t g_vals[MAX_ENTRIES];
static int      g_count = 0;
static int      g_open = 0;

static void load_from_disk(void)
{
    FILE *f = fopen(g_path, "r");
    char  key[MAX_KEY];
    unsigned long val;

    g_count = 0;
    if (f == NULL) return;

    while (g_count < MAX_ENTRIES && fscanf(f, "%23s %lu", key, &val) == 2) {
        strncpy(g_keys[g_count], key, MAX_KEY - 1);
        g_keys[g_count][MAX_KEY - 1] = '\0';
        g_vals[g_count] = (uint32_t)val;
        g_count++;
    }
    fclose(f);
}

static storage_status_t flush_to_disk(void)
{
    FILE *f = fopen(g_path, "w");
    int i;

    if (f == NULL) return STORAGE_ERR_IO;
    for (i = 0; i < g_count; i++)
        fprintf(f, "%s %lu\n", g_keys[i], (unsigned long)g_vals[i]);

    /* fclose flushes; on the host that is as durable as this needs to be. */
    return (fclose(f) == 0) ? STORAGE_OK : STORAGE_ERR_IO;
}

storage_status_t node_storage_init(void)
{
    load_from_disk();
    g_open = 1;
    return STORAGE_OK;
}

void node_storage_deinit(void)
{
    g_open = 0;
}

storage_status_t node_storage_get_u32(const char *key, uint32_t *out)
{
    int i;

    if (!g_open || key == NULL || out == NULL) return STORAGE_ERR_IO;

    for (i = 0; i < g_count; i++) {
        if (strcmp(g_keys[i], key) == 0) { *out = g_vals[i]; return STORAGE_OK; }
    }
    return STORAGE_NOT_FOUND;
}

storage_status_t node_storage_set_u32(const char *key, uint32_t value)
{
    int i;

    if (!g_open || key == NULL) return STORAGE_ERR_IO;

    for (i = 0; i < g_count; i++) {
        if (strcmp(g_keys[i], key) == 0) { g_vals[i] = value; return flush_to_disk(); }
    }
    if (g_count >= MAX_ENTRIES) return STORAGE_ERR_IO;

    strncpy(g_keys[g_count], key, MAX_KEY - 1);
    g_keys[g_count][MAX_KEY - 1] = '\0';
    g_vals[g_count] = value;
    g_count++;
    return flush_to_disk();
}

void node_storage_host_reset(const char *path)
{
    if (path != NULL) {
        strncpy(g_path, path, sizeof(g_path) - 1);
        g_path[sizeof(g_path) - 1] = '\0';
    }
    g_count = 0;
    remove(g_path);
}

#endif /* platform */
