/*
 * sensor_hal_esp32.c — real sensor reads on ESP-IDF.
 *
 * The only file in the leaf firmware that touches hardware. Everything above
 * it — scaling, quality flags, framing, encryption, the handshake — is
 * exercised on the host against sensor_hal_host.c.
 *
 *
 * ⚠ STATUS: NOT YET VALIDATED ON HARDWARE ⚠
 * =========================================
 * This compiles under ESP-IDF but has not been run on a board. Two things to
 * check on first bring-up, in this order:
 *
 *  1. **MCP3008 wiring and reference.** Confirm VREF, and confirm the
 *     single-ended channel mapping matches channel_config.c. A swapped
 *     voltage/current pair produces plausible-looking data that is silently
 *     wrong — precisely the failure mode the plausibility bands exist to
 *     catch, so watch for CH_QUALITY_RANGE on first boot.
 *
 *  2. **DHT22 timing.** The 1-wire protocol below is bit-banged with
 *     interrupts disabled. It is the fiddliest code here and the most likely
 *     to need adjustment for your board and IDF version. If it proves
 *     unreliable, replace it with a maintained component (esp-idf-lib's dht)
 *     rather than tuning the delays — this is not where the project's value
 *     lies.
 *
 * Calibrate scale/offset in channel_config.c against a reference meter before
 * trusting any number out of this file. The placeholders there are deliberately
 * round so an uncalibrated build is obvious in the data.
 */
#include "channel.h"

#ifdef ESP_PLATFORM

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <string.h>

/* ── SPI wiring for the MCP3008 ──────────────────────────────────────────── */

#define MCP3008_HOST      SPI2_HOST
#define PIN_MISO          19
#define PIN_MOSI          23
#define PIN_SCLK          18
#define PIN_CS            5
#define MCP3008_CLOCK_HZ  1350000   /* MCP3008 max at 3.3 V is ~1.35 MHz */

static spi_device_handle_t g_spi;
static int g_spi_ready = 0;

/* ── DHT22 ───────────────────────────────────────────────────────────────── */

/*
 * The DHT22 will not answer faster than once every ~2 s, but the sample loop
 * runs at 10 Hz. So the last good reading is cached and re-served, marked
 * CH_QUALITY_STALE once it ages past the refresh interval.
 *
 * Serving a stale-but-flagged value beats either blocking the loop (which
 * would break every other channel's cadence) or emitting a gap (which the
 * server cannot distinguish from a dropped frame).
 */
#define DHT_REFRESH_US    2000000
#define DHT_STALE_US      6000000   /* three missed refreshes -> STALE */

static struct {
    float    temperature;
    float    humidity;
    int64_t  last_us;
    int      valid;
} g_dht;

static int dht_read_raw(uint8_t pin, float *temp_out, float *hum_out)
{
    uint8_t  data[5] = {0};
    int      i, bit;
    int64_t  t0;
    uint16_t raw_h, raw_t;

    gpio_set_direction(pin, GPIO_MODE_OUTPUT);
    gpio_set_level(pin, 0);
    esp_rom_delay_us(1100);          /* start pulse: >= 1 ms low */
    gpio_set_level(pin, 1);
    esp_rom_delay_us(30);
    gpio_set_direction(pin, GPIO_MODE_INPUT);

    /*
     * Interrupts off for the bit loop. The DHT22 encodes a bit in the length
     * of a high pulse (~26 us for 0, ~70 us for 1), so a FreeRTOS tick or a
     * WiFi interrupt landing mid-pulse corrupts the reading. The window is
     * ~5 ms, which is acceptable at a 2 s refresh interval.
     */
    portDISABLE_INTERRUPTS();

    /* Response: 80 us low, then 80 us high. */
    t0 = esp_timer_get_time();
    while (gpio_get_level(pin) == 1) if (esp_timer_get_time() - t0 > 100) goto fail;
    t0 = esp_timer_get_time();
    while (gpio_get_level(pin) == 0) if (esp_timer_get_time() - t0 > 100) goto fail;
    t0 = esp_timer_get_time();
    while (gpio_get_level(pin) == 1) if (esp_timer_get_time() - t0 > 100) goto fail;

    for (i = 0; i < 40; i++) {
        int64_t high_start;

        t0 = esp_timer_get_time();
        while (gpio_get_level(pin) == 0)
            if (esp_timer_get_time() - t0 > 100) goto fail;

        high_start = esp_timer_get_time();
        while (gpio_get_level(pin) == 1)
            if (esp_timer_get_time() - high_start > 150) goto fail;

        /* Long high pulse = 1. The 50 us threshold sits between the nominal
         * 26 us and 70 us, which is the widest margin available. */
        bit = (esp_timer_get_time() - high_start) > 50;
        data[i / 8] = (uint8_t)((data[i / 8] << 1) | (uint8_t)bit);
    }

    portENABLE_INTERRUPTS();

    /* Checksum: the low byte of the sum of the first four. */
    if (((data[0] + data[1] + data[2] + data[3]) & 0xFF) != data[4])
        return -1;

    raw_h = (uint16_t)((data[0] << 8) | data[1]);
    raw_t = (uint16_t)((data[2] << 8) | data[3]);

    *hum_out  = (float)raw_h / 10.0f;
    /* Bit 15 of the temperature word is a sign bit, not part of the value. */
    *temp_out = (raw_t & 0x8000)
        ? -((float)(raw_t & 0x7FFF) / 10.0f)
        :   (float)raw_t / 10.0f;
    return 0;

fail:
    portENABLE_INTERRUPTS();
    return -1;
}

static void dht_refresh(uint8_t pin)
{
    int64_t now = esp_timer_get_time();
    float   t, h;

    if (g_dht.valid && (now - g_dht.last_us) < DHT_REFRESH_US) return;

    if (dht_read_raw(pin, &t, &h) == 0) {
        g_dht.temperature = t;
        g_dht.humidity    = h;
        g_dht.last_us     = now;
        g_dht.valid       = 1;
    }
    /* On failure the cached value stands and ages into STALE below. */
}

/* ── HAL entry points ────────────────────────────────────────────────────── */

int sensor_hal_init(const channel_desc_t *channels, size_t count)
{
    spi_bus_config_t bus = {
        .miso_io_num = PIN_MISO,
        .mosi_io_num = PIN_MOSI,
        .sclk_io_num = PIN_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 32,
    };
    spi_device_interface_config_t dev = {
        .clock_speed_hz = MCP3008_CLOCK_HZ,
        .mode = 0,
        .spics_io_num = PIN_CS,
        .queue_size = 1,
    };
    size_t i;

    memset(&g_dht, 0, sizeof(g_dht));

    if (spi_bus_initialize(MCP3008_HOST, &bus, SPI_DMA_CH_AUTO) != ESP_OK) return -1;
    if (spi_bus_add_device(MCP3008_HOST, &dev, &g_spi) != ESP_OK) return -1;
    g_spi_ready = 1;

    /* Configure every GPIO the table mentions. Driven from the table, so a
     * new channel needs no change here. */
    for (i = 0; i < count; i++) {
        if (channels[i].source == CH_SRC_GPIO) {
            gpio_set_direction(channels[i].pin, GPIO_MODE_INPUT);
            gpio_set_pull_mode(channels[i].pin, GPIO_PULLUP_ONLY);
        } else if (channels[i].source == CH_SRC_ONEWIRE) {
            gpio_set_pull_mode(channels[i].pin, GPIO_PULLUP_ONLY);
        }
    }
    return 0;
}

void sensor_hal_deinit(void)
{
    if (g_spi_ready) {
        spi_bus_remove_device(g_spi);
        spi_bus_free(MCP3008_HOST);
        g_spi_ready = 0;
    }
}

/*
 * MCP3008 single-ended read.
 *
 * Three bytes out: a start bit, then the SGL/DIFF bit and the 3-bit channel
 * left-aligned, then a filler byte while the device clocks the result back.
 * The 10-bit result arrives in the low 2 bits of rx[1] and all of rx[2].
 */
static int mcp3008_read(uint8_t adc_channel, uint16_t *out)
{
    spi_transaction_t tx;
    uint8_t txbuf[3], rxbuf[3];

    if (!g_spi_ready || adc_channel > 7) return -1;

    txbuf[0] = 0x01;
    txbuf[1] = (uint8_t)(0x80 | (adc_channel << 4));
    txbuf[2] = 0x00;

    memset(&tx, 0, sizeof(tx));
    tx.length    = 8 * 3;
    tx.tx_buffer = txbuf;
    tx.rx_buffer = rxbuf;

    if (spi_device_polling_transmit(g_spi, &tx) != ESP_OK) return -1;

    *out = (uint16_t)(((rxbuf[1] & 0x03) << 8) | rxbuf[2]);
    return 0;
}

int sensor_hal_read(const channel_desc_t *desc, channel_reading_t *out)
{
    if (desc == NULL || out == NULL) return -1;

    out->value   = 0.0f;
    out->quality = CH_QUALITY_NOT_READY;

    switch (desc->source) {
    case CH_SRC_ADC: {
        uint16_t raw;
        if (mcp3008_read(desc->pin, &raw) != 0) {
            out->quality = CH_QUALITY_FAULT;
            return -1;
        }
        out->value   = (float)raw;      /* raw counts; channel.c scales */
        out->quality = CH_QUALITY_GOOD;
        return 0;
    }

    case CH_SRC_GPIO:
        out->value   = gpio_get_level(desc->pin) ? 1.0f : 0.0f;
        out->quality = CH_QUALITY_GOOD;
        return 0;

    case CH_SRC_ONEWIRE: {
        int64_t age;

        dht_refresh(desc->pin);
        if (!g_dht.valid) {
            out->quality = CH_QUALITY_NOT_READY;
            return -1;
        }

        out->value = (desc->sub == 0) ? g_dht.temperature : g_dht.humidity;

        age = esp_timer_get_time() - g_dht.last_us;
        out->quality = (age > DHT_STALE_US) ? CH_QUALITY_STALE : CH_QUALITY_GOOD;
        return 0;
    }

    default:
        out->quality = CH_QUALITY_FAULT;
        return -1;
    }
}

#endif /* ESP_PLATFORM */
