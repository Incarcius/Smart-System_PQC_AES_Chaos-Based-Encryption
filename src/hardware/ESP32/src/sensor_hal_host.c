/*
 * sensor_hal_host.c — synthetic sensors for host builds.
 *
 * Two jobs:
 *
 *   1. Make the whole leaf data path testable without a board — sampling,
 *      scaling, framing, encryption, COBS, all of it.
 *   2. Let the gateway daemon be developed and soaked against a realistic
 *      10 Hz stream before any hardware exists.
 *
 * Deterministic by construction: the signals are closed-form functions of a
 * sample counter, not of wall-clock time or an RNG, so a test that passes once
 * passes every time and a KAT over the output is meaningful.
 *
 * Values are RAW (ADC counts, GPIO levels). channel.c applies scale/offset,
 * exactly as it will with the real HAL.
 */
#include "channel.h"

#include <math.h>
#include <stddef.h>

static uint64_t g_tick = 0;
static int      g_initialised = 0;

/* Fault injection for tests: force the next N reads of a channel to fail. */
static int      g_fault_channel = -1;
static int      g_fault_count   = 0;

int sensor_hal_init(const channel_desc_t *channels, size_t count)
{
    (void)channels;
    (void)count;
    g_tick = 0;
    g_initialised = 1;
    return 0;
}

void sensor_hal_deinit(void)
{
    g_initialised = 0;
}

/* Test hook — not part of the HAL contract, host build only. */
void sensor_hal_host_inject_fault(int channel_id, int count)
{
    g_fault_channel = channel_id;
    g_fault_count   = count;
}

void sensor_hal_host_set_tick(uint64_t tick)
{
    g_tick = tick;
}

int sensor_hal_read(const channel_desc_t *desc, channel_reading_t *out)
{
    double phase;

    if (desc == NULL || out == NULL) return -1;
    if (!g_initialised) {
        out->value   = 0.0f;
        out->quality = CH_QUALITY_NOT_READY;
        return -1;
    }

    if (g_fault_channel == (int)desc->channel_id && g_fault_count > 0) {
        g_fault_count--;
        out->value   = 0.0f;
        out->quality = CH_QUALITY_STALE;
        return -1;
    }

    /* 10 Hz sampling, so one tick is 0.1 s. */
    phase = (double)g_tick * 0.1;

    switch (desc->source) {
    case CH_SRC_ADC:
        if (desc->pin == 0) {
            /* Voltage: ~230 V nominal with a slow swell, in ADC counts given
             * the 250 V full-scale placeholder in channel_config.c. */
            out->value = (float)(941.0 + 12.0 * sin(phase * 0.5));
        } else {
            /* Current: ACS712 is centred at mid-scale, ~5 A load. */
            out->value = (float)(682.0 + 40.0 * sin(phase * 0.7));
        }
        out->quality = CH_QUALITY_GOOD;
        break;

    case CH_SRC_ONEWIRE:
        /* One wire, two measurands: sub 0 temperature, sub 1 humidity. */
        out->value = (desc->sub == 0)
            ? (float)(35.0 + 2.0 * sin(phase * 0.05))
            : (float)(50.0 + 5.0 * sin(phase * 0.03));
        out->quality = CH_QUALITY_GOOD;
        break;

    case CH_SRC_GPIO:
        /* Relay: closed, opening briefly every 30 s. */
        out->value   = ((g_tick / 300) % 2 == 0) ? 1.0f : 0.0f;
        out->quality = CH_QUALITY_GOOD;
        break;

    default:
        out->value   = 0.0f;
        out->quality = CH_QUALITY_FAULT;
        return -1;
    }

    return 0;
}

/* Advance the synthetic clock. The real HAL has no equivalent — time passes
 * on its own there. */
void sensor_hal_host_tick(void)
{
    g_tick++;
}
