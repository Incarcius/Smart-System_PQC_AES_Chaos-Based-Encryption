/*
 * channel_config.c — the prototype's channel table.
 *
 * THIS IS THE ONE FILE TO EDIT WHEN THE SENSOR SET CHANGES. Nothing else in
 * the firmware knows what a ZMPT101B is; everything loops over this table.
 * Adding a channel to an industry deployment is an entry here, not a code
 * change, up to NODE_MAX_CHANNELS (32, bounded by tg_control_t.node_mask).
 *
 * channel_id is the bit index in node_mask, so it must be stable: renumbering
 * channels after the LSTM has been trained silently changes what every
 * quarantine command means.
 *
 * The scale/offset values below are PLACEHOLDERS pending calibration against
 * a reference meter. They are deliberately obvious round numbers so an
 * uncalibrated build is easy to spot in the data rather than quietly wrong.
 */
#include "channel.h"

const channel_desc_t NODE_CHANNELS[] = {
    {
        .channel_id = 0,
        .source     = CH_SRC_ADC,
        .pin        = 0,                 /* MCP3008 CH0 */
        .sub        = 0,
        /* 10-bit ADC, 3.3 V reference, through the ZMPT101B divider.
         * Placeholder: assumes 0..250 V maps across the full ADC span. */
        .scale      = 250.0f / 1023.0f,
        .offset     = 0.0f,
        .min_valid  = 0.0f,
        .max_valid  = 300.0f,
        .name       = "voltage",
    },
    {
        .channel_id = 1,
        .source     = CH_SRC_ADC,
        .pin        = 1,                 /* MCP3008 CH1 */
        .sub        = 0,
        /* ACS712 is bipolar and centred at Vcc/2, hence the negative offset. */
        .scale      = 30.0f / 1023.0f,
        .offset     = -15.0f,
        .min_valid  = -20.0f,
        .max_valid  = 20.0f,
        .name       = "current",
    },
    {
        .channel_id = 2,
        .source     = CH_SRC_ONEWIRE,
        .pin        = 4,                 /* DHT22 data line */
        .sub        = 0,                 /* temperature */
        .scale      = 1.0f,
        .offset     = 0.0f,
        .min_valid  = -40.0f,
        .max_valid  = 80.0f,
        .name       = "temperature",
    },
    {
        .channel_id = 3,
        .source     = CH_SRC_ONEWIRE,
        .pin        = 4,                 /* same wire as channel 2 */
        .sub        = 1,                 /* humidity */
        .scale      = 1.0f,
        .offset     = 0.0f,
        .min_valid  = 0.0f,
        .max_valid  = 100.0f,
        .name       = "humidity",
    },
    {
        .channel_id = 4,
        .source     = CH_SRC_GPIO,
        .pin        = 5,                 /* relay state */
        .sub        = 0,
        .scale      = 1.0f,
        .offset     = 0.0f,
        /* Both zero disables the range check — 0/1 is always in range. */
        .min_valid  = 0.0f,
        .max_valid  = 0.0f,
        .name       = "relay_state",
    },
};

const size_t NODE_CHANNEL_COUNT = sizeof(NODE_CHANNELS) / sizeof(NODE_CHANNELS[0]);
