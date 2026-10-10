/*
 * channel.c — sampling loop over the channel table.
 *
 * Platform-independent: the actual reads go through sensor_hal_read(), which
 * has an ESP-IDF implementation and a host implementation. Everything above
 * that line — scaling, plausibility checking, quality flags — is tested on the
 * host without a board attached.
 */
#include "channel.h"

#include <string.h>

void channel_sample_all(const channel_desc_t *channels, size_t count,
                        channel_reading_t *out)
{
    size_t i;

    if (channels == NULL || out == NULL) {
        return;
    }

    for (i = 0; i < count; i++) {
        channel_reading_t raw;

        /*
         * Pre-fill so that a HAL which returns non-zero without writing
         * anything still leaves a well-defined, clearly-flagged sample. A
         * gap in the series would be indistinguishable from a dropped frame
         * at the gateway; a flagged zero is not.
         */
        raw.value   = 0.0f;
        raw.quality = CH_QUALITY_NOT_READY;

        if (sensor_hal_read(&channels[i], &raw) != 0) {
            if (raw.quality == CH_QUALITY_GOOD) {
                raw.quality = CH_QUALITY_FAULT;
            }
            out[i] = raw;
            continue;
        }

        /* Raw counts -> engineering units. The LSTM must see physical units,
         * or it has to be retrained whenever a divider changes. */
        out[i].value   = raw.value * channels[i].scale + channels[i].offset;
        out[i].quality = raw.quality;

        /*
         * Plausibility band. Flag rather than clamp or drop: the value still
         * travels, marked, so the server can tell a sensor fault from a
         * genuine excursion. Clamping would hide a real fault; dropping would
         * look like an outage.
         *
         * Both bounds zero means the check is disabled (a relay's 0/1).
         */
        if (channels[i].min_valid != 0.0f || channels[i].max_valid != 0.0f) {
            if (out[i].value < channels[i].min_valid ||
                out[i].value > channels[i].max_valid) {
                out[i].quality |= CH_QUALITY_RANGE;
            }
        }
    }
}
