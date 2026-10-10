/*
 * channel.h — measurement channels on a crypto endpoint.
 *
 * A "channel" is one measurand: a voltage, a current, a temperature, a relay
 * state. It is the unit the LSTM attributes anomalies to and the unit
 * `tg_control_t.node_mask` quarantines. It is NOT a unit of key ownership —
 * keys belong to the endpoint (the ESP32), which is why quarantining a channel
 * isolates its series but recycles the whole endpoint's key.
 * See docs/REMAINING_WORK.md §0b.
 *
 * Channels are configuration, not code
 * ------------------------------------
 * The prototype has 5 sensors, some analog (through the MCP3008 ADC over SPI)
 * and some digital (GPIO or 1-wire). Industry deployments have n, in
 * combinations nobody is going to tell us in advance. So the firmware does not
 * know what a "ZMPT101B" is: it reads a table of channel descriptors and loops
 * over it. Adding a sensor is a table entry, not a code change, and the same
 * binary runs a 5-channel prototype and a 20-channel substation node.
 *
 * Raw-to-engineering conversion lives here too, because the LSTM must see
 * physical units. A model trained on ADC counts would have to be retrained the
 * moment anyone changed a voltage divider.
 */
#ifndef NODE_CHANNEL_H
#define NODE_CHANNEL_H

#include <stdint.h>
#include <stddef.h>

/* Bounded by tg_control_t.node_mask, which is a 32-bit bitmap. */
#define NODE_MAX_CHANNELS 32

typedef enum {
    /* Analog, read through the MCP3008 ADC over SPI. `pin` is the ADC
     * channel number 0..7. */
    CH_SRC_ADC = 0,

    /* Digital level read straight off a GPIO. `pin` is the GPIO number. */
    CH_SRC_GPIO = 1,

    /* Single-wire sensor with its own protocol (DHT22 and friends).
     * `pin` is the GPIO number; `sub` selects which measurand the device
     * returns — a DHT22 gives temperature AND humidity on one wire, so it
     * occupies two channels sharing a pin. */
    CH_SRC_ONEWIRE = 2,

    CH_SRC__COUNT
} channel_source_t;

/* Quality flags. A reading that is stale or out of range must be distinguishable
 * from a genuine excursion, or the LSTM learns to call sensor faults attacks. */
typedef enum {
    CH_QUALITY_GOOD      = 0x00,
    CH_QUALITY_STALE     = 0x01,   /* device did not respond in time      */
    CH_QUALITY_RANGE     = 0x02,   /* raw value outside the plausible band */
    CH_QUALITY_FAULT     = 0x04,   /* device reported an error            */
    CH_QUALITY_NOT_READY = 0x08    /* first read not completed yet        */
} channel_quality_t;

typedef struct {
    uint8_t          channel_id;   /* 0..31 — the bit index in node_mask   */
    channel_source_t source;
    uint8_t          pin;          /* ADC channel or GPIO number           */
    uint8_t          sub;          /* sub-measurand for multi-value devices */

    /* value = raw * scale + offset, in engineering units. */
    float            scale;
    float            offset;

    /* Plausibility band, used to set CH_QUALITY_RANGE. Set both to 0 to
     * disable the check (sensible for a relay's 0/1). */
    float            min_valid;
    float            max_valid;

    const char      *name;         /* for logs only; never on the wire */
} channel_desc_t;

typedef struct {
    float   value;
    uint8_t quality;               /* bitwise channel_quality_t */
} channel_reading_t;

/*
 * The sensor HAL. Two implementations exist:
 *
 *   sensor_hal_esp32.c  real SPI / GPIO / 1-wire on ESP-IDF
 *   sensor_hal_host.c   synthetic signals for host tests and for developing
 *                       the gateway without hardware attached
 *
 * Keeping the split here means the whole data path — sampling, conversion,
 * framing, encryption — is testable on a laptop. Only these three functions
 * actually need a board.
 */
int  sensor_hal_init(const channel_desc_t *channels, size_t count);

/*
 * Read one channel. Returns 0 on success; on failure it must still write a
 * reading with the appropriate quality flag rather than leaving it untouched,
 * so a failed sensor produces a flagged sample instead of a gap.
 */
int  sensor_hal_read(const channel_desc_t *desc, channel_reading_t *out);

void sensor_hal_deinit(void);

/*
 * Sample every channel in the table into `out` (which must hold `count`
 * entries). Applies scaling and the plausibility check. Always fills every
 * entry, flagging rather than skipping on error.
 */
void channel_sample_all(const channel_desc_t *channels, size_t count,
                        channel_reading_t *out);

/* The prototype's 5-channel table. Defined in channel_config.c so the wiring
 * lives in exactly one place. */
extern const channel_desc_t NODE_CHANNELS[];
extern const size_t         NODE_CHANNEL_COUNT;

#endif /* NODE_CHANNEL_H */
