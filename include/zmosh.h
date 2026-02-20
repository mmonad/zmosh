#ifndef ZMOSH_H
#define ZMOSH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque session handle */
typedef struct zmosh_session zmosh_session_t;

/* Status codes */
typedef enum {
    ZMOSH_OK              = 0,
    ZMOSH_ERR_RESOLVE     = 1,
    ZMOSH_ERR_SOCKET      = 2,
    ZMOSH_ERR_INVALID_KEY = 3,
    ZMOSH_ERR_DISCONNECTED = 4,
    ZMOSH_ERR_DEAD        = 5,
    ZMOSH_ERR_POLL        = 6,
    ZMOSH_ERR_NULL        = 7,
    ZMOSH_ERR_SEND        = 8,
    ZMOSH_ERR_TOO_LARGE   = 9,
} zmosh_status_t;

/* Max bytes per zmosh_send_input call (8192). */
#define ZMOSH_MAX_INPUT_LEN 8192

/* Connection state */
typedef enum {
    ZMOSH_STATE_CONNECTED    = 0,
    ZMOSH_STATE_DISCONNECTED = 1,
    ZMOSH_STATE_DEAD         = 2,
} zmosh_state_t;

/* Callbacks */
typedef void (*zmosh_output_fn)(void *ctx, const uint8_t *data, uint32_t len);
typedef void (*zmosh_state_fn)(void *ctx, zmosh_state_t state);
typedef void (*zmosh_session_end_fn)(void *ctx);

/*
 * Connect to a remote zmosh gateway over encrypted UDP.
 *
 * host:       hostname or IP (null-terminated)
 * port:       UDP port
 * key_base64: base64-encoded 32-byte session key (null-terminated)
 * rows, cols: initial terminal dimensions
 * output_cb:  called with terminal output bytes (required)
 * state_cb:   called on connection state changes (may be NULL)
 * end_cb:     called when the remote session ends (may be NULL)
 * ctx:        opaque pointer passed to all callbacks
 * status:     receives status code on failure (may be NULL)
 *
 * Returns a session handle, or NULL on failure.
 */
zmosh_session_t *zmosh_connect(
    const char *host,
    uint16_t port,
    const char *key_base64,
    uint16_t rows,
    uint16_t cols,
    zmosh_output_fn output_cb,
    zmosh_state_fn state_cb,
    zmosh_session_end_fn end_cb,
    void *ctx,
    zmosh_status_t *status
);

/*
 * Get the UDP socket file descriptor for event loop integration.
 * Use with GCD DispatchSource, kqueue, or poll().
 * Call zmosh_poll() when the fd is readable.
 */
int zmosh_get_fd(const zmosh_session_t *session);

/*
 * Process pending UDP data, send heartbeats, update state.
 * Call when the fd is readable, or periodically (~500ms) for heartbeats.
 * Invokes callbacks during this call.
 */
zmosh_status_t zmosh_poll(zmosh_session_t *session);

/* Send terminal input bytes to the remote session. */
zmosh_status_t zmosh_send_input(zmosh_session_t *session,
                                const uint8_t *data, uint32_t len);

/* Notify the remote session of a terminal resize. */
zmosh_status_t zmosh_resize(zmosh_session_t *session,
                            uint16_t rows, uint16_t cols);

/* Disconnect and free all resources. Handle is invalid after this call. */
void zmosh_disconnect(zmosh_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* ZMOSH_H */
