/* Media streams of a session (libnpf npf_media_*; data-channel.md 14).
 *
 *   - On AnLiu (direct path, UDP relay): each media stream is an AnLiu
 *     semi-reliable stream of its own, opened and closed with it (AnLiu's
 *     close tells the peer); frames go as they are, the frame numbers and
 *     loss counts are AnLiu's.
 *   - On the WS relay: records of channel 2 with a small header (the streams
 *     share one byte stream), opened and closed with MEDIA units, queued here
 *     so that a send never blocks; frames older than max_age are dropped,
 *     the forwards' data yields to the media. */
#ifndef NPF_MEDIA_H
#define NPF_MEDIA_H

#include <stddef.h>
#include <stdint.h>

#include "anliu.h"
#include "npf/loop.h"
#include "npf/node.h"

#define NPF_TAG_MEDIA      16       /* AnLiu tag: NPF_TAG_MEDIA + the application's tag (0..999) */
#define NPF_MEDIA_TAGS     1000
#define NPF_MEDIA_TAG_RDK  0x8000   /* tag bit: the receiver drops non-key frames after a loss */
#define NPF_MEDIA_OUT_MAX  30       /* AnLiu streams one side opens: 2 x 30 + sid 0 + the data
                                       stream = 62 of AnLiu's 64 (closing ones count until confirmed) */
#define NPF_MEDIA_MAX      256      /* logical streams per session at once */
/* AnLiu receive windows (segments). A stream's rcv_wnd is the opener's
 * choice, up to ANL_MAX_WND (32768), and the receiver may have to hold
 * that many out-of-order segments of it whether the application reads or
 * not (AnLiu SECURITY_AUDIT.md 4.1: ~3 GB a connection at 63 streams of
 * 32768). Both ends open with these and refuse a peer's stream above them:
 * a session holds at most 4096 + 4096 + 30 x 512 segments (~25 MB). */
#define NPF_ANL_CTRL_WND   4096     /* sid 0: control (our cfg.default_rcv_wnd) */
#define NPF_ANL_DATA_WND   4096     /* the data stream (5 MB: 10 MB/s up to 500 ms RTT) */
#define NPF_ANL_MEDIA_WND  512      /* each media stream */
#define NPF_MEDIA_FRAME_MAX (4 << 20)
#define NPF_FRAME_KEY_FLAG 1             /* = NPF_FRAME_KEY of npf.h */

typedef struct npf_media npf_media;

typedef struct npf_media_io {
    /* a MEDIA unit to the peer (the tunnel's control channel); 0 or -1 */
    int    (*unit)(void *arg, const uint8_t *buf, size_t len);
    /* WS relay: one record of channel 2; 0 or -1 */
    int    (*ws_write)(void *arg, const uint8_t *buf, size_t len);
    /* WS relay: bytes written and not yet on the wire; all bytes handed to it */
    void   (*ws_backlog)(void *arg, size_t *pending, uint64_t *total);
    /* AnLiu: frames were queued, flush soon */
    void   (*kick)(void *arg);
    /* the peer opened a stream: 1 takes it */
    int    (*on_open)(void *arg, uint32_t id, int tag);
    void   (*on_frame)(void *arg, uint32_t id, const uint8_t *buf, size_t len, uint32_t frame_no, int flags,
                       uint32_t lost_before);
    /* the stream ended from the other side (closed or refused there) */
    void   (*on_closed)(void *arg, uint32_t id);
    /* a callback ended the session: stop delivering */
    int    (*ended)(void *arg);
} npf_media_io;

/* anl NULL: the WS relay; odd: this side's ids are odd (the callee) */
npf_media *npf_media_new(npf_loop *loop, anl_t *anl, int odd, const npf_media_io *io, void *arg);
/* the session ended: everything goes without callbacks */
void npf_media_free(npf_media *m);

/* AnLiu: the accept callback for a media stream of the peer (its tag in
 * NPF_TAG_MEDIA ..); 0 takes it for now, the application is asked in
 * npf_media_poll after the input */
int  npf_media_accept(npf_media *m, anl_stream_t *s, anl_stream_opt *opt);
int  npf_media_poll(npf_media *m);
/* is s a media stream (ours or the peer's)? */
int  npf_media_is_stream(const npf_media *m, anl_stream_t *s);
/* s is readable: its frames to the application, or its end. -1 when a
 * callback ended the session (stop reading) */
int  npf_media_drain(npf_media *m, anl_stream_t *s);
/* a MEDIA unit / a WS record of channel 2 from the peer */
void npf_media_unit_input(npf_media *m, const uint8_t *buf, size_t len);
void npf_media_ws_input(npf_media *m, const uint8_t *buf, size_t len);
/* WS relay: frames waiting here (the forwards' data yields while there are any) */
size_t npf_media_ws_queued(const npf_media *m);
int  npf_media_count(const npf_media *m);

/* the application's side; errors NPF_CALL_E* */
uint32_t npf_media_open_stream(npf_media *m, const npf_call_media_opt *o, int *err);
/* t_submit: when the application gave the frame (npf_mono_ms), 0: now */
int  npf_media_send_frame(npf_media *m, uint32_t id, int flags, const void *buf, size_t len, int64_t t_submit);
int  npf_media_stream_stats(npf_media *m, uint32_t id, npf_call_media_stats *out);
int  npf_media_close_stream(npf_media *m, uint32_t id);

#endif
