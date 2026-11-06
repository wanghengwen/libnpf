/* Media streams and channels of a session (libnpf npf_media_*,
 * npf_channel_*; data-channel.md 14): each is an AnLiu stream of its own, on
 * whichever carrier the connection runs (UDP or the WS relay), opened and
 * closed with it (AnLiu's close tells the peer). A media stream is a
 * semi-reliable stream of frames, sent as they are, the frame numbers and
 * loss counts AnLiu's; a channel is a reliable byte stream, both sides send
 * on it. */
#ifndef NPF_MEDIA_H
#define NPF_MEDIA_H

#include <stddef.h>
#include <stdint.h>

#include "anliu.h"
#include "npf.h"                    /* NPF_MEDIA_FRAME_MAX, NPF_FRAME_KEY */
#include "npf/node.h"

#define NPF_TAG_MEDIA      16       /* AnLiu tag: NPF_TAG_MEDIA + the application's tag (0..999) */
#define NPF_MEDIA_TAGS     1000
#define NPF_MEDIA_TAG_RDK  0x8000   /* tag bit: the receiver drops non-key frames after a loss */
#define NPF_TAG_CHAN       2048     /* AnLiu tag of a channel: NPF_TAG_CHAN + the application's tag (0..999) */
#define NPF_MEDIA_OUT_MAX  30       /* AnLiu streams one side opens, media and channels together: 2 x 30 +
                                       sid 0 + the data and the UDP stream = 63 of AnLiu's 64 (closing ones
                                       count until confirmed) */
#define NPF_CHAN_LINGER_MS 30000    /* a channel closed here waits this long at most for its data to be
                                       acknowledged (a peer that paused it), then goes */
/* AnLiu receive windows (segments). A stream's rcv_wnd is the opener's
 * choice, up to ANL_MAX_WND (32768), and the receiver may have to hold
 * that many out-of-order segments of it whether the application reads or
 * not (AnLiu SECURITY_AUDIT.md 4.1: ~3 GB a connection at 63 streams of
 * 32768). Both ends open with these and refuse a peer's stream above them:
 * a session holds at most 4096 + 4096 + 31 x 512 segments (~25 MB). */
#define NPF_ANL_CTRL_WND   4096     /* sid 0: control (our cfg.default_rcv_wnd) */
#define NPF_ANL_DATA_WND   4096     /* the data stream (5 MB: 10 MB/s up to 500 ms RTT) */
#define NPF_ANL_MEDIA_WND  512      /* each media stream, each channel, the UDP stream (udpfwd.h) */

typedef struct npf_media npf_media;

typedef struct npf_media_io {
    /* AnLiu: frames were queued, flush soon */
    void   (*kick)(void *arg);
    /* the peer opened a stream: 1 takes it */
    int    (*on_open)(void *arg, uint32_t id, int tag);
    void   (*on_frame)(void *arg, uint32_t id, const uint8_t *buf, size_t len, uint32_t frame_no, int flags,
                       uint32_t lost_before);
    /* the stream or channel ended from the other side (closed or refused there) */
    void   (*on_closed)(void *arg, uint32_t id);
    /* a callback ended the session: stop delivering */
    int    (*ended)(void *arg);
    /* channels: the peer opened one (1 takes it); bytes of one; one refused
     * a send (NPF_CALL_EBUSY) and has room again */
    int    (*on_chan_open)(void *arg, uint32_t id, int tag);
    void   (*on_chan_data)(void *arg, uint32_t id, const uint8_t *buf, size_t len);
    void   (*on_chan_writable)(void *arg, uint32_t id);
} npf_media_io;

/* odd: this side's ids are odd (the callee) */
npf_media *npf_media_new(anl_t *anl, int odd, const npf_media_io *io, void *arg);
/* the session ended: everything goes without callbacks */
void npf_media_free(npf_media *m);

/* AnLiu: the accept callback for a media stream or channel of the peer
 * (its tag in NPF_TAG_MEDIA .., NPF_TAG_CHAN ..); 0 takes it for now, the
 * application is asked in npf_media_poll after the input */
int  npf_media_accept(npf_media *m, anl_stream_t *s, anl_stream_opt *opt);
/* before reading (each input, each tick): the peer's new streams to the
 * application, closed channels whose data is acknowledged released, room
 * told to channels that refused a send. -1 when a callback ended the session */
int  npf_media_poll(npf_media *m);
/* is s a media stream or channel (ours or the peer's)? */
int  npf_media_is_stream(const npf_media *m, anl_stream_t *s);
/* s is readable: its frames or bytes to the application, or its end. -1
 * when a callback ended the session (stop reading) */
int  npf_media_drain(npf_media *m, anl_stream_t *s);
int  npf_media_count(const npf_media *m);
/* changes whenever an AnLiu stream is closed here: a list of readable
 * streams taken before may hold released handles */
unsigned npf_media_gen(const npf_media *m);

/* the application's side; errors NPF_CALL_E* */
uint32_t npf_media_open_stream(npf_media *m, const npf_call_media_opt *o, int *err);
/* t_submit: when the application gave the frame (npf_mono_ms), 0: now */
int  npf_media_send_frame(npf_media *m, uint32_t id, int flags, const void *buf, size_t len, int64_t t_submit);
int  npf_media_stream_stats(npf_media *m, uint32_t id, npf_call_media_stats *out);
/* a media stream closed at once; a channel once what it sent is
 * acknowledged (at most NPF_CHAN_LINGER_MS): either way gone for the
 * application, no on_closed follows */
int  npf_media_close_stream(npf_media *m, uint32_t id);
/* channels; errors NPF_CALL_E* */
uint32_t npf_media_open_chan(npf_media *m, const npf_call_chan_opt *o, int *err);
/* all of buf queued, or nothing: NPF_CALL_EBUSY while NPF_CHANNEL_BUFFER
 * bytes wait (on_chan_writable follows below half) */
int  npf_media_chan_send(npf_media *m, uint32_t id, const void *buf, size_t len);
/* paused: its bytes wait in AnLiu (the peer's sends stop once the window is full) */
int  npf_media_chan_pause(npf_media *m, uint32_t id, int paused);

#endif
