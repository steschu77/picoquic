/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <stdio.h>
#include "picoquic_internal.h"
#include "bytestream.h"

typedef struct st_bytestream_msg {
    struct st_bytestream_msg * next;
    struct st_bytestream_msg * peer;
    uint64_t time;
    uint64_t seq_no;
    int rxtx;
    bytestream s;
} bytestream_msg;

typedef struct st_bytestream_msgs {
    struct st_bytestream_msg * first;
    struct st_bytestream_msg * last;
} bytestream_msgs;

typedef enum {
    svr_send_msgs = 0,
    svr_recv_msgs = 1,
    cli_send_msgs = 2,
    cli_recv_msgs = 3
} bytestream_msgs_type;

int read_log(FILE * bin_log, bytestream_msgs * msgs);
void merge_logs(bytestream_msgs * send_msgs, bytestream_msgs * recv_msgs);

int add_log_event(bytestream_msgs * msgs, bytestream_msg * msg, int rxtx)
{
    int ret = 0;

    bytestream_reset(&msg->s);
    ret |= byteread_vint(&msg->s, &msg->time);
    ret |= byteread_vint(&msg->s, &msg->seq_no);

    msg->next = NULL;
    msg->peer = NULL;
    msg->rxtx = rxtx;

    if (msgs->last != NULL) {
        msgs->last->next = msg;
    }

    msgs->last = msg;

    if (msgs->first == NULL) {
        msgs->first = msg;
    }

    return ret;
}

int read_log(FILE* bin_log, bytestream_msgs * msgs)
{
    int ret = 0;

    bytestream_buf stream_head;
    bytestream* ps_head = bytestream_buf_init(&stream_head, 8);

    while (ret == 0 && fread(stream_head.buf, bytestream_size(ps_head), 1, bin_log) > 0) {

        uint32_t id = 0;
        ret |= byteread_int32(ps_head, &id);
        uint32_t len = 0;
        ret |= byteread_int32(ps_head, &len);

        bytestream_reset(ps_head);

        if (id == picoquic_log_event_packet_sent || id == picoquic_log_event_packet_recv)
        {
            int rxtx = id == picoquic_log_event_packet_recv;

            bytestream_msg * stream_msg = (bytestream_msg*)malloc(sizeof(bytestream_msg));
            bytestream * ps_msg = bytestream_alloc(&stream_msg->s, len);
            if (ps_msg == NULL) {
                ret = -1;
            }

            if (ret == 0 && fread(ps_msg->data, bytestream_size(ps_msg), 1, bin_log) <= 0) {
                ret = -1;
            }

            if (ret == 0) {
                add_log_event(msgs, stream_msg, rxtx);
            }
        }
        else {
            ret = fseek(bin_log, len, SEEK_CUR);
        }
    }

    return ret;
}

void merge_logs(bytestream_msgs * send_msgs, bytestream_msgs * recv_msgs)
{
    bytestream_msg * send_msg = send_msgs->first;
    bytestream_msg * recv_msg = recv_msgs->first;

    while (send_msg != NULL && recv_msg != NULL) {

        /* skip all received msgs on sender log */
        while (send_msg != NULL && send_msg->rxtx != 0) {
            send_msg = send_msg->next;
        }

        /* skip all sent msgs on receiver log */
        while (recv_msg != NULL && recv_msg->rxtx == 0) {
            recv_msg = recv_msg->next;
        }

        if (send_msg != NULL && recv_msg != NULL) {
            if (send_msg->seq_no == recv_msg->seq_no) {
                send_msg->peer = recv_msg;
                recv_msg->peer = send_msg;

                send_msg = send_msg->next;
                recv_msg = recv_msg->next;
            }
            else if (send_msg->seq_no < recv_msg->seq_no) {
                send_msg = send_msg->next;
            }
            else {
                recv_msg = recv_msg->next;
            }
        }
    }
}

int read_frames(bytestream_msg * msg)
{
    int ret = 0;

    bytestream* s = &msg->s;
    if (msg->rxtx == 1 && msg->peer != NULL) {
        s = &msg->peer->s;
    }

    uint64_t time, seq_no, length, type;

    bytestream_reset(s);
    ret |= byteread_vint(s, &time);
    ret |= byteread_vint(s, &seq_no);
    ret |= byteread_vint(s, &length);
    ret |= byteread_vint(s, &type);

    uint64_t nb_frames = 0;
    ret |= byteread_vint(s, &nb_frames);

    for (uint64_t i = 0; i < nb_frames; ++i) {

        uint64_t ftype, frame_length, stream_id, epoch, path_seq;
        ret |= byteread_vint(s, &ftype);
        ret |= byteread_vint(s, &frame_length);

        if (ftype >= picoquic_frame_type_stream_range_min &&
            ftype <= picoquic_frame_type_stream_range_max) {
            ret |= byteread_vint(s, &stream_id);
        }
        else switch (ftype) {

        case picoquic_frame_type_crypto_hs:
            ret |= byteread_vint(s, &epoch);
            break;
        case picoquic_frame_type_new_connection_id:
            ret |= byteread_vint(s, &path_seq);
            break;
        }
    }

    return 0;
}
