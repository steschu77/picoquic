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
#include "util.h"

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

bytestream_msgs msgs[4];

inline int sgn(int sign, int value) {
    return (1 - 2 * sign) * value;
}

int read_log(FILE * bin_log, bytestream_msgs * msgs);
void merge_logs(bytestream_msgs * send_msgs, bytestream_msgs * recv_msgs);
int render_to_svg(FILE * svg, bytestream_msgs * msgs);

int main(int argc, char ** argv)
{
    if (argc != 5) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "\t%s <input_svg_template.svg> <input_log_file.bin> <output_file.svg>\n", argv[0]);
        fprintf(stderr, "Convert a binary congestion control log file produced by\n");
        fprintf(stderr, "picoquic to an svg-image.\n");
        return -1;
    }

    debug_printf_push_stream(stderr);

    uint32_t log_time = 0;
    const char* svg_tmp_name = argv[1];
    const char* svg_seq_name = argv[2];
    const char* svr_log_name = argv[3];
    const char* cli_log_name = argv[4];
    FILE* svg_tmp = picoquic_file_open(svg_tmp_name, "r");
    FILE* svg_seq = picoquic_file_open(svg_seq_name, "w");
    FILE* svr_log = picoquic_open_cc_log_file_for_read(svr_log_name, &log_time);
    FILE* cli_log = picoquic_open_cc_log_file_for_read(cli_log_name, &log_time);

    if (svg_tmp != NULL && svr_log != NULL && cli_log != NULL && svg_seq != NULL) {

        read_log(svr_log, &msgs[0]);
        read_log(cli_log, &msgs[1]);
        merge_logs(&msgs[0], &msgs[1]);
        merge_logs(&msgs[1], &msgs[0]);

        char line[256];
        while (fgets(line, sizeof(line), svg_tmp) != NULL) /* read a line */ {
            if (strcmp(line, "#\n") != 0) {
                fprintf(svg_seq, line);
            }
            else {
                render_to_svg(svg_seq, &msgs[0]);
            }
        }
    }

    picoquic_file_close(svg_tmp);
    picoquic_file_close(svg_seq);
    picoquic_file_close(svr_log);
    picoquic_file_close(cli_log);

    return 0;
}

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

    bytestream stream_head;
    bytestream* ps_head = bytestream_alloc(&stream_head, 8);

    while (ret == 0 && fread(bytestream_data(ps_head), bytestream_size(ps_head), 1, bin_log) > 0) {

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

            if (ret == 0 && fread(bytestream_data(ps_msg), bytestream_size(ps_msg), 1, bin_log) <= 0) {
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

    bytestream_delete(ps_head);
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

int get_frame_width(uint64_t ftype)
{
    switch (ftype) {
    case picoquic_frame_type_ping:
        return 35;

    case picoquic_frame_type_ack:
        return 22;

    case picoquic_frame_type_crypto_hs:
        return 55;

    case picoquic_frame_type_new_connection_id:
        return 28;

    default:
        return 30;
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

    int width = 0;
    for (uint64_t i = 0; i < nb_frames; ++i) {

        uint64_t ftype, length, stream_id, epoch, path_seq;
        ret |= byteread_vint(s, &ftype);
        ret |= byteread_vint(s, &length);

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

        width += get_frame_width(ftype);
    }

    return width;
}

int log_event(FILE * svg, bytestream_msg * msg)
{
    static int nb = 0;
    const int event_height = 32;

    int ret = 0;
    const char* dir = msg->rxtx == 0 ? "out" : "in";
    uint64_t time, seq_no, length, type;
    int y_pos = 32 + event_height * nb;
    int x_pos = 50;

    bytestream_reset(&msg->s);
    ret |= byteread_vint(&msg->s, &time);
    ret |= byteread_vint(&msg->s, &seq_no);
    ret |= byteread_vint(&msg->s, &length);
    ret |= byteread_vint(&msg->s, &type);

    uint64_t time1 = time / 1000;
    uint64_t time01 = (time % 1000) / 100;

    fprintf(svg, "  <use x=\"%d\" y=\"%d\" xlink:href=\"#packet-%s\" />\n", x_pos, y_pos, dir);
    fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"time\">%I64d.%I64d ms</text>\n", x_pos - 4, y_pos + 8, time1, time01);
    fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"time\">%I64d.%I64d ms</text>\n", x_pos - 4, y_pos + 8, time1, time01);

    if (msg->rxtx == 0) {
        fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"seq_%s\">%I64d</text>\n", x_pos - 4, y_pos - 4, dir, seq_no);
        fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"arw\">%I64d b</text>\n", 80, y_pos - 2, length);
    }
    else {
        fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"seq_%s\">%I64d</text>\n", 600 - x_pos + 4, y_pos - 4, dir, seq_no);
        fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"arw\">%I64d b</text>\n", 600-80, y_pos - 2, length);
    }

    bytestream* s = &msg->s;
    const char* anchor = "start";
    if (msg->rxtx == 1 && msg->peer != NULL) {

        s = &msg->peer->s;

        bytestream_reset(s);
        ret |= byteread_vint(s, &time);
        ret |= byteread_vint(s, &seq_no);
        ret |= byteread_vint(s, &length);
        ret |= byteread_vint(s, &type);

        x_pos = 600 - x_pos;
        anchor = "end";
    }

    uint64_t nb_frames = 0;
    ret |= byteread_vint(s, &nb_frames);
    for (uint64_t i = 0; i < nb_frames; ++i) {
        uint64_t ftype, length, stream_id, epoch, path_seq;
        ret |= byteread_vint(s, &ftype);
        ret |= byteread_vint(s, &length);
        if (ftype >= picoquic_frame_type_stream_range_min &&
            ftype <= picoquic_frame_type_stream_range_max) {
            ret |= byteread_vint(s, &stream_id);
            fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"%s\" class=\"frm\">[%I64d: %I64d]</text>\n", x_pos, y_pos + 10, anchor, stream_id, length);
            x_pos += sgn(msg->rxtx, 40);
        }
        else switch (ftype) {
        case picoquic_frame_type_ping:
            fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"%s\" class=\"arw\">[ping: %I64d]</text>\n", x_pos, y_pos + 10, anchor, length);
            x_pos += sgn(msg->rxtx, 35);
            break;

        case picoquic_frame_type_ack:
            fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"%s\" class=\"arw\">[ack]</text>\n", x_pos, y_pos + 10, anchor);
            x_pos += sgn(msg->rxtx, 22);
            break;
        case picoquic_frame_type_crypto_hs:
            ret |= byteread_vint(s, &epoch);
            fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"%s\" class=\"chs\">[crypto-hs %I64d]</text>\n", x_pos, y_pos + 10, anchor, epoch);
            x_pos += sgn(msg->rxtx, 55);
            break;
        case picoquic_frame_type_new_connection_id:
            ret |= byteread_vint(s, &path_seq);
            fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"%s\" class=\"arw\">[cid %I64d]</text>\n", x_pos, y_pos + 10, anchor, path_seq);
            x_pos += sgn(msg->rxtx, 28);
            break;

        default:
            fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"%s\" class=\"arw\">%I64d: %I64d</text>\n", x_pos, y_pos + 10, anchor, ftype, length);
            x_pos += sgn(msg->rxtx, 30);
            break;
        }
    }
    nb++;
    return ret;
}

int render_to_svg(FILE * svg, bytestream_msgs * msgs)
{
    int ret = 0;

    for (bytestream_msg * msg = msgs->first; msg != NULL; msg = msg->next) {
        ret = log_event(svg, msg);
        if (ret != 0) {
            break;
        }
    }

    return ret;
}

