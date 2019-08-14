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

int log_2_svg(FILE* bin_log, FILE* svg_seq);
int log_event_cb(uint32_t id, bytestream* s, FILE* svg);

int main(int argc, char ** argv)
{
    if (argc != 4) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "\t%s <input_svg_template.svg> <input_log_file.bin> <output_file.svg>\n", argv[0]);
        fprintf(stderr, "Convert a binary congestion control log file produced by\n");
        fprintf(stderr, "picoquic to an svg-image.\n");
        return -1;
    }

    debug_printf_push_stream(stderr);

    uint32_t log_time = 0;
    const char* svg_tmp_name = argv[1];
    const char* bin_log_name = argv[2];
    const char* svg_seq_name = argv[3];
    FILE* svg_tmp = picoquic_file_open(svg_tmp_name, "r");
    FILE* svg_seq = picoquic_file_open(svg_seq_name, "w");
    FILE* bin_log = picoquic_open_cc_log_file_for_read(bin_log_name, &log_time);

    if (svg_tmp != NULL && bin_log != NULL && svg_seq != NULL) {

        char line[256];
        while (fgets(line, sizeof(line), svg_tmp) != NULL) /* read a line */ {
            if (strcmp(line, "#\n") != 0) {
                fprintf(svg_seq, line);
            }
            else {
                log_2_svg(bin_log, svg_seq);
            }
        }
    }

    picoquic_file_close(svg_tmp);
    picoquic_file_close(svg_seq);
    picoquic_file_close(bin_log);

    return 0;
}

int log_2_svg(FILE* bin_log, FILE* svg_seq)
{
    int ret = 0;

    bytestream stream_head;
    bytestream * ps_head = bytestream_alloc(&stream_head, 8);

    while (ret == 0 && fread(bytestream_data(ps_head), bytestream_size(ps_head), 1, bin_log) > 0) {

        uint32_t id = 0;
        ret |= byteread_int32(ps_head, &id);
        uint32_t len = 0;
        ret |= byteread_int32(ps_head, &len);

        bytestream_reset(ps_head);

        bytestream stream_msg;
        bytestream * ps_msg = bytestream_alloc(&stream_msg, len);
        if (ps_msg == NULL) {
            ret = -1;
        }

        if (ret == 0 && fread(bytestream_data(ps_msg), bytestream_size(ps_msg), 1, bin_log) <= 0) {
            ret = -1;
        }

        if (ret == 0) {
            ret = log_event_cb(id, ps_msg, svg_seq);
        }

        bytestream_delete(ps_msg);
    }

    bytestream_delete(ps_head);
    return ret;
}

int log_event_cb(uint32_t id, bytestream* s, FILE* svg)
{
    static int nb = 0;
    const int event_height = 32;

    int ret = 0;
    if (id == picoquic_log_event_packet_sent || id == picoquic_log_event_packet_recv)
    {
        const char* dir = id == picoquic_log_event_packet_sent ? "out" : "in";
        uint64_t time, seq_no, length, type;
        int y_pos = 32 + event_height * nb;

        ret |= byteread_vint(s, &time);
        ret |= byteread_vint(s, &seq_no);
        ret |= byteread_vint(s, &length);
        ret |= byteread_vint(s, &type);

        fprintf(svg, "  <use x=\"%d\" y=\"%d\" xlink:href=\"#packet-%s\" />\n", 40, y_pos, dir);
        fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"arw\">%I64d</text>\n", 80, y_pos - 2, length);
        fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"seq_%s\">%I64d</text>\n", 35, y_pos - 4, dir, seq_no);
        fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"time\">%I64d</text>\n", 35, y_pos + 8, time);

        int x_pos = 85;
        uint64_t nb_frames = 0;
        ret |= byteread_vint(s, &nb_frames);
        for (uint64_t i = 0; i < nb_frames; ++i) {
            uint64_t ftype, length, stream_id;
            ret |= byteread_vint(s, &ftype);
            ret |= byteread_vint(s, &length);
            if (ftype >= picoquic_frame_type_stream_range_min &&
                ftype <= picoquic_frame_type_stream_range_max) {
                ret |= byteread_vint(s, &stream_id);
                fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"frm\">[%I64d: %I64d]</text>\n", x_pos, y_pos - 2, stream_id, length);
                x_pos += 40;
            }
            else {
                fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"arw\">%I64d: %I64d</text>\n", x_pos, y_pos - 2, ftype, length);
                x_pos += 30;
            }
        }
        nb++;
    }
    return ret;
}
