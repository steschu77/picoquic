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
#include "picohash.h"
#include "util.h"
#include "../picoquicfirst/getopt.h"

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

int list_cnxids(FILE* bin_log, const char* fname);

int convert_log(FILE* log0, FILE* log1, const char* log_name);
int convert_qlog(FILE* log0, const char* log_name);
int convert_csv(FILE* log0, FILE* log1, const char* csv_name);
int convert_svg(FILE* log0, FILE* log1, const char* svg_tmp_name, const char* svg_seq_name);

void usage();

int main(int argc, char ** argv)
{
    int ret = 0;

    const char * log0_name = NULL;
    const char * log1_name = NULL;
    const char * out_format = "log";
    const char * out_file = NULL;
    const char * svg_tmp_name = NULL;
    int list_cnxid = 0;

    int opt;
    while ((opt = getopt(argc, argv, "o:f:t:l")) != -1) {
        switch (opt) {
        case 'o':
            out_file = optarg;
            break;
        case 'f':
            out_format = optarg;
            break;
        case 't':
            svg_tmp_name = optarg;
            break;
        case 'l':
            list_cnxid = 1;
            break;
        default:
            usage();
            break;
        }
    }

    /* Simplified style params */
    if (optind < argc) {
        log0_name = argv[optind++];
    }
    if (optind < argc) {
        log1_name = argv[optind++];
    }

    debug_printf_push_stream(stderr);

    uint32_t log_time = 0;
    FILE* log0 = log0_name ? picoquic_open_cc_log_file_for_read(log0_name, &log_time) : NULL;
    FILE* log1 = log1_name ? picoquic_open_cc_log_file_for_read(log1_name, &log_time) : NULL;

    if (log0_name != NULL && log0 == NULL) {
        fprintf(stderr, "Could not open file %s\n", log0_name);
        exit(1);
    }

    if (log1_name != NULL && log1 == NULL) {
        fprintf(stderr, "Could not open file %s\n", log1_name);
        exit(1);
    }

    if (list_cnxid && log0 != NULL) {
        list_cnxids(log0, log0_name);
    }

    if (list_cnxid && log1 != NULL) {
        list_cnxids(log1, log1_name);
    }

    if (!list_cnxid && log0 != NULL) {
        if (strcmp(out_format, "log") == 0) {
            ret = convert_log(log0, log1, out_file);
        } else if (strcmp(out_format, "csv") == 0) {
            ret = convert_csv(log0, log1, out_file);
        } else if (strcmp(out_format, "svg") == 0) {
            ret = convert_svg(log0, log1, svg_tmp_name, out_file);
        } else if (strcmp(out_format, "qlog") == 0) {
            ret = convert_qlog(log0, out_file);
        } else {
            fprintf(stderr, "Invalid output format %s\n", out_format);
            ret = 1;
        }
    }

    log0 = picoquic_file_close(log0);
    log1 = picoquic_file_close(log1);
    return ret;
}

int byteread_cid(bytestream* s, picoquic_connection_id_t* cid)
{
    memset(cid->id, 0, sizeof(cid->id));

    int ret = byteread_int8(s, &cid->id_len);
    ret |= byteread_buffer(s, cid->id, cid->id_len);
    return ret;
}

/* Hash and compare for CNX hash tables */
static uint64_t picoquic_cid_hash(void* key)
{
    picoquic_connection_id_t* cid = (picoquic_connection_id_t*)key;
    return picoquic_val64_connection_id(*cid);
}

static int picoquic_cid_compare(void* key0, void* key1)
{
    picoquic_connection_id_t* cid0 = (picoquic_connection_id_t*)key0;
    picoquic_connection_id_t* cid1 = (picoquic_connection_id_t*)key1;

    return picoquic_compare_connection_id(cid0, cid1);
}

int add_cnx_id(picohash_table* table_cnx_by_id, picoquic_connection_id_t * cnx_id)
{
    int ret = 0;

    picohash_item* item = picohash_retrieve(table_cnx_by_id, cnx_id);
    if (item == NULL) {
        picoquic_connection_id_t* key = (picoquic_connection_id_t*)malloc(sizeof(picoquic_connection_id_t));
        if (key == NULL) {
            ret = -1;
        } else {
            *key = *cnx_id;
            ret = picohash_insert(table_cnx_by_id, key);
        }
    }

    return ret;
}

int read_binlog(FILE* bin_log, int(*cb)(bytestream*, void*), void* cbptr)
{
    int ret = 0;
    uint8_t head[4];
    bytestream_buf stream_msg;

    while (ret == 0 && fread(head, sizeof(head), 1, bin_log) > 0) {

        uint32_t len = (head[0] << 24) | (head[1] << 16) | (head[2] << 8) | head[3];
        if (len > sizeof(stream_msg.buf)) {
            ret = -1;
        }

        if (ret == 0 && fread(stream_msg.buf, len, 1, bin_log) <= 0) {
            ret = -1;
        }

        if (ret == 0) {
            bytestream* s = bytestream_buf_init(&stream_msg, len);
            ret |= cb(s, cbptr);
        }
    }

    return ret;
}

int list_cnxids_cb(bytestream* s, void * cbptr)
{
    picoquic_connection_id_t cid;
    int ret = byteread_cid(s, &cid);

    picohash_table *hash = (picohash_table*)cbptr;
    ret |= add_cnx_id(hash, &cid);

    return ret;
}

void print_connection_id(const picoquic_connection_id_t * cid)
{
    printf("<");
    for (uint8_t i = 0; i < cid->id_len; i++) {
        printf("%02x", cid->id[i]);
    }
    printf(">");
}

int list_cnxids(FILE* bin_log, const char * fname)
{
    int ret = 0;

    picohash_table* cnxids = picohash_create(32, picoquic_cid_hash, picoquic_cid_compare);
    if(read_binlog(bin_log, list_cnxids_cb, cnxids) != 0) {
        ret = -1;
    } else {
        int nb_cnxids = 0;

        for (size_t i = 0; i < cnxids->nb_bin; i++) {
            for (picohash_item* item = cnxids->hash_bin[i]; item != NULL; item = item->next_in_bin) {
                nb_cnxids++;
            }
        }

        printf("%s contains %d connections:\n", fname, nb_cnxids);

        for (size_t i = 0; i < cnxids->nb_bin; i++) {
            for (picohash_item* item = cnxids->hash_bin[i]; item != NULL; item = item->next_in_bin) {
                printf("  ");
                print_connection_id((picoquic_connection_id_t*)item->key);
                printf("\n");
            }
        }
    }

    return ret;
}

int convert_log(FILE* log0, FILE* log1, const char* log_name)
{
    return 0;
}

int convert_qlog(FILE* log0, const char* log_name)
{
    return 0;
}

int convert_csv(FILE* log0, FILE* log1, const char* csv_name)
{
    return 0;
}

int convert_svg(FILE * log0, FILE * log1, const char * svg_tmp_name, const char* svg_seq_name)
{
    FILE* svg_tmp = picoquic_file_open(svg_tmp_name, "r");
    FILE* svg_seq = picoquic_file_open(svg_seq_name, "w");

    if (log0 != NULL && log1 != NULL && svg_tmp != NULL && svg_seq != NULL) {

        read_log(log0, &msgs[0]);
        read_log(log1, &msgs[1]);
        merge_logs(&msgs[0], &msgs[1]);
        merge_logs(&msgs[1], &msgs[0]);

        char line[256];
        while (fgets(line, sizeof(line), svg_tmp) != NULL) /* read a line */ {
            if (strcmp(line, "#\n") != 0) {
                fprintf(svg_seq, line);
            } else {
                render_to_svg(svg_seq, &msgs[0]);
            }
        }
    }

    picoquic_file_close(svg_tmp);
    picoquic_file_close(svg_seq);
    return 0;
}

int add_log_event_2(bytestream* s, void* cbptr)
{
    int ret = 0;

    picoquic_connection_id_t cid;
    ret |= byteread_cid(s, &cid);

    uint64_t time = 0;
    ret |= byteread_vint(s, &time);

    uint64_t id = 0;
    ret |= byteread_vint(s, &id);

    picohash_table* hash = (picohash_table*)cbptr;
    ret |= add_cnx_id(hash, &cid);

    return ret;
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

    while (!bytestream_finished(s)) {

        uint64_t length;
        ret |= byteread_vint(s, &length);

        bytestream strm;
        bytestream * frame = bytestream_ref_init(&strm, bytestream_ptr(s), length);

        bytestream_skip(s, length);

        uint64_t ftype, epoch, path_seq;
        ret |= byteread_vint(frame, &ftype);

        if (ftype >= picoquic_frame_type_stream_range_min &&
            ftype <= picoquic_frame_type_stream_range_max) {

            uint64_t stream_id;
            ret |= byteread_vint(frame, &stream_id);

            uint64_t offset = 0;
            if ((ftype & 4) != 0) {
                ret |= byteread_vint(frame, &offset);
            }

            uint64_t length = 0;
            if ((ftype & 2) != 0) {
                ret |= byteread_vint(frame, &length);
            }

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
            {
                uint64_t offset = 0;
                ret |= byteread_vint(frame, &offset);

                uint64_t length = 0;
                ret |= byteread_vint(frame, &length);

                fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"%s\" class=\"chs\">[crypto-hs %I64d]</text>\n", x_pos, y_pos + 10, anchor, length);
                x_pos += sgn(msg->rxtx, 55);
            }
            break;

        case picoquic_frame_type_new_connection_id:
            ret |= byteread_vint(frame, &path_seq);
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
        /*if (ret != 0) {
            break;
        }*/
    }

    return ret;
}

void usage()
{
    fprintf(stderr, "PicoQUIC log file converter\n");
    fprintf(stderr, "Usage: picolog <options> [input] \n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -o file               output file name\n");
    fprintf(stderr, "  -f format             output format:\n");
    fprintf(stderr, "                        -f log: generate text log file\n");
    fprintf(stderr, "                        -f csv: generate CC csv file\n");
    fprintf(stderr, "                        -f svg: generate flow graph\n");
    fprintf(stderr, "                        -f qlog: generate qlog json file\n");
    fprintf(stderr, "  -t file               template svg file for svg output\n");
    fprintf(stderr, "  -l                    list all connections by connection id\n");

    exit(1);
}
