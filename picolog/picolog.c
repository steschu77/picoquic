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

#include "picolog.h"
#include "binlog.h"
#include "binlogmsg.h"
#include "cidset.h"

static int list_cids_cb(bytestream* s, void * cbptr)
{
    picoquic_connection_id_t cid;
    int ret = byteread_cid(s, &cid);

    if (ret != 0) {
        ret = cidset_insert((picohash_table*)cbptr, &cid);
    }

    return ret;
}

int list_cids(FILE* binlog, picohash_table * cids)
{
    fseek(binlog, 16, SEEK_SET);
    return fileread_binlog(binlog, list_cids_cb, cids);
}

static int count_cid(const picoquic_connection_id_t * cid, void * cbptr)
{
    cid;
    (int*)cbptr;
    return 0;
}

static int print_cid(const picoquic_connection_id_t * cid, void * cbptr)
{
    FILE * f = (FILE*)cbptr;

    fprintf(f, "  <");
    for (uint8_t i = 0; i < cid->id_len; i++) {
        fprintf(f, "%02x", cid->id[i]);
    }
    fprintf(f, ">\n");
    return 0;
}

void print_cids(FILE * f, const char * fname, picohash_table* cids)
{
    int nb_cids = 0;
    cidset_iterate(cids, count_cid, &nb_cids);

    fprintf(f, "%s contains %d connections:\n", fname, nb_cids);
    cidset_iterate(cids, print_cid, f);
}

typedef struct st_log_file_ctx_t {
    FILE * log;
    const picoquic_connection_id_t * cid;
} log_file_ctx_t;

int convert_log_file_cb(bytestream * s, void * cbptr)
{
    const log_file_ctx_t * ctx = (log_file_ctx_t*)cbptr;

    int ret = 0;

    picoquic_connection_id_t cid;
    ret |= byteread_cid(s, &cid);

    if (picoquic_compare_connection_id(&cid, ctx->cid) != 0) {
        return 0;
    }

    uint64_t time = 0;
    ret |= byteread_vint(s, &time);

    uint64_t id = 0;
    ret |= byteread_vint(s, &id);

    if (id == picoquic_log_event_packet_recv || id == picoquic_log_event_packet_sent) {
        picoquic_packet_header ph;
        ret |= byteread_packet_header(s, &ph);
    }

    fprintf(ctx->log, "%"PRIi64" id:%" PRIi64 "\n", time, id);

    return ret;
}

int convert_log_file(FILE * binlog, FILE * log, const picoquic_connection_id_t * cid)
{
    if (binlog == NULL || log == NULL) {
        return -1;
    } else {
        log_file_ctx_t ctx;
        ctx.cid = cid;
        ctx.log = log;
        fseek(binlog, 16, SEEK_SET);
        return fileread_binlog(binlog, convert_log_file_cb, &ctx);
    }
}

int convert_log(FILE * binlog, const picoquic_connection_id_t * cid, const char * log_dir)
{
    int ret = 0;
    char log_name[512];

    char cid_str[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
    picoquic_print_connection_id_hexa(cid_str, sizeof(cid_str), cid);

    if (picoquic_sprintf(log_name, sizeof(log_name), NULL, "%s%c%s.log", log_dir, PICOQUIC_FILE_SEPARATOR, cid_str) != 0) {
        DBG_PRINTF("Cannot format file name into folder %s, id_len = %d\n", log_dir, cid->id_len);
        ret = -1;
    }

    FILE* log = picoquic_file_open(log_name, "w");
    ret |= convert_log_file(binlog, log, cid);
    log = picoquic_file_close(log);
    return ret;
}

int convert_logs(FILE* binlog, picohash_table* cids, const char* log_dir)
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < cids->nb_bin; i++) {
        for (picohash_item* item = cids->hash_bin[i]; ret == 0 && item != NULL; item = item->next_in_bin) {
            ret = convert_log(binlog, (picoquic_connection_id_t*)item->key, log_dir);
        }
    }
    return ret;
}

int convert_qlog(FILE* binlog, picohash_table* cids, const char* log_name)
{
    return 0;
}

int convert_csv(FILE* binlog, picohash_table* cids, const char* csv_name)
{
    return 0;
}

int convert_svg(FILE * binlog0, FILE * binlog1, picohash_table * cids, const char * svg_tmp_name, const char * svg_seq_name)
{
    FILE* svg_tmp = picoquic_file_open(svg_tmp_name, "r");
    FILE* svg_seq = picoquic_file_open(svg_seq_name, "w");

    if (binlog0 != NULL && binlog1 != NULL && svg_tmp != NULL && svg_seq != NULL) {

        bytestream_msgs msgs[4];

        read_log(binlog0, &msgs[0]);
        read_log(binlog1, &msgs[1]);
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

        uint64_t ftype, path_seq;
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
            x_pos += 40;
        }
        else switch (ftype) {
        case picoquic_frame_type_ping:
            fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"%s\" class=\"arw\">[ping: %I64d]</text>\n", x_pos, y_pos + 10, anchor, length);
            x_pos += 35;
            break;

        case picoquic_frame_type_ack:
            fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"%s\" class=\"arw\">[ack]</text>\n", x_pos, y_pos + 10, anchor);
            x_pos += 22;
            break;

        case picoquic_frame_type_crypto_hs:
            {
                uint64_t offset = 0;
                ret |= byteread_vint(frame, &offset);

                uint64_t length = 0;
                ret |= byteread_vint(frame, &length);

                fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"%s\" class=\"chs\">[crypto-hs %I64d]</text>\n", x_pos, y_pos + 10, anchor, length);
                x_pos += 55;
            }
            break;

        case picoquic_frame_type_new_connection_id:
            ret |= byteread_vint(frame, &path_seq);
            fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"%s\" class=\"arw\">[cid %I64d]</text>\n", x_pos, y_pos + 10, anchor, path_seq);
            x_pos += 28;
            break;

        default:
            fprintf(svg, "  <text x=\"%d\" y=\"%d\" text-anchor=\"%s\" class=\"arw\">%I64d: %I64d</text>\n", x_pos, y_pos + 10, anchor, ftype, length);
            x_pos += 30;
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

/* Extract all picoquic_log_event_cc_update events from the binary log file and write them into an csv file. */
int picoquic_cc_log_file_to_csv(char const * bin_cc_log_name, char const * csv_cc_log_name)
{
    /* Open the bin file for reading, the csv file for writing */
    int ret = 0;
    uint32_t log_time = 0;
    FILE * bin_log = picoquic_open_cc_log_file_for_read(bin_cc_log_name, &log_time);
    FILE * csv_log = picoquic_file_open(csv_cc_log_name, "w");

    if (bin_log == NULL || csv_log == NULL) {
        ret = -1;
    }
    else {

        /* TODO: maintain the list of headers as debugging data is added */
        ret |= fprintf(csv_log, "time, ") <= 0;
        ret |= fprintf(csv_log, "sequence, ") <= 0;
        ret |= fprintf(csv_log, "highest ack, ") <= 0;
        ret |= fprintf(csv_log, "high ack time, ") <= 0;
        ret |= fprintf(csv_log, "last time ack, ") <= 0;
        ret |= fprintf(csv_log, "cwin, ") <= 0;
        ret |= fprintf(csv_log, "SRTT, ") <= 0;
        ret |= fprintf(csv_log, "RTT min, ") <= 0;
        ret |= fprintf(csv_log, "Send MTU, ") <= 0;
        ret |= fprintf(csv_log, "pacing packet time(us), ") <= 0;
        ret |= fprintf(csv_log, "nb retrans, ") <= 0;
        ret |= fprintf(csv_log, "nb spurious, ") <= 0;
        ret |= fprintf(csv_log, "cwin blkd, ") <= 0;
        ret |= fprintf(csv_log, "flow blkd, ") <= 0;
        ret |= fprintf(csv_log, "stream blkd, ") <= 0;
        ret |= fprintf(csv_log, "\n") <= 0;

        bytestream_buf stream;
        bytestream * ps_head = bytestream_buf_init(&stream, 8);

        if (ps_head == NULL) {
            ret = -1;
        }

        while (ret == 0 && fread(stream.buf, bytestream_size(ps_head), 1, bin_log) > 0) {

            uint32_t id, len;
            ret |= byteread_int32(ps_head, &len);
            ret |= byteread_int32(ps_head, &id);

            bytestream_reset(ps_head);

            if (ret == 0 && id == picoquic_log_event_cc_update) {
                
                bytestream_buf stream_msg;
                bytestream * ps_msg = bytestream_buf_init(&stream_msg, len);

                if (ps_msg == NULL || fread(stream_msg.buf, bytestream_size(ps_msg), 1, bin_log) <= 0) {
                    ret = -1;
                }
                else {
                    uint64_t time = 0;
                    uint64_t sequence = 0;
                    uint64_t packet_rcvd = 0;
                    uint64_t highest_ack = (uint64_t)(int64_t)-1;
                    uint64_t high_ack_time = 0;
                    uint64_t last_time_ack = 0;
                    uint64_t cwin = 0;
                    uint64_t SRTT = 0;
                    uint64_t RTT_min = 0;
                    uint64_t Send_MTU = 0;
                    uint64_t pacing_packet_time = 0;
                    uint64_t nb_retrans = 0;
                    uint64_t nb_spurious = 0;
                    uint64_t cwin_blkd = 0;
                    uint64_t flow_blkd = 0;
                    uint64_t stream_blkd = 0;

                    ret |= byteread_vint(ps_msg, &time);
                    ret |= byteread_vint(ps_msg, &sequence);
                    ret |= byteread_vint(ps_msg, &packet_rcvd);
                    if (packet_rcvd != 0) {
                        ret |= byteread_vint(ps_msg, &highest_ack);
                        ret |= byteread_vint(ps_msg, &high_ack_time);
                        ret |= byteread_vint(ps_msg, &last_time_ack);
                    }
                    ret |= byteread_vint(ps_msg, &cwin);
                    ret |= byteread_vint(ps_msg, &SRTT);
                    ret |= byteread_vint(ps_msg, &RTT_min);
                    ret |= byteread_vint(ps_msg, &Send_MTU);
                    ret |= byteread_vint(ps_msg, &pacing_packet_time);
                    ret |= byteread_vint(ps_msg, &nb_retrans);
                    ret |= byteread_vint(ps_msg, &nb_spurious);
                    ret |= byteread_vint(ps_msg, &cwin_blkd);
                    ret |= byteread_vint(ps_msg, &flow_blkd);
                    ret |= byteread_vint(ps_msg, &stream_blkd);

                    if (ret != 0 || fprintf(csv_log, "%" PRIu64 ", %" PRIu64 ", %" PRId64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", ",
                        time, sequence, (int64_t)highest_ack, high_ack_time, last_time_ack,
                        cwin, SRTT, RTT_min, Send_MTU, pacing_packet_time,
                        nb_retrans, nb_spurious, cwin_blkd, flow_blkd, stream_blkd) <= 0) {
                        ret = -1;
                        break;
                    }
                    if (ret == 0) {
                        if (fprintf(csv_log, "\n") <= 0) {
                            DBG_PRINTF("Error writing data on file %s.\n", csv_cc_log_name);
                            ret = -1;
                        }
                    }
                }
            }
            else {
                fseek(bin_log, len, SEEK_CUR);
            }
        }
    }

    (void)picoquic_file_close(csv_log);
    (void)picoquic_file_close(bin_log);

    return ret;
}
