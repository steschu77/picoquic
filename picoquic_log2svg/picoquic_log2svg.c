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

int list_cids(FILE* bin_log, picohash_table ** cids);

void usage();
int open_binlog(FILE ** pf, picohash_table ** pcids, const char * fname);

int main(int argc, char ** argv)
{
    const char * out_format = "log";
    const char * out_file = NULL;
    const char * svg_tmp_name = NULL;

    int list_cnxid = 0;
    int all = 0;
    int ret = 0;

    int opt;
    while ((opt = getopt(argc, argv, "a:o:f:t:l")) != -1) {
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
        case 'a':
            all = 1;
            break;
        default:
            usage();
            break;
        }
    }

    /* Simplified style params */
    picohash_table * cids[2] = { NULL, NULL };
    const char * log_name[2] = { NULL, NULL };
    FILE * log[2] = { NULL, NULL };

    int nb_logs = 0;
    for (; nb_logs < 2 && optind < argc; nb_logs++, optind++) {
        log_name[nb_logs] = argv[optind];
        ret |= open_binlog(&log[nb_logs], &cids[nb_logs], log_name[nb_logs]);
        ret |= print_cids(log[nb_logs], log_name[nb_logs], cids[nb_logs]);
    }

    if (ret == 0 && out_file != NULL && log[0] != NULL) {

        if (strcmp(out_format, "log") == 0) {
            ret = convert_logs(log[0], cids[0], out_file);
        } else if (strcmp(out_format, "csv") == 0) {
            ret = convert_csv(log[0], cids[0], out_file);
        } else if (strcmp(out_format, "svg") == 0) {
            ret = convert_svg(log[0], log[1], cids[0], svg_tmp_name, out_file);
        } else if (strcmp(out_format, "qlog") == 0) {
            ret = convert_qlog(log[0], cids[0], out_file);
        } else {
            fprintf(stderr, "Invalid output format %s\n", out_format);
            ret = 1;
        }
    }

    cidset_delete(cids[0]);
    cidset_delete(cids[1]);

    picoquic_file_close(log[0]);
    picoquic_file_close(log[1]);
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

int open_binlog(FILE ** pf, picohash_table ** pcids, const char * fname)
{
    if (fname == NULL) {
        return 0;
    }

    int ret = 0;
    uint32_t log_time = 0;
    FILE * f = picoquic_open_cc_log_file_for_read(fname, &log_time);
    if (f == NULL) {
        fprintf(stderr, "Could not open file %s\n", fname);
        ret = -1;
    }

    picohash_table * cids = cidset_create();
    if (cids == NULL) {
        fprintf(stderr, "Could not create connection set for file %s\n", fname);
        ret = -1;
    }

    if (ret == 0 && list_cids(f, cids) != 0) {
        fprintf(stderr, "Could not read file %s\n", fname);
        ret = -1;
    }

    if (ret != 0) {
        cids = cidset_delete(cids);
        f = picoquic_file_close(f);
    } else {
        *pf = f;
        *pcids = cids;
    }

    return ret;
}
