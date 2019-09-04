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
