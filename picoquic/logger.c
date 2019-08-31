/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
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

/*
* Packet logging.
*/
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "fnv1a.h"
#include "picoquic_internal.h"
#include "bytestream.h"
#include "tls_api.h"

void picoquic_log_prefix_initial_cid64(FILE* F, uint64_t log_cnxid64)
{
    if (log_cnxid64 != 0) {
        fprintf(F, "%016llx: ", (unsigned long long)log_cnxid64);
    }
}

void picoquic_log_packet_address(FILE* F, uint64_t log_cnxid64, picoquic_cnx_t* cnx,
    struct sockaddr* addr_peer, int receiving, size_t length, uint64_t current_time)
{
    uint64_t delta_t = 0;
    uint64_t time_sec = 0;
    uint32_t time_usec = 0;

    picoquic_log_prefix_initial_cid64(F, log_cnxid64);

    fprintf(F, (receiving) ? "Receiving %d bytes from " : "Sending %d bytes to ",
        (int)length);

    if (addr_peer->sa_family == AF_INET) {
        struct sockaddr_in* s4 = (struct sockaddr_in*)addr_peer;
        uint8_t* addr = (uint8_t*)&s4->sin_addr;

        fprintf(F, "%d.%d.%d.%d:%d",
            addr[0], addr[1], addr[2], addr[3],
            ntohs(s4->sin_port));
    } else {
        struct sockaddr_in6* s6 = (struct sockaddr_in6*)addr_peer;
        uint8_t* addr = (uint8_t*)&s6->sin6_addr;

        fprintf(F, "[");
        for (int i = 0; i < 8; i++) {
            if (i != 0) {
                fprintf(F, ":");
            }

            if (addr[2 * i] != 0) {
                fprintf(F, "%x%02x", addr[2 * i], addr[(2 * i) + 1]);
            } else {
                fprintf(F, "%x", addr[(2 * i) + 1]);
            }
        }
        fprintf(F, "]:%d\n", ntohs(s6->sin6_port));
    }

    if (cnx != NULL) {
        delta_t = current_time - cnx->start_time;
        time_sec = delta_t / 1000000;
        time_usec = (uint32_t)(delta_t % 1000000);
    }

    fprintf(F, " at T=%llu.%06d (%llx)\n",
        (unsigned long long)time_sec, time_usec,
        (unsigned long long)current_time);
}

char const* picoquic_log_ptype_name(picoquic_packet_type_enum ptype)
{
    char const* ptype_name = "unknown";

    switch (ptype) {
    case picoquic_packet_error:
        ptype_name = "error";
        break;
    case picoquic_packet_version_negotiation:
        ptype_name = "version negotiation";
        break;
    case picoquic_packet_initial:
        ptype_name = "initial";
        break;
    case picoquic_packet_retry:
        ptype_name = "retry";
        break;
    case picoquic_packet_handshake:
        ptype_name = "handshake";
        break;
    case picoquic_packet_0rtt_protected:
        ptype_name = "0rtt protected";
        break;
    case picoquic_packet_1rtt_protected:
        ptype_name = "1rtt protected";
        break;
    default:
        break;
    }

    return ptype_name;
}

char const* picoquic_log_tp_name(uint64_t tp_number)
{
    char const * tp_name = "unknown";

    switch (tp_number) {
    case picoquic_tp_original_connection_id:
        tp_name = "ocid";
        break;
    case picoquic_tp_idle_timeout:
        tp_name = "ocid";
        break;
    case picoquic_tp_stateless_reset_token:
        tp_name = "stateless_reset_token";
        break;
    case picoquic_tp_max_packet_size:
        tp_name = "max_packet_size";
        break;
    case picoquic_tp_initial_max_data:
        tp_name = "initial_max_data";
        break;
    case picoquic_tp_initial_max_stream_data_bidi_local:
        tp_name = "max_stream_data_bidi_local";
        break;
    case picoquic_tp_initial_max_stream_data_bidi_remote:
        tp_name = "max_stream_data_bidi_remote";
        break;
    case picoquic_tp_initial_max_stream_data_uni:
        tp_name = "max_stream_data_uni";
        break;
    case picoquic_tp_initial_max_streams_bidi:
        tp_name = "max_streams_bidi";
        break;
    case picoquic_tp_initial_max_streams_uni:
        tp_name = "max_streams_uni";
        break;
    case picoquic_tp_ack_delay_exponent:
        tp_name = "ack_delay_exponent";
        break;
    case picoquic_tp_max_ack_delay:
        tp_name = "max_ack_delay";
        break;
    case picoquic_tp_disable_migration:
        tp_name = "disable_migration";
        break;
    case picoquic_tp_server_preferred_address:
        tp_name = "server_preferred_address";
        break;
    case picoquic_tp_active_connection_id_limit:
        tp_name = "active_connection_id_limit";
        break;
    case picoquic_tp_max_datagram_size:
        tp_name = "max_datagram_size";
        break;
    default:
        break;
    }

    return tp_name;
}

void picoquic_log_connection_id(FILE* F, picoquic_connection_id_t * cid)
{
    fprintf(F, "<");
    for (uint8_t i = 0; i < cid->id_len; i++) {
        fprintf(F, "%02x", cid->id[i]);
    }
    fprintf(F, ">");
}

void picoquic_log_packet_header(FILE* F, uint64_t log_cnxid64, picoquic_packet_header* ph, int receiving)
{
    picoquic_log_prefix_initial_cid64(F, log_cnxid64);

    fprintf(F, "%s packet type: %d (%s), ", (receiving != 0)?"Receiving":"Sending",
        ph->ptype, picoquic_log_ptype_name(ph->ptype));

    fprintf(F, "S%d,", ph->spin);

    switch (ph->ptype) {
    case picoquic_packet_1rtt_protected:
        /* Short packets. Log dest CID and Seq number. */
        fprintf(F, "\n");
        picoquic_log_prefix_initial_cid64(F, log_cnxid64);
        fprintf(F, "    ");
        picoquic_log_connection_id(F, &ph->dest_cnx_id);
        fprintf(F, ", Seq: %d (%llu), Phi: %d,\n", ph->pn, (unsigned long long)ph->pn64, ph->key_phase);
        break;
    case picoquic_packet_version_negotiation:
        /* V nego. log both CID */
        fprintf(F, "\n");
        picoquic_log_prefix_initial_cid64(F, log_cnxid64);
        fprintf(F, "    ");
        picoquic_log_connection_id(F, &ph->dest_cnx_id);
        fprintf(F, ", ");
        picoquic_log_connection_id(F, &ph->srce_cnx_id);
        fprintf(F, "\n");
        break;
    default:
        /* Long packets. Log Vnum, both CID, Seq num, Payload length */
        fprintf(F, " Version %x,", ph->vn);

        fprintf(F, "\n");
        picoquic_log_prefix_initial_cid64(F, log_cnxid64);
        fprintf(F, "    ");
        picoquic_log_connection_id(F, &ph->dest_cnx_id);
        fprintf(F, ", ");
        picoquic_log_connection_id(F, &ph->srce_cnx_id);
        fprintf(F, ", Seq: %d, pl: %zd\n", ph->pn, ph->pl_val);
        if (ph->ptype == picoquic_packet_initial) {
            picoquic_log_prefix_initial_cid64(F, log_cnxid64);
            fprintf(F, "    Token length: %zd", ph->token_length);
            if (ph->token_length > 0) {
                size_t printed_length = (ph->token_length > 16) ? 16 : ph->token_length;
                fprintf(F, ", Token: ");
                for (size_t i = 0; i < printed_length; i++) {
                    fprintf(F, "%02x", ph->token_bytes[i]);
                }
                if (printed_length < ph->token_length) {
                    fprintf(F, "...");
                }
            }
            fprintf(F, "\n");
        }
        break;
    }
}

void picoquic_log_negotiation_packet(FILE* F, uint64_t log_cnxid64,
    uint8_t* bytes, size_t length, picoquic_packet_header* ph)
{
    size_t byte_index = ph->offset;
    uint32_t vn = 0;

    picoquic_log_prefix_initial_cid64(F, log_cnxid64);

    fprintf(F, "    versions: ");

    while (byte_index + 4 <= length) {
        vn = PICOPARSE_32(bytes + byte_index);
        byte_index += 4;
        fprintf(F, "%x, ", vn);
    }
    fprintf(F, "\n");
}

void picoquic_log_retry_packet(FILE* F, picoquic_cnx_t* cnx, uint64_t log_cnxid64,
    uint8_t* bytes, picoquic_packet_header* ph)
{
    size_t byte_index = ph->offset;
    int token_length = 0;
    uint8_t odcil;
    uint8_t unused_cil;
    int payload_length = (int)(ph->payload_length);
    /* Decode ODCIL from bottom 4 bits of first byte */
    if (cnx != NULL && picoquic_supported_versions[cnx->version_index].version ==
        PICOQUIC_TWELFTH_INTEROP_VERSION) {
        picoquic_parse_packet_header_cnxid_lengths(bytes[0], &unused_cil, &odcil);
    }
    else {
        odcil = bytes[byte_index];
        byte_index++;
        payload_length--;
    }

    if ((int)odcil > payload_length) {
        picoquic_log_prefix_initial_cid64(F, log_cnxid64);
        fprintf(F, "packet too short, ODCIL: %d, only %d bytes available.\n", 
            odcil, payload_length);
    } else {
        /* Dump the old connection ID */
        picoquic_log_prefix_initial_cid64(F, log_cnxid64);
        fprintf(F, "    ODCIL: <");
        for (uint8_t i = 0; i < odcil; i++) {
            fprintf(F, "%02x", bytes[byte_index++]);
        }

        token_length = payload_length - odcil;
        fprintf(F, ">, Token length: %d\n", token_length);
        /* Print the token or an error */
        if (token_length > 0) {
            int printed_length = (token_length > 16) ? 16 : token_length; 
            picoquic_log_prefix_initial_cid64(F, log_cnxid64);
            fprintf(F, "    Token: ");
            for (uint8_t i = 0; i < printed_length; i++) {
                fprintf(F, "%02x", bytes[byte_index++]);
            }
            if (printed_length < token_length) {
                fprintf(F, "...");
            }
            fprintf(F, "\n");
        }
    }
    fprintf(F, "\n");
}

#define VARINT_LEN(bytes) ((size_t)1 << (((bytes)[0] & 0xC0) >> 6))

static const uint8_t* picoquic_log_fixed_skip(const uint8_t* bytes, const uint8_t* bytes_max, size_t size)
{
    return bytes == NULL ? NULL : ((bytes += size) <= bytes_max ? bytes : NULL);
}

static const uint8_t* picoquic_log_varint_skip(const uint8_t* bytes, const uint8_t* bytes_max)
{
    return bytes == NULL ? NULL : (bytes < bytes_max ? picoquic_log_fixed_skip(bytes, bytes_max, VARINT_LEN(bytes)) : NULL);
}

static const uint8_t* picoquic_log_varint(const uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n64)
{
    size_t len = picoquic_varint_decode(bytes, bytes_max - bytes, n64);
    return len == 0 ? NULL : bytes + len;
}

void picoquic_log_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    if (bytes != NULL && bytes_max != NULL) {
        size_t len = bytes_max - bytes;
        uint8_t varlen[8];
        size_t l_varlen = picoquic_varint_encode(varlen, 8, len);
        fwrite(varlen, 1, l_varlen, f);
        fwrite(bytes, 1, len, f);
    }
}

const uint8_t* picoquic_log_stream_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    uint8_t ftype = bytes[0];
    uint64_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    if ((ftype & 4) != 0) {
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
    }

    if ((ftype & 2) != 0) {
        bytes = picoquic_log_varint(bytes, bytes_max, &length);
    } else {
        length = bytes_max - bytes;
    }

    picoquic_log_frame(f, bytes_begin, bytes);

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);
    return bytes;
}

const uint8_t* picoquic_log_ack_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    uint8_t ftype = bytes[0];
    uint64_t nb_blocks;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint(bytes, bytes_max, &nb_blocks);

    for (uint64_t i = 0; i <= nb_blocks; i++) {
        if (i != 0) {
            bytes = picoquic_log_varint_skip(bytes, bytes_max);
        }
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
    }

    if (ftype == picoquic_frame_type_ack_ecn) {
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
    }

    picoquic_log_frame(f, bytes_begin, bytes);
    return bytes;
}

const uint8_t* picoquic_log_reset_stream_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t * bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_log_frame(f, bytes_begin, bytes);
    return bytes;
}

const uint8_t* picoquic_log_stop_sending_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 2);

    picoquic_log_frame(f, bytes_begin, bytes);
    return bytes;
}

const uint8_t* picoquic_log_close_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    uint64_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint(bytes, bytes_max, &length);
    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);

    picoquic_log_frame(f, bytes_begin, bytes);
    return bytes;
}

const uint8_t* picoquic_log_max_data_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_log_frame(f, bytes_begin, bytes);
    return bytes;
}

const uint8_t* picoquic_log_max_stream_data_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_log_frame(f, bytes_begin, bytes);
    return bytes;
}

const uint8_t* picoquic_log_max_stream_id_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_log_frame(f, bytes_begin, bytes);
    return bytes;
}

const uint8_t* picoquic_log_blocked_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_log_frame(f, bytes_begin, bytes);
    return bytes;
}

const uint8_t* picoquic_log_stream_blocked_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_log_frame(f, bytes_begin, bytes);
    return bytes;
}

const uint8_t* picoquic_log_streams_blocked_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_log_frame(f, bytes_begin, bytes);
    return bytes;
}

const uint8_t* picoquic_log_new_connection_id_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    if (bytes != NULL) {
        bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1 + bytes[0]);
    }

    picoquic_log_frame(f, bytes_begin, bytes);

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, PICOQUIC_RESET_SECRET_SIZE);
    return bytes;
}

const uint8_t* picoquic_log_retire_connection_id_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_log_frame(f, bytes_begin, bytes);
    return bytes;
}

const uint8_t* picoquic_log_new_token_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    uint64_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint(bytes, bytes_max, &length);

    picoquic_log_frame(f, bytes_begin, bytes);

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);
    return bytes;
}

const uint8_t* picoquic_log_path_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1 + 8);

    picoquic_log_frame(f, bytes_begin, bytes);
    return bytes;
}

const uint8_t* picoquic_log_crypto_hs_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    uint64_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint(bytes, bytes_max, &length);

    picoquic_log_frame(f, bytes_begin, bytes);

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);
    return bytes;
}


const uint8_t* picoquic_log_datagram_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    uint8_t ftype = bytes[0];
    uint64_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);

    if (ftype & 2) {
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
    }

    if (ftype & 1) {
        bytes = picoquic_log_varint(bytes, bytes_max, &length);
    } else {
        length = bytes_max - bytes;
    }

    picoquic_log_frame(f, bytes_begin, bytes);

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);
    return bytes;
}

const uint8_t* picoquic_log_padding(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    picoquic_log_frame(f, bytes, bytes + 1);

    uint8_t ftype = bytes[0];
    while (bytes < bytes_max && bytes[0] == ftype) {
        bytes++;
    }

    return bytes;
}


void picoquic_log_frames(picoquic_cnx_t * cnx, const uint8_t* bytes, size_t length)
{
    const uint8_t* bytes_max = bytes + length;
    FILE * f = cnx->cc_log;

    while (bytes != NULL && bytes < bytes_max) {

        uint8_t ftype = bytes[0];

        if (PICOQUIC_IN_RANGE(ftype, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            bytes = picoquic_log_stream_frame(f, bytes, bytes_max);
            continue;
        }

        switch (ftype) {
        case picoquic_frame_type_ack:
        case picoquic_frame_type_ack_ecn:
            bytes = picoquic_log_ack_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_retire_connection_id:
            bytes = picoquic_log_retire_connection_id_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_padding:
        case picoquic_frame_type_ping:
            bytes = picoquic_log_padding(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_reset_stream:
            bytes = picoquic_log_reset_stream_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_connection_close:
        case picoquic_frame_type_application_close:
            bytes = picoquic_log_close_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_max_data:
            bytes = picoquic_log_max_data_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_max_stream_data:
            bytes = picoquic_log_max_stream_data_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_max_streams_bidir:
        case picoquic_frame_type_max_streams_unidir:
            bytes = picoquic_log_max_stream_id_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_data_blocked:
            bytes = picoquic_log_blocked_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_stream_data_blocked:
            bytes = picoquic_log_stream_blocked_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_streams_blocked_bidir:
        case picoquic_frame_type_streams_blocked_unidir:
            bytes = picoquic_log_streams_blocked_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_new_connection_id:
            bytes = picoquic_log_new_connection_id_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_stop_sending:
            bytes = picoquic_log_stop_sending_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_path_challenge:
        case picoquic_frame_type_path_response:
            bytes = picoquic_log_path_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_crypto_hs:
            bytes = picoquic_log_crypto_hs_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_new_token:
            bytes = picoquic_log_new_token_frame(f, bytes, bytes_max);
            break; 
        case picoquic_frame_type_datagram:
        case picoquic_frame_type_datagram_l:
        case picoquic_frame_type_datagram_id:
        case picoquic_frame_type_datagram_id_l:
            bytes = picoquic_log_datagram_frame(f, bytes, bytes_max);
            break;
        default:
            bytes = NULL;
            break;
        }
    }
}

void picoquic_log_decrypted_segment(void* F_log, int log_cnxid, picoquic_cnx_t* cnx,
    int receiving, picoquic_packet_header * ph, uint8_t* bytes, size_t length, uint64_t current_time)
{
    if (cnx == NULL || cnx->cc_log == NULL) {
        return;
    }

    if (picoquic_supported_versions[cnx->version_index].version == PICOQUIC_TWELFTH_INTEROP_VERSION) {
        return; /* for now, no support of writing logs for old versions */
    }


    bytestream_buf stream_head;
    bytestream* head = bytestream_buf_init(&stream_head, 8);

    long fpos0 = ftell(cnx->cc_log);
    (void)fwrite(bytestream_data(head), bytestream_size(head), 1, cnx->cc_log);

    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, 80);
    bytewrite_vint(msg, current_time - cnx->start_time);
    bytewrite_vint(msg, ph->pn64);
    bytewrite_vint(msg, ph->payload_length);
    bytewrite_vint(msg, ph->ptype);
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, cnx->cc_log);

    //uint64_t log_cnxid64 = picoquic_val64_connection_id(cnx->initial_cnxid);

    /* Header */
    //picoquic_log_packet_header(F, log_cnxid64, ph, receiving);

    if (ph->ptype == picoquic_packet_version_negotiation) {
        /* log version negotiation */
        //picoquic_log_negotiation_packet(F, log_cnxid64, bytes, length, ph);
    }
    else if (ph->ptype == picoquic_packet_retry) {
        /* log version negotiation */
        //picoquic_log_retry_packet(F, cnx, log_cnxid64, bytes, ph);
    }
    else if (ph->ptype != picoquic_packet_error) {
        picoquic_log_frames(cnx, bytes + ph->offset, ph->payload_length);
    }

    long fpos1 = ftell(cnx->cc_log);

    bytewrite_int32(head, receiving ? picoquic_log_event_packet_recv : picoquic_log_event_packet_sent);
    bytewrite_int32(head, (uint32_t)(fpos1 - fpos0 - 8));

    (void)fseek(cnx->cc_log, fpos0, SEEK_SET);
    (void)fwrite(bytestream_data(head), bytestream_size(head), 1, cnx->cc_log);
    (void)fseek(cnx->cc_log, 0, SEEK_END);
}

void picoquic_log_outgoing_segment(void* F_log, int log_cnxid, picoquic_cnx_t* cnx,
    uint8_t * bytes,
    uint64_t sequence_number,
    size_t length,
    uint8_t* send_buffer, size_t send_length, uint64_t current_time)
{
    picoquic_cnx_t* pcnx = cnx;
    picoquic_packet_header ph;
    size_t checksum_length = (cnx != NULL) ? picoquic_get_checksum_length(cnx, 0) : 16;
    struct sockaddr_in default_addr;
    int ret;

    if (F_log == NULL) {
        return;
    }

    memset(&default_addr, 0, sizeof(struct sockaddr_in));
    default_addr.sin_family = AF_INET;

    ret = picoquic_parse_packet_header((cnx == NULL) ? NULL : cnx->quic, send_buffer, send_length,
        ((cnx == NULL || cnx->path[0] == NULL) ? (struct sockaddr *)&default_addr :
        (struct sockaddr *)&cnx->path[0]->local_addr), &ph, &pcnx, 0);

    ph.pn64 = sequence_number;
    ph.pn = (uint32_t)ph.pn64;
    if (ph.ptype != picoquic_packet_retry) {
        if (ph.pn_offset != 0) {
            ph.offset = ph.pn_offset + 4; /* todo: should provide the actual length */
            ph.payload_length -= 4;
        }
    }
    if (ph.ptype != picoquic_packet_version_negotiation) {
        if (ph.payload_length > checksum_length) {
            ph.payload_length -= (uint16_t)checksum_length;
        }
        else {
            ph.payload_length = 0;
        }
    }
    /* log the segment. */
    picoquic_log_decrypted_segment(F_log, log_cnxid, cnx, 0,
        &ph, bytes, length, current_time);
}

int bytewrite_cid(bytestream* s, const picoquic_connection_id_t* cid)
{
    int ret = bytewrite_int8(s, cid->id_len);
    ret |= bytewrite_buffer(s, cid->id, cid->id_len);
    return ret;
}

int bytewrite_cstr(bytestream* s, const char * cstr)
{
    size_t l_cstr = cstr != NULL ? strlen(cstr) : 0;
    int ret = bytewrite_vint(s, l_cstr);
    ret |= bytewrite_buffer(s, cstr, l_cstr);
    return ret;
}

void picoquic_log_transport_extension(picoquic_cnx_t* cnx)
{
    char const* sni = picoquic_tls_get_sni(cnx);
    char const* alpn = picoquic_tls_get_negotiated_alpn(cnx);

    uint8_t* bytes = NULL;
    size_t bytes_max = 0;
    int ext_received_return = 0;
    int client_mode = 1;
    picoquic_provide_received_transport_extensions(cnx,
        &bytes, &bytes_max, &ext_received_return, &client_mode);

    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    bytewrite_cid(msg, &cnx->initial_cnxid);
    bytewrite_cstr(msg, sni);
    bytewrite_cstr(msg, alpn);
    bytewrite_vint(msg, bytes_max);
    bytewrite_buffer(msg, bytes, bytes_max);

    bytestream_buf stream_head;
    bytestream* head = bytestream_buf_init(&stream_head, 8);
    bytewrite_int32(head, picoquic_log_event_param_update);
    bytewrite_int32(head, (uint32_t)bytestream_length(msg));

    (void)fwrite(bytestream_data(head), bytestream_length(head), 1, cnx->cc_log);
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, cnx->cc_log);
}

void picoquic_log_picotls_ticket(FILE* f, picoquic_connection_id_t cnx_id,
    uint8_t* ticket, uint16_t ticket_length)
{
    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    bytewrite_cid(msg, &cnx_id);
    bytewrite_vint(msg, ticket_length);
    bytewrite_buffer(msg, ticket, ticket_length);

    bytestream_buf stream_head;
    bytestream* head = bytestream_buf_init(&stream_head, 8);
    bytewrite_int32(head, picoquic_log_event_tls_key_update);
    bytewrite_int32(head, (uint32_t)bytestream_length(msg));

    (void)fwrite(bytestream_data(head), bytestream_length(head), 1, f);
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}

/*
 * Check whether dumping of transmission traces is required. If it is,
 * the master context specifies the directory where to log the file.
 */

int picoquic_open_cc_dump(picoquic_cnx_t * cnx)
{
    if (cnx->cc_log != NULL) {
        DBG_PRINTF("%s", "CC LOG File is already open!\n");
        return -1;
    }

    if (cnx->quic->cc_log_dir == NULL) {
        DBG_PRINTF("%s", "CC LOG directory not set!\n");
        return -1;
    }

    char cc_log_file_name[512];
    char cnxid_str[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
    int ret = 0;

    if (picoquic_print_connection_id_hexa(cnxid_str, sizeof(cnxid_str), &cnx->initial_cnxid) != 0
        || picoquic_sprintf(cc_log_file_name, sizeof(cc_log_file_name), NULL, "%s%c%s-log.bin", cnx->quic->cc_log_dir, PICOQUIC_FILE_SEPARATOR, cnxid_str) != 0)
    {
        DBG_PRINTF("Cannot format file name into folder %s, id_len = %d\n", cnx->quic->cc_log_dir, cnx->initial_cnxid.id_len);
        ret = -1;
    }
    else {
        cnx->cc_log = picoquic_file_open(cc_log_file_name, "wb");
        if (cnx->cc_log == NULL) {
            DBG_PRINTF("Cannot open file %s for write.\n", cc_log_file_name);
            ret = -1;
        }
        else {
            /* Write a header text with version identifier and current date  */
            bytestream stream;
            bytestream * ps = bytestream_alloc(&stream, 16);
            bytewrite_int32(ps, FOURCC('q', 'l', 'o', 'g'));
            bytewrite_int32(ps, 0x01);
            bytewrite_int32(ps, (uint32_t)(picoquic_current_time() / 1000000ll));
            bytewrite_int32(ps, 0);

            if (fwrite(bytestream_data(ps), bytestream_length(ps), 1, cnx->cc_log) <= 0) {
                DBG_PRINTF("Cannot write header for file %s.\n", cc_log_file_name);
                cnx->cc_log = picoquic_file_close(cnx->cc_log);
            }

            bytestream_delete(ps);
        }
    }

    return ret;
}

void picoquic_close_cc_dump(picoquic_cnx_t * cnx)
{
    cnx->cc_log = picoquic_file_close(cnx->cc_log);
}

/*
 * Log the state of the congestion management, retransmission, etc.
 * Call either just after processing a received packet, or just after
 * sending a packet.
 */

void picoquic_cc_dump(picoquic_cnx_t * cnx, uint64_t current_time)
{
    if (cnx->cc_log == NULL) {
        return;
    }

    bytestream_buf stream_msg;
    bytestream * ps_msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    picoquic_packet_context_t * pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_application];
    picoquic_path_t * path = cnx->path[0];

    bytewrite_vint(ps_msg, current_time - cnx->start_time);
    bytewrite_vint(ps_msg, cnx->pkt_ctx[picoquic_packet_context_application].send_sequence);

    if (pkt_ctx->highest_acknowledged != (uint64_t)(int64_t)-1) {
        bytewrite_vint(ps_msg, 1);
        bytewrite_vint(ps_msg, pkt_ctx->highest_acknowledged);
        bytewrite_vint(ps_msg, pkt_ctx->highest_acknowledged_time - cnx->start_time);
        bytewrite_vint(ps_msg, pkt_ctx->latest_time_acknowledged - cnx->start_time);
    }
    else {
        bytewrite_vint(ps_msg, 0);
    }

    bytewrite_vint(ps_msg, path->cwin);
    bytewrite_vint(ps_msg, path->smoothed_rtt);
    bytewrite_vint(ps_msg, path->rtt_min);
    bytewrite_vint(ps_msg, path->send_mtu);
    bytewrite_vint(ps_msg, path->pacing_packet_time_microsec);
    bytewrite_vint(ps_msg, cnx->nb_retransmission_total);
    bytewrite_vint(ps_msg, cnx->nb_spurious);
    bytewrite_vint(ps_msg, cnx->cwin_blocked);
    bytewrite_vint(ps_msg, cnx->flow_blocked);
    bytewrite_vint(ps_msg, cnx->stream_blocked);

    bytestream_buf stream_head;
    bytestream * ps_head = bytestream_buf_init(&stream_head, BYTESTREAM_MAX_BUFFER_SIZE);

    bytewrite_int32(ps_head, picoquic_log_event_cc_update);
    bytewrite_int32(ps_head, (uint32_t)bytestream_length(ps_msg));

    (void)fwrite(bytestream_data(ps_head), bytestream_length(ps_head), 1, cnx->cc_log);
    (void)fwrite(bytestream_data(ps_msg), bytestream_length(ps_msg), 1, cnx->cc_log);

    cnx->cwin_blocked = 0;
    cnx->flow_blocked = 0;
    cnx->stream_blocked = 0;
}

/* Open the bin file for reading */
FILE * picoquic_open_cc_log_file_for_read(char const * bin_cc_log_name, uint32_t * log_time)
{
    int ret = 0;
    FILE * bin_log = picoquic_file_open(bin_cc_log_name, "rb");
    if (bin_log == NULL) {
        DBG_PRINTF("Cannot open CC file %s.\n", bin_cc_log_name);
        ret = -1;
    }

    if (ret == 0) {
        bytestream_buf stream;
        bytestream * ps = bytestream_buf_init(&stream, 16);

        uint32_t fcc = 0;
        uint32_t version = 0;

        if (fread(stream.buf, bytestream_size(ps), 1, bin_log) <= 0) {
            ret = -1;
            DBG_PRINTF("Cannot read header for file %s.\n", bin_cc_log_name);
        }
        else if (byteread_int32(ps, &fcc) != 0 || fcc != FOURCC('q', 'l', 'o', 'g')) {
            ret = -1;
            DBG_PRINTF("Header for file %s does not start with magic number.\n", bin_cc_log_name);
        }
        else if (byteread_int32(ps, &version) != 0 || version != 0x01) {
            ret = -1;
            DBG_PRINTF("Header for file %s requires unsupported version.\n", bin_cc_log_name);
        }
        else {
            ret = byteread_int32(ps, log_time);
        }
    }

    if (ret != 0) {
        bin_log = picoquic_file_close(bin_log);
    }

    return bin_log;
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
            ret |= byteread_int32(ps_head, &id);
            ret |= byteread_int32(ps_head, &len);

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