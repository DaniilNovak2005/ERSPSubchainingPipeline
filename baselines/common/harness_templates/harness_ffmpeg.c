/*
 * Unified Validation Harness — FFmpeg
 *
 * Compile:
 *   gcc -fsanitize=address -g -O0 -w \
 *       -I<ffmpeg_src> \
 *       harness_ffmpeg.c \
 *       <ffmpeg_src>/libavcodec/libavcodec.a \
 *       <ffmpeg_src>/libavformat/libavformat.a \
 *       <ffmpeg_src>/libavutil/libavutil.a \
 *       <ffmpeg_src>/libswresample/libswresample.a \
 *       <ffmpeg_src>/libavfilter/libavfilter.a \
 *       -lm -lz -lpthread -ldl -o test_harness
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/avutil.h>
#include <libavutil/frame.h>
#include <libavutil/imgutils.h>
#include <libavutil/mem.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersrc.h>
#include <libavfilter/buffersink.h>

/* ================================================================
 * BASELINE INPUT
 * ================================================================ */

#ifndef TARGET_FUNC
#define TARGET_FUNC  "decode_nal_unit"
#define TARGET_FILE  "hevc_ps.c"
#define TARGET_LINE  0
#endif

#ifndef ENTRY_PATH
#define ENTRY_PATH "decode_packet"
/* Options: "decode_packet", "encode_frame", "parse_header", "filter" */
#endif

/* Codec parameters (baseline provides these) */
#ifndef INPUT_CODEC_ID
#define INPUT_CODEC_ID AV_CODEC_ID_H264
#endif

#ifndef INPUT_ENCODER_NAME
#define INPUT_ENCODER_NAME "libx264"
#endif

#ifndef INPUT_WIDTH
#define INPUT_WIDTH 64
#endif

#ifndef INPUT_HEIGHT
#define INPUT_HEIGHT 64
#endif

#ifndef INPUT_PIX_FMT
#define INPUT_PIX_FMT AV_PIX_FMT_YUV420P
#endif

/* ================================================================
 * Entry path implementations
 * ================================================================ */

static int test_decode_packet(void) {
    const AVCodec *codec = avcodec_find_decoder(INPUT_CODEC_ID);
    if (!codec) {
        fprintf(stderr, "Codec not found\n");
        return 1;
    }

    AVCodecContext *ctx = avcodec_alloc_context3(codec);
    if (!ctx) return 1;

    if (avcodec_open2(ctx, codec, NULL) < 0) {
        fprintf(stderr, "Could not open codec\n");
        avcodec_free_context(&ctx);
        return 1;
    }

    /* Create a synthetic packet with controlled data */
    AVPacket *pkt = av_packet_alloc();
    if (!pkt) { avcodec_free_context(&ctx); return 1; }

    /* Allocate packet buffer with crafted NAL-like data */
    int buf_size = 1024;
    uint8_t *buf = av_malloc(buf_size + AV_INPUT_BUFFER_PADDING_SIZE);
    memset(buf, 0, buf_size + AV_INPUT_BUFFER_PADDING_SIZE);

    /* Start code + NAL header */
    buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x01;
    buf[3] = 0x67;  /* SPS NAL unit */
    /* Fill rest with semi-valid data */
    for (int i = 4; i < buf_size; i++)
        buf[i] = (uint8_t)(i & 0xff);

    pkt->data = buf;
    pkt->size = buf_size;

    /* Send packet and receive frame */
    AVFrame *frame = av_frame_alloc();
    avcodec_send_packet(ctx, pkt);

    int ret;
    while ((ret = avcodec_receive_frame(ctx, frame)) == 0) {
        /* Frame decoded — exercise output */
    }

    /* Flush decoder */
    avcodec_send_packet(ctx, NULL);
    while (avcodec_receive_frame(ctx, frame) == 0) { }

    av_frame_free(&frame);
    av_free(buf);
    av_packet_free(&pkt);
    avcodec_free_context(&ctx);
    return 0;
}

static int test_encode_frame(void) {
    const AVCodec *codec = avcodec_find_encoder_by_name(INPUT_ENCODER_NAME);
    if (!codec) {
        /* Fall back to built-in encoder */
        codec = avcodec_find_encoder(AV_CODEC_ID_MPEG2VIDEO);
        if (!codec) {
            fprintf(stderr, "No encoder found\n");
            return 1;
        }
    }

    AVCodecContext *ctx = avcodec_alloc_context3(codec);
    if (!ctx) return 1;

    ctx->width = INPUT_WIDTH;
    ctx->height = INPUT_HEIGHT;
    ctx->pix_fmt = INPUT_PIX_FMT;
    ctx->time_base = (AVRational){1, 25};

    if (avcodec_open2(ctx, codec, NULL) < 0) {
        fprintf(stderr, "Could not open encoder\n");
        avcodec_free_context(&ctx);
        return 1;
    }

    AVFrame *frame = av_frame_alloc();
    frame->format = ctx->pix_fmt;
    frame->width = ctx->width;
    frame->height = ctx->height;
    av_frame_get_buffer(frame, 0);

    AVPacket *pkt = av_packet_alloc();

    /* Encode a few frames */
    for (int i = 0; i < 5; i++) {
        av_frame_make_writable(frame);
        /* Fill with gradient pattern */
        for (int y = 0; y < ctx->height; y++) {
            for (int x = 0; x < ctx->width; x++) {
                frame->data[0][y * frame->linesize[0] + x] =
                    (uint8_t)((x + y + i * 3) & 0xff);
            }
        }
        /* Fill U/V planes */
        for (int y = 0; y < ctx->height / 2; y++) {
            for (int x = 0; x < ctx->width / 2; x++) {
                frame->data[1][y * frame->linesize[1] + x] = 128;
                frame->data[2][y * frame->linesize[2] + x] = 128;
            }
        }
        frame->pts = i;

        avcodec_send_frame(ctx, frame);
        while (avcodec_receive_packet(ctx, pkt) == 0)
            av_packet_unref(pkt);
    }

    /* Flush encoder */
    avcodec_send_frame(ctx, NULL);
    while (avcodec_receive_packet(ctx, pkt) == 0)
        av_packet_unref(pkt);

    av_packet_free(&pkt);
    av_frame_free(&frame);
    avcodec_free_context(&ctx);
    return 0;
}

static int test_parse_header(void) {
    /* Use avformat probing to parse header from in-memory buffer */
    const char *tmppath = "/tmp/sailor_harness_ffmpeg.dat";
    FILE *fp = fopen(tmppath, "wb");
    if (!fp) return 1;

    /* Write minimal data for format probing */
    unsigned char probe_data[4096];
    memset(probe_data, 0, sizeof(probe_data));
    /* RIFF/AVI signature for probing */
    memcpy(probe_data, "RIFF", 4);
    uint32_t sz = sizeof(probe_data) - 8;
    memcpy(probe_data + 4, &sz, 4);
    memcpy(probe_data + 8, "AVI ", 4);
    fwrite(probe_data, 1, sizeof(probe_data), fp);
    fclose(fp);

    AVFormatContext *fmt_ctx = NULL;
    int ret = avformat_open_input(&fmt_ctx, tmppath, NULL, NULL);
    if (ret < 0) {
        char errbuf[128];
        av_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "avformat_open_input: %s\n", errbuf);
        return 1;
    }

    avformat_find_stream_info(fmt_ctx, NULL);

    fprintf(stderr, "Format: %s, streams: %d\n",
            fmt_ctx->iformat->name, fmt_ctx->nb_streams);

    avformat_close_input(&fmt_ctx);
    return 0;
}

static int test_filter(void) {
    const AVFilter *buffersrc = avfilter_get_by_name("buffer");
    const AVFilter *buffersink = avfilter_get_by_name("buffersink");
    if (!buffersrc || !buffersink) {
        fprintf(stderr, "Could not find buffer filters\n");
        return 1;
    }

    AVFilterGraph *graph = avfilter_graph_alloc();
    if (!graph) return 1;

    char args[256];
    snprintf(args, sizeof(args),
             "video_size=%dx%d:pix_fmt=%d:time_base=1/25",
             INPUT_WIDTH, INPUT_HEIGHT, INPUT_PIX_FMT);

    AVFilterContext *src_ctx = NULL, *sink_ctx = NULL;
    int ret = avfilter_graph_create_filter(&src_ctx, buffersrc, "in",
                                            args, NULL, graph);
    if (ret < 0) { avfilter_graph_free(&graph); return 1; }

    ret = avfilter_graph_create_filter(&sink_ctx, buffersink, "out",
                                        NULL, NULL, graph);
    if (ret < 0) { avfilter_graph_free(&graph); return 1; }

    /* Link src → sink directly (null filter) */
    ret = avfilter_link(src_ctx, 0, sink_ctx, 0);
    if (ret < 0) { avfilter_graph_free(&graph); return 1; }

    ret = avfilter_graph_config(graph, NULL);
    if (ret < 0) { avfilter_graph_free(&graph); return 1; }

    /* Push a frame through the filter */
    AVFrame *frame = av_frame_alloc();
    frame->format = INPUT_PIX_FMT;
    frame->width = INPUT_WIDTH;
    frame->height = INPUT_HEIGHT;
    av_frame_get_buffer(frame, 0);

    for (int y = 0; y < INPUT_HEIGHT; y++)
        memset(frame->data[0] + y * frame->linesize[0], 128, INPUT_WIDTH);
    for (int y = 0; y < INPUT_HEIGHT / 2; y++) {
        memset(frame->data[1] + y * frame->linesize[1], 128, INPUT_WIDTH / 2);
        memset(frame->data[2] + y * frame->linesize[2], 128, INPUT_WIDTH / 2);
    }
    frame->pts = 0;

    av_buffersrc_add_frame(src_ctx, frame);

    AVFrame *filt_frame = av_frame_alloc();
    while (av_buffersink_get_frame(sink_ctx, filt_frame) >= 0)
        av_frame_unref(filt_frame);

    av_frame_free(&filt_frame);
    av_frame_free(&frame);
    avfilter_graph_free(&graph);
    return 0;
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void) {
    fprintf(stderr, "Target: %s at %s:%d\n", TARGET_FUNC, TARGET_FILE, TARGET_LINE);
    fprintf(stderr, "Entry path: %s\n", ENTRY_PATH);

    if (strcmp(ENTRY_PATH, "decode_packet") == 0) return test_decode_packet();
    if (strcmp(ENTRY_PATH, "encode_frame") == 0) return test_encode_frame();
    if (strcmp(ENTRY_PATH, "parse_header") == 0) return test_parse_header();
    if (strcmp(ENTRY_PATH, "filter") == 0) return test_filter();

    fprintf(stderr, "Unknown entry path: %s\n", ENTRY_PATH);
    return 1;
}
