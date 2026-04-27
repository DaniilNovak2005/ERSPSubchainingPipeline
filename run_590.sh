SPEC="590_parser.c_11460_local_cpp_cwe-125-cursor-lookahead-missing-bytes-check"
DIR="manual_replay/specs/$SPEC"

gcc -fsanitize=address -g -O1 -fno-omit-frame-pointer \
    -I manual_replay/asan_build/include \
    -include manual_replay/klee_compat.h \
    "$DIR/replay_driver.c" \
    manual_replay/asan_build/.libs/libxml2.a \
    -o "$DIR/replay_driver" \
    -lm -lz -lpthread -ldl -Wl,--allow-multiple-definition
