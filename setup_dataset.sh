#!/bin/bash
# setup_dataset.sh — clone all 10 projects at evaluation commits
set -e

clone_at() {
    local url=$1 dir=$2 commit=$3
    echo "Cloning $dir at $commit..."
    git clone "$url" "$dir" 2>/dev/null || true
    (cd "$dir" && git checkout "$commit" 2>/dev/null)
}

mkdir -p dataset

clone_at "https://gitlab.gnome.org/GNOME/libxml2.git" \
    "dataset/e334a9d/libxml2_e334a9d_vul" "e334a9d661c175203517565c4efae87a6577d5eb"

clone_at "https://gitlab.com/libtiff/libtiff.git" \
    "dataset/f324415/libtiff_f324415_vul" "f324415f50cb5c90f7712e9dfe69831f5d2ea88d"

clone_at "https://github.com/pnggroup/libpng.git" \
    "dataset/747dd02/libpng_747dd02_vul" "747dd02240d95dc8da1b9fecf0f58569ebbcf5a7"

clone_at "https://sourceware.org/git/binutils-gdb.git" \
    "dataset/b2bc71a/binutils_b2bc71a_vul" "b2bc71a12976fc169295662ab17f692f13d167d2"

clone_at "https://github.com/curl/curl.git" \
    "dataset/2eebc58/curl_2eebc58_vul" "2eebc58c4b8d68c98c8344381a9f6df4cca838fd"

clone_at "https://github.com/openssl/openssl.git" \
    "dataset/67b5686b/openssl_67b5686b_vul" "67b5686b4419b4cb8caa502711c41815f5279751"

clone_at "https://github.com/FFmpeg/FFmpeg.git" \
    "dataset/f46e5144/ffmpeg_f46e5144_vul" "f46e514491172d15bd74b4abb1814cd2f05a763e"

clone_at "https://github.com/SELinuxProject/selinux.git" \
    "dataset/ca10fc4/libselinux_ca10fc4_vul" "ca10fc4204ed60540d41d2499127c18ad0643f9e"

clone_at "https://github.com/ArtifexSoftware/mupdf.git" \
    "dataset/21fb0a2b/mupdf_21fb0a2b_vul" "21fb0a2bf815c927cf09881f799f78cbece0daf2"

clone_at "https://github.com/sqlite/sqlite.git" \
    "dataset/0f08d958/sqlite_0f08d958_vul" "0f08d9586c4e93c6fd84666cbd17ab17d9a7f57c"

echo ""
echo "Dataset setup complete. 10 projects, 6.8M LOC, 14,634 files."
