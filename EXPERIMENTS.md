# Reproducing Experiments

## Prerequisites

1. **Dataset**: Run `bash setup_dataset.sh` (see DATASET.md)
2. **Docker**: SAILOR Docker image with KLEE 3.1, Clang 14, CodeQL
   ```bash
   docker build -t sailor .
   ```
3. **API Keys**:
   - GPT-5: `export LLM_API_KEY=<your-openai-key>`
   - DeepSeek-V3: `export DEEPSEEK_API_KEY=<your-deepseek-key>`
   - Claude Code: `claude login` (Max plan required for B5)
4. **Hardware**: 128-core server, 251GB RAM recommended

## Environment Setup

```bash
# Create .env for SAILOR and baselines
cat > .env << EOF
export LLM_API_KEY=<your-openai-key>
export LLM_API_BASE=https://api.openai.com/v1
export LLM_MODEL=gpt-5
EOF

# For DeepSeek variant
cat > .env.deepseek << EOF
export LLM_API_KEY=<your-deepseek-key>
export LLM_API_BASE=https://api.deepseek.com/v1
export LLM_MODEL=deepseek-chat
EOF
```

## Experiment 1: SAILOR-GPT5 (Main Result)

### Step 1: CodeQL Scan + Spec Generation
```bash
source .env
for commit_proj in \
    "e334a9d/libxml2_e334a9d_vul" \
    "f324415/libtiff_f324415_vul" \
    "747dd02/libpng_747dd02_vul" \
    "b2bc71a/binutils_b2bc71a_vul" \
    "2eebc58/curl_2eebc58_vul" \
    "67b5686b/openssl_67b5686b_vul" \
    "f46e5144/ffmpeg_f46e5144_vul" \
    "ca10fc4/libselinux_ca10fc4_vul" \
    "0f08d958/sqlite_0f08d958_vul" \
    "21fb0a2b/mupdf_21fb0a2b_vul"; do

    docker run --rm \
        -v $(pwd)/dataset:/app/dataset \
        -v $(pwd)/sa_outputs:/app/sa_outputs \
        -v $(pwd)/specs:/app/specs \
        -v $(pwd)/rules:/app/rules \
        -v $(pwd)/configs:/app/configs \
        sailor bash -c "./sailor_prepare.sh $commit_proj"
done
```

### Step 2: Run SAILOR Agent + KLEE
```bash
source .env
for commit_proj in \
    "e334a9d/libxml2_e334a9d_vul" \
    "f324415/libtiff_f324415_vul" \
    # ... (all 10 projects)
    ; do

    proj=$(echo $commit_proj | cut -d/ -f2)
    docker run --rm \
        --name sailor_${proj} \
        --memory=200g \
        -e LLM_API_KEY="${LLM_API_KEY}" \
        -e LLM_API_BASE="${LLM_API_BASE}" \
        -e LLM_MODEL="${LLM_MODEL}" \
        -e JOBS=128 \
        -v $(pwd)/dataset:/app/dataset \
        -v $(pwd)/configs:/app/configs \
        -v $(pwd)/sa_outputs:/app/sa_outputs \
        -v $(pwd)/specs:/app/specs \
        -v $(pwd)/se_runs:/app/se_runs \
        -v $(pwd)/rules:/app/rules \
        sailor bash -c "./sailor.sh $commit_proj"
done
```

### Step 3: Results
Results appear in `se_runs/sailor_engine/<project>/summary.tsv`.
Concrete validation is in-pipeline (ktest replay against `.a`).

**Expected**: 421 confirmed crashes (379 unique) across 10 projects.
**Time**: ~2-3 hours per project with 128 parallel jobs.
**Cost**: ~2,288M total LLM tokens across all projects.

## Experiment 2: SAILOR-DeepSeek

Same as Experiment 1 but with `.env.deepseek`:
```bash
source .env.deepseek
# Same docker commands, output to se_runs/sailor_deepseek/
```

**Expected**: ~12+ verified bugs (partial results available).

## Experiment 3: B1 — Human Harness (OSS-Fuzz) + KLEE

```bash
# Runs inside Docker (needs KLEE for symbolic execution)
docker run --rm \
    -v $(pwd)/dataset:/app/dataset \
    -v $(pwd)/se_runs/b1:/app/se_runs/b1 \
    sailor bash -c '
        python3 baselines/b1_ossfuzz_se/run_b1.py \
            --project libtiff_f324415_vul \
            --dataset-root /app/dataset/f324415/libtiff_f324415_vul \
            --output-dir /app/se_runs/b1/libtiff_f324415_vul
    '
```

For projects without OSS-Fuzz harnesses (libpng, SQLite, mupdf),
manually written harnesses are needed. These are withheld from this
artifact pending responsible disclosure and will be released upon
completion of the disclosure process.

**Expected**: 0 confirmed bugs across all projects. Harnesses
target API-level entry points too broad for symbolic execution;
56 of 86 (62%) fail to compile for KLEE.

## Experiment 4: B2 — Single-shot LLM Harness + KLEE

```bash
source .env
docker run --rm \
    -e LLM_API_KEY="$LLM_API_KEY" \
    -e LLM_API_BASE="$LLM_API_BASE" \
    -e LLM_MODEL="$LLM_MODEL" \
    -v $(pwd)/dataset:/app/dataset \
    -v $(pwd)/se_runs/b2:/app/se_runs/b2 \
    sailor bash -c '
        python3 baselines/b2_llm_harness_se/run_b2.py \
            --project libtiff_f324415_vul \
            --dataset-root /app/dataset/f324415/libtiff_f324415_vul \
            --output-dir /app/se_runs/b2/libtiff_f324415_vul \
            --klee-timeout 300 \
            --num-rounds 3 \
            --jobs 4
    '
```

**Expected**: 0 confirmed bugs. 228 of 281 (81%) harnesses fail to
compile due to LLM hallucinations without iterative feedback.

## Experiment 5: B3 — Pure LLM Detect

```bash
source .env
python3 baselines/b3_llm_detect/run_b3.py \
    --project libtiff_f324415_vul \
    --dataset-root dataset/f324415/libtiff_f324415_vul \
    --output-dir se_runs/b3/libtiff_f324415_vul \
    --max-files 0  # scan all files
```

### Strict Validation (strip-and-relink)
```bash
python3 scripts/revalidate_baselines.py \
    --baseline b3 \
    --findings-dir se_runs/b3/libtiff_f324415_vul/findings \
    --unmodified project-libs dataset/f324415/libtiff_f324415_vul/build_simple/libtiff.a \
    --include-dirs dataset/f324415/libtiff_f324415_vul/libtiff \
    --src-root dataset/f324415/libtiff_f324415_vul \
    --output-dir /tmp/b3_validated/libtiff \
    --jobs 16
```

**Expected**: 5 unique / 6 confirmed (all in libtiff).
**Time**: ~8-14 hours per project (API-bound).

## Experiment 6: B4 — SA + LLM Detect

```bash
source .env
python3 baselines/b4_sa_llm_detect/run_b4.py \
    --project libtiff_f324415_vul \
    --dataset-root dataset/f324415/libtiff_f324415_vul \
    --sa-outputs-dir sa_outputs/libtiff_f324415_vul \
    --output-dir se_runs/b4/libtiff_f324415_vul
```

### Strict Validation
```bash
python3 scripts/revalidate_baselines.py \
    --baseline b4 \
    --findings-dir se_runs/b4/libtiff_f324415_vul/findings \
    --unmodified project-libs dataset/f324415/libtiff_f324415_vul/build_simple/libtiff.a \
    --include-dirs dataset/f324415/libtiff_f324415_vul/libtiff \
    --src-root dataset/f324415/libtiff_f324415_vul \
    --output-dir /tmp/b4_validated/libtiff \
    --jobs 16
```

**Expected**: 2 verified (SELinux only).

## Experiment 7: B5 — Agentic (Claude Code)

```bash
# Requires Claude Code CLI: npm install -g @anthropic-ai/claude-code
# Requires Claude Max plan: claude login

python3 baselines/b5_agentic_llm/run_b5.py \
    --project openssl_67b5686b_vul \
    --dataset-root dataset/67b5686b/openssl_67b5686b_vul \
    --output-dir se_runs/b5/openssl_67b5686b_vul \
    --unmodified project-libs dataset/67b5686b/openssl_67b5686b_vul/libcrypto.a,dataset/67b5686b/openssl_67b5686b_vul/libssl.a \
    --extra-include-dirs dataset/67b5686b/openssl_67b5686b_vul/include \
    --max-targets 9999 --timeout 600 --jobs 16
```

**Expected**: 12 verified (OpenSSL=5, SELinux=6, SQLite=1).
**Cost**: ~$270 total across 10 projects (Claude Max plan).

## Experiment 8: A1 — SAILOR − SA (Ablation)

```bash
source .env
python3 baselines/a1_sailor_no_sa/run_a1.py \
    --project libtiff_f324415_vul \
    --dataset-root dataset/f324415/libtiff_f324415_vul \
    --output-dir se_runs/a1/libtiff_f324415_vul \
    --max-files 50 --jobs 64
```

Then run Phase 2 in Docker (same as SAILOR but with LLM-discovered specs).

**Expected**: 31 unique (libtiff=11, libxml2=20). FPE and non-.a bugs excluded.

## Concrete Validation Standard

All baselines use the same strict validation:

> **A bug is confirmed only if ASan crashes inside the real unmodified project `.a`
> library code — not in reproducer, copied functions, or stub code.**

| Approach | Validation Method | Script |
|----------|------------------|--------|
| SAILOR / A1 | In-pipeline ktest replay against `.a` | Automatic |
| B3 / B4 | Strip static copies, link against `.a` | `scripts/revalidate_baselines.py` |
| B5 | Direct `.a` linking (reproducer calls real API) | Automatic |
| B1 / B2 | KLEE-native (crash location in bitcode) | Automatic |

## Utility Scripts

```bash
# Collect LLM token usage across experiments
python3 scripts/collect_token_usage.py --se-runs se_runs/
```

## Expected Results Summary

| Baseline | Unique | Confirmed | Detected |
|----------|--------|-----------|----------|
| B1 | 0 | 0 | 19 |
| B2 | 0 | 0 | 86 |
| B3 | 5 | 5 | 1,781 |
| B4 | 2 | 2 | 1,363 |
| B5 | 12 | 12 | 430 |
| A1 | 31 | 31 | 276 |
| **SAILOR** | **379** | **421** | **1,345** |

Detailed results: `export/baseline_confirmed/baseline_confirmed.csv`

> **Note:** Crash reproducers, per-bug vulnerability details, fuzz reproduction
> artifacts, and case studies are withheld from this artifact because the
> discovered vulnerabilities are undergoing responsible disclosure. These
> materials will be released upon completion of the disclosure process.
