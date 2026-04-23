# Running SAILOR on a New Target

All commands should be run from the repository root.

## Step 1: Clone the target project

```bash
git clone <repo_url> dataset/<commit>/<project_name>
git -C dataset/<commit>/<project_name> checkout <commit>
```

## Step 2: Create a build config

Create `configs/<project_name>_config.sh` with project-specific
settings. Use an existing config as a template:

```bash
# Example: configs/libtiff_f324415_vul_config.sh
cat configs/libtiff_f324415_vul_config.sh
```

Key settings:
- `EXTRA_CFLAGS`: include paths for the project headers
- `TOOL_FILES`: comma-separated list of CLI tool source files to
  exclude from analysis (e.g., `test_*.c,example_*.c`)
- `NON_LIBRARY_FILES`: source files not compiled into the `.a`

```bash
cat > configs/<project_name>_config.sh << 'EOF'
#!/bin/bash
export EXTRA_CFLAGS="-I${SRC_ROOT}/include"
export TOOL_FILES="test_*.c,example_*.c"
export NON_LIBRARY_FILES=""
EOF
```

## Step 3: Phase 1 — CodeQL scan + spec generation

```bash
docker run --rm \
    -v $(pwd)/dataset:/app/dataset \
    -v $(pwd)/sa_outputs:/app/sa_outputs \
    -v $(pwd)/specs:/app/specs \
    -v $(pwd)/rules:/app/rules \
    -v $(pwd)/configs:/app/configs \
    sailor bash -c "./sailor_prepare.sh <commit>/<project_name>"
```

This produces vulnerability specifications in `specs/<project_name>/`.
Check how many specs were generated:
```bash
ls specs/<project_name>/*.json | wc -l
```

## Step 4: Phase 2+3 — LLM harness synthesis + KLEE + validation

```bash
source .env
docker run --rm \
    -e LLM_API_KEY="$LLM_API_KEY" \
    -e LLM_API_BASE="$LLM_API_BASE" \
    -e LLM_MODEL="$LLM_MODEL" \
    -e JOBS=64 \
    -v $(pwd)/dataset:/app/dataset \
    -v $(pwd)/sa_outputs:/app/sa_outputs \
    -v $(pwd)/specs:/app/specs \
    -v $(pwd)/se_runs:/app/se_runs \
    -v $(pwd)/rules:/app/rules \
    -v $(pwd)/configs:/app/configs \
    sailor bash -c "./sailor.sh <commit>/<project_name>"
```

## Step 5: Results

```bash
# Summary of all specs
cat se_runs/sailor_engine/<project_name>/summary.tsv

# Count confirmed bugs
grep -c "VALIDATED_TP" se_runs/sailor_engine/<project_name>/summary.tsv
```

## Requirements

- C/C++ project with a build system (autotools, cmake, or custom)
- Project must produce a static archive (`.a`) for concrete validation
- Build config specifying include paths and files to exclude
