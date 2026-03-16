_llama_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="-h --help --usage --version --license -cl --cache-list --completion-bash --verbose-prompt -t --threads -tb --threads-batch -C --cpu-mask -Cr --cpu-range --cpu-strict --prio --poll -Cb --cpu-mask-batch -Crb --cpu-range-batch --cpu-strict-batch --prio-batch --poll-batch -c --ctx-size -n --predict --n-predict -b --batch-size -ub --ubatch-size --keep --swa-full -fa --flash-attn -p --prompt --perf -f --file -bf --binary-file -e --escape --rope-scaling --rope-scale --rope-freq-base --rope-freq-scale --yarn-orig-ctx --yarn-ext-factor --yarn-attn-factor --yarn-beta-slow --yarn-beta-fast -kvo --kv-offload --repack --no-host -ctk --cache-type-k -ctv --cache-type-v -dt --defrag-thold -np --parallel --mlock --mmap -dio --direct-io --numa -dev --device --list-devices -ot --override-tensor -cmoe --cpu-moe -ncmoe --n-cpu-moe -ngl --gpu-layers --n-gpu-layers -sm --split-mode -ts --tensor-split -mg --main-gpu -fit --fit -fitt --fit-target -fitc --fit-ctx --check-tensors --override-kv --op-offload --lora --lora-scaled --control-vector --control-vector-scaled --control-vector-layer-range -m --model -mu --model-url -dr --docker-repo -hf -hfr --hf-repo -hfd -hfrd --hf-repo-draft -hff --hf-file -hfv -hfrv --hf-repo-v -hffv --hf-file-v -hft --hf-token --log-disable --log-file --log-colors -v --verbose --log-verbose --offline -lv --verbosity --log-verbosity --log-prefix --log-timestamps -ctkd --cache-type-k-draft -ctvd --cache-type-v-draft --samplers -s --seed --sampler-seq --sampling-seq --ignore-eos --temp --temperature --top-k --top-p --min-p --top-nsigma --top-n-sigma --xtc-probability --xtc-threshold --typical --typical-p --repeat-last-n --repeat-penalty --presence-penalty --frequency-penalty --dry-multiplier --dry-base --dry-allowed-length --dry-penalty-last-n --dry-sequence-breaker --adaptive-target --adaptive-decay --dynatemp-range --dynatemp-exp --mirostat --mirostat-lr --mirostat-ent -l --logit-bias --grammar --grammar-file -j --json-schema -jf --json-schema-file -bs --backend-sampling --display-prompt -co --color -ctxcp --ctx-checkpoints --swa-checkpoints -cpent --checkpoint-every-n-tokens -cram --cache-ram --context-shift -sys --system-prompt --show-timings -sysf --system-prompt-file -r --reverse-prompt -sp --special -cnv --conversation -st --single-turn -mli --multiline-input --warmup -mm --mmproj -mmu --mmproj-url --mmproj-auto --mmproj-offload --image --audio --image-min-tokens --image-max-tokens -otd --override-tensor-draft -cmoed --cpu-moe-draft -ncmoed --n-cpu-moe-draft --chat-template-kwargs --jinja --reasoning-format -rea --reasoning --reasoning-budget --reasoning-budget-message --chat-template --chat-template-file --simple-io --draft --draft-n --draft-max --draft-min --draft-n-min --draft-p-min -cd --ctx-size-draft -devd --device-draft -ngld --gpu-layers-draft --n-gpu-layers-draft -md --model-draft --spec-replace --gpt-oss-20b-default --gpt-oss-120b-default --vision-gemma-4b-default --vision-gemma-12b-default "

    case "$prev" in
        --model|-m)
            COMPREPLY=( $(compgen -f -X '!*.gguf' -- "$cur") $(compgen -d -- "$cur") )
            return 0
            ;;
        --grammar-file)
            COMPREPLY=( $(compgen -f -X '!*.gbnf' -- "$cur") $(compgen -d -- "$cur") )
            return 0
            ;;
        --chat-template-file)
            COMPREPLY=( $(compgen -f -X '!*.jinja' -- "$cur") $(compgen -d -- "$cur") )
            return 0
            ;;
        *)
            COMPREPLY=( $(compgen -W "${opts}" -- "$cur") )
            return 0
            ;;
    esac
}

complete -F _llama_completions llama-batched
complete -F _llama_completions llama-batched-bench
complete -F _llama_completions llama-bench
complete -F _llama_completions llama-cli
complete -F _llama_completions llama-completion
complete -F _llama_completions llama-convert-llama2c-to-ggml
complete -F _llama_completions llama-cvector-generator
complete -F _llama_completions llama-debug
complete -F _llama_completions llama-diffusion-cli
complete -F _llama_completions llama-embedding
complete -F _llama_completions llama-eval-callback
complete -F _llama_completions llama-export-lora
complete -F _llama_completions llama-finetune
complete -F _llama_completions llama-fit-params
complete -F _llama_completions llama-gemma3-cli
complete -F _llama_completions llama-gen-docs
complete -F _llama_completions llama-gguf
complete -F _llama_completions llama-gguf-hash
complete -F _llama_completions llama-gguf-split
complete -F _llama_completions llama-idle
complete -F _llama_completions llama-imatrix
complete -F _llama_completions llama-llava-cli
complete -F _llama_completions llama-lookahead
complete -F _llama_completions llama-lookup
complete -F _llama_completions llama-lookup-create
complete -F _llama_completions llama-lookup-merge
complete -F _llama_completions llama-lookup-stats
complete -F _llama_completions llama-minicpmv-cli
complete -F _llama_completions llama-mtmd-cli
complete -F _llama_completions llama-parallel
complete -F _llama_completions llama-passkey
complete -F _llama_completions llama-perplexity
complete -F _llama_completions llama-q8dot
complete -F _llama_completions llama-quantize
complete -F _llama_completions llama-qwen2vl-cli
complete -F _llama_completions llama-retrieval
complete -F _llama_completions llama-save-load-state
complete -F _llama_completions llama-server
complete -F _llama_completions llama-simple
complete -F _llama_completions llama-simple-chat
complete -F _llama_completions llama-speculative
complete -F _llama_completions llama-speculative-simple
complete -F _llama_completions llama-tokenize
complete -F _llama_completions llama-tts
complete -F _llama_completions llama-vdot
