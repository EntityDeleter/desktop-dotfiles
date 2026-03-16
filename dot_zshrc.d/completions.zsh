eval "$(zoxide init zsh)"
eval "$(thefuck --alias oops)"
eval "$(mcat --generate zsh)"
eval "$(llama-cli --completion-bash | grep -vi 'ggml_cuda_init: found 1 CUDA devices (Total VRAM: 8098 MiB):' | grep -vi 'Device 0: NVIDIA GeForce GTX 1080, compute capability 6.1, VMM: yes, VRAM: 8098 MiB (7455 MiB free)')"
