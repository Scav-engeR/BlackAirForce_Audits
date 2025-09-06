#!/bin/bash -ex

################################################################################
PACKAGES_TO_INSTALL="python=3.10.9 pytorch[version=2,build=py3.10_cuda11.7*] torchvision torchaudio pytorch-cuda=11.7 cuda-toolkit ninja git"
CHANNEL="-c pytorch -c nvidia/label/cuda-11.7.0 -c nvidia -c conda-forge"

#REPO_URL="https://github.com/oobabooga/text-generation-webui.git" # -b …
#GPTQ_URL="https://github.com/qwopqwop200/GPTQ-for-LLaMa.git -b cuda"
#GPTQ_URL="https://github.com/oobabooga/GPTQ-for-LLaMa.git" # -b …

REPO_URL="https://github.com/StefanDanielSchwarz/text-generation-webui.git" # -b …
GPTQ_URL="https://github.com/StefanDanielSchwarz/GPTQ-for-LLaMa.git" # -b …
################################################################################

sudo apt update && sudo apt install bzip2 g++ make wslu -y

[[ -e /usr/bin/xdg-open ]] || sudo ln -s wslview /usr/bin/xdg-open # auto-launch

cd
curl -Ls https://micro.mamba.pm/api/micromamba/linux-64/latest | tar -xvj bin/micromamba
PATH="$HOME/bin:$PATH"
micromamba create -y -n textgen ${CHANNEL:?} ${PACKAGES_TO_INSTALL:?}
eval "$(micromamba shell hook --shell=${SHELL##*/})"
micromamba shell init --shell=${SHELL##*/} --prefix=~/micromamba
micromamba activate textgen
git clone ${REPO_URL:?}
#pip install https://github.com/jllllll/bitsandbytes-windows-webui/raw/main/bitsandbytes-0.37.2-py3-none-any.whl # ❌
cd text-generation-webui
pip install -r requirements.txt # --upgrade
pip install -r extensions/api/requirements.txt # --upgrade
pip install -r extensions/elevenlabs_tts/requirements.txt # --upgrade
pip install -r extensions/google_translate/requirements.txt # --upgrade
pip install -r extensions/silero_tts/requirements.txt # --upgrade
pip install -r extensions/whisper_stt/requirements.txt # --upgrade
mkdir repositories
cd repositories
git clone ${GPTQ_URL:?}
cd GPTQ-for-LLaMa
pip install -r requirements.txt # ❓
cd ../..

echo -e "\n✅ Successfully installed United Corporations of text-generation-webui"
