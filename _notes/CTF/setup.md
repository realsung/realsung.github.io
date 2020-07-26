---
layout: post
type: note
title: Ubuntu setup
alias: CTF
published : false
---

Ubuntu setup

```shell
sudo apt-get update
sudo apt-get install python2.7-dev python-pip -y
pip install pwntools
sudo apt-get install libcapstone-dev -y
cd ~/
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
cd ~/
git clone https://github.com/scwuaptx/Pwngdb.git
cp ~/Pwngdb/.gdbinit ~/

# if not install pwndbg & pwngdb ? use howdays gdb
# wget http://howdays.kr/public/gdb/setupdbg.sh
# chmod 777 setupdbg.sh
# ./setupdbg.sh

sudo apt-get install git
sudo apt-get install zsh -y
sudo chsh -s /usr/bin/zsh
sudo sh -c "$(wget https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh -O -)"
git clone https://github.com/zsh-users/zsh-autosuggestions $ZSH_CUSTOM/plugins/zsh-autosuggestions
# ADD ~/.zshrc -> (zsh-autosuggestions)
source ~/.zshrc

sudo apt install ruby-full -y
gem install one_gadget

sudo pip install ropgadget -y

sudo dpkg --add-architecture i386
sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386 -y

sudo apt-get install z3
git clone https://github.com/Z3Prover/z3.git
cd z3
cd build
make
sudo make install
```

