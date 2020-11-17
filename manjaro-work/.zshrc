ZSH=~/.oh-my-zsh
ZSH_CUSTOM=$ZSH/custom
POWERLEVEL9K_DISABLE_CONFIGURATION_WIZARD=true
ZSH_THEME="powerlevel10k/powerlevel10k"
ENABLE_CORRECTION="false"
COMPLETION_WAITING_DOTS="true"
plugins=(git extract colorize encode64 docker docker-compose kubectl)
EDITOR='nano'
LANG=en_US.UTF-8
source $ZSH/oh-my-zsh.sh
source ~/.p10k.zsh
alias ls='ls --color=auto -A -F -h'
alias alpine='docker run -it --rm alpine:3.12'
alias lzd='docker run -it -v /var/run/docker.sock:/var/run/docker.sock lazyteam/lazydocker'
alias dps='docker ps --format "{{.Names}} ({{.Status}} using {{.Image}})"'
alias dstats='printf "RAM \t CPU \t IO \t Container\n"; docker stats --no-stream --format "{{.MemPerc}}\t{{.CPUPerc}}\t{{.BlockIO}}\t{{.Name}}" | sort'
alias dlog='docker logs -f'
alias ipt='watch -n 1 -d iptables -nvL'
function findproc(){
  if [ -z $1 ]; then printf "Usage: findproc filepath\n"; return 1; fi
  ls -l /proc/[0-9]*/fd/* 2> /dev/null | grep "$1" | grep -oE "/proc/[0-9]+/f" | grep -oE "[0-9]+" | sort -n | uniq
}
function dse(){
  if [ -z $1 ]; then echo "Usage: dse <querystring>"; return 1; fi
  dps | grep "$1"
  docker network ls | tail -n +2 | grep "$1"
}
function search(){
  read pipein
  if [ -z $1 ]; then echo "Usage: <command> | search <querystring>"; return 1; fi
  echo "1 is: $1"
  pipein=""
  while read line; do pipein="$pipein"'\n'"$line" done < /dev/stdin;
  echo "$pipein" | grep --color -E "$1|\$"
}
~/welcome
