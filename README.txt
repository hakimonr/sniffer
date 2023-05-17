#You must have Golang 18 and above in order this script to work properly.
Run the following commands in terminal as "root":

apt update && apt install golang && apt install libpcap-dev
echo "export GOPATH=$HOME/go" >> /root/.zshrc
echo "export PATH=$PATH:$GOPATH/bin" >> /root/.zshrc
source /root/.zshrc
--------------------------
go env -w GO111MODULE=auto
go mod init github.com/google
go mod tidy
-------------------------
go build -o sniffer
./sniffer
