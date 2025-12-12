.PHONY: all build build-all build-linux build-darwin bpf generate clean deps run

VERSION := 0.1.0
LDFLAGS := -ldflags "-s -w -X main.Version=$(VERSION)"

all: build

# 构建当前平台
build:
	go build $(LDFLAGS) -o dist/sninsight ./cmd/sninsight

# 一次性构建 Linux x86_64 + macOS ARM64
build-all: build-linux build-darwin
	@echo "构建完成:"
	@ls -lh dist/sninsight-*

# 构建 Linux x86_64 (纯 Go，使用 eBPF)
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/sninsight-linux-amd64 ./cmd/sninsight

# 构建 Linux ARM64
build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/sninsight-linux-arm64 ./cmd/sninsight

# 构建 macOS ARM64 (需要 CGO 支持 libpcap，必须在 macOS 上编译)
build-darwin:
ifeq ($(shell uname -s),Darwin)
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/sninsight-darwin-arm64 ./cmd/sninsight
else
	@echo "警告: macOS 版本需要在 macOS 上编译 (需要 libpcap)"
	@echo "跳过 darwin 构建"
endif

# 构建 macOS Intel (需要在 macOS 上编译)
build-darwin-amd64:
ifeq ($(shell uname -s),Darwin)
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/sninsight-darwin-amd64 ./cmd/sninsight
else
	@echo "警告: macOS 版本需要在 macOS 上编译 (需要 libpcap)"
	@echo "跳过 darwin-amd64 构建"
endif

# 编译 eBPF 程序 (需要 clang 和 vmlinux.h)
bpf:
	clang -O2 -g -target bpf \
		-D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/') \
		-I/usr/include \
		-I./bpf/headers \
		-c bpf/traffic.c \
		-o bpf/traffic.o

# 生成 Go eBPF 绑定 (需要 bpf2go)
generate:
	go generate ./internal/capture/...

# 清理
clean:
	rm -rf dist/
	rm -f bpf/*.o
	rm -f internal/capture/traffic_*.go
	rm -f sninsight

# 运行 (需要 sudo)
run: build
	sudo ./dist/sninsight

# 安装依赖
deps:
	go mod download
	go mod tidy

# 格式化代码
fmt:
	go fmt ./...

# 检查代码
vet:
	go vet ./...

# 安装到系统
install: build
	sudo cp dist/sninsight /usr/local/bin/
	sudo mkdir -p /etc/sninsight
	sudo cp configs/config.example.yaml /etc/sninsight/config.yaml.example

# 帮助
help:
	@echo "Sninsight Makefile"
	@echo ""
	@echo "使用方法:"
	@echo "  make build          - 构建当前平台"
	@echo "  make build-all      - 一次性构建 Linux x86_64 + macOS ARM64"
	@echo "  make build-linux    - 构建 Linux amd64"
	@echo "  make build-darwin   - 构建 macOS arm64"
	@echo "  make bpf            - 编译 eBPF 程序"
	@echo "  make generate       - 生成 Go eBPF 绑定"
	@echo "  make clean          - 清理构建产物"
	@echo "  make run            - 构建并运行 (需要 sudo)"
	@echo "  make deps           - 安装依赖"
	@echo "  make install        - 安装到系统"
