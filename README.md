# native-core-backtrace

Linux 崩溃栈还原后端（无前端）。上传 core 与部署映像，按帧指针 ABI
还原每个线程的调用链并符号化。Go 1.27.1 + Chi 5.2.1。

## 支持的子集

- 仅 x86-64 小端 ELF64；core 必须是 ET_CORE，映像必须是 ET_EXEC 或 ET_DYN。
- 从 PT_NOTE 读取 NT_PRSTATUS（TID、当前信号、RIP/RSP/RBP）与 NT_FILE；
  未知 note 跳过；损坏头部、截断、非法偏移、重复 TID 整份拒绝。
- 进程内存只来自 PT_LOAD 的实际存储范围（p_filesz），未转储区不补零。
- 回溯仅从 RIP 出发按帧指针 ABI（[rbp]=saved rbp, [rbp+8]=返回地址）；
  不扫描栈猜地址，不调用 gdb。零帧指针正常结束；缺内存、未对齐、
  链不递增或成环时保留已有帧并给出 stop_reason；每线程最多 64 帧。
- 加载偏移由 NT_FILE 映射范围/页大小/页偏移与映像 PT_LOAD 推导，
  支持 PIE 与共享库（不取最低映射起点当偏移）。
- 符号来自 .symtab 与 .dynsym 中重定位后的非零大小 STT_FUNC 范围；
  缺映像或符号时标 unknown，地址一律十六进制字符串。
- 上传文件的路径只用于与 NT_FILE 匹配，不读宿主文件、不执行上传文件。
- 请求上限 64 MiB；各线程独立回溯。

## 构建与运行

```sh
go build -o server .
./server          # 监听 :8080
go test ./...
```

## API

`POST /backtrace`，multipart/form-data：

- `core`：core 文件（ET_CORE）。
- `images`：可多个，每个映像的 filename 必须是其原始部署路径
  （仅用于匹配，不读宿主文件）。

`GET /healthz` 健康检查。

### curl 示例

```sh
curl -F "core=@/tmp/coredemo/core" \
     -F "images=@/tmp/coredemo/crash;filename=/tmp/coredemo/crash" \
     -F "images=@/usr/lib/x86_64-linux-gnu/libc.so.6;filename=/usr/lib/x86_64-linux-gnu/libc.so.6" \
     http://localhost:8080/backtrace
```

响应：每线程 tid/signal/rip/rsp/rbp、stop_reason 及有序帧
（address、image、function、offset，均为十六进制字符串或 unknown）。

## 生成测试 core（gdb 仅用于造样例）

```sh
gcc -g -O0 -fno-omit-frame-pointer -pthread -o crash crash.c
gdb -batch -ex run -ex "gcore core" ./crash
```

## 代码结构

- `elf.go`：ELF64 头部/程序头/节头解析与校验。
- `note.go`：PT_NOTE 遍历，NT_PRSTATUS / NT_FILE 解码。
- `memory.go`：基于 PT_LOAD 存储字节的地址读取。
- `unwind.go`：帧指针回溯（上限 64 帧，带停止原因）。
- `symbol.go`：加载偏移推导与 STT_FUNC 符号定位。
- `main.go`：Chi HTTP 层与整体流水线。
