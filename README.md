# native-core-backtrace

Linux 崩溃栈还原后端（Go 1.27.1 + Chi 5.2.1，无前端）。上传 core 文件与按
原路径标识的程序/共享库映像，服务从 core 与部署映像中定位每线程调用链。
不读取宿主文件、不执行上传文件、不调用 gdb 获取分析结果。

## 支持子集

- 仅 x86-64 小端 ELF64；core 必须为 `ET_CORE`，映像必须为 `ET_EXEC` 或 `ET_DYN`。
- 从 `PT_NOTE` 读取 `NT_PRSTATUS`（逐线程 TID、当前信号、RIP/RSP/RBP）与
  `NT_FILE`（映射范围、页大小、页偏移）；未知 note 跳过。
- 从 `PT_LOAD` 建立地址读取，只使用实际存储（filesz）范围，未转储区不补零。
- 损坏头部、截断、非法偏移、重复 TID 一律整份拒绝（400）。
- 回溯：从 RIP 起按帧指针 ABI 读取保存的 RBP 与返回地址，得到有序帧；
  零帧指针正常结束；缺内存、未对齐、链不递增、成环时保留已有帧并给出
  `stop_reason`；每线程最多 64 帧；不扫描栈猜地址。
- 符号：用 `NT_FILE` 映射 + 页大小 + 页偏移结合映像 `PT_LOAD` 推导加载偏移
  （支持 PIE/共享库，不把最低映射起点当偏移）；以重定位后的非零大小
  `STT_FUNC` 范围（`.symtab` 优先，其次 `.dynsym`）定位函数；缺映像或符号
  时标 `unknown`；地址为十六进制字符串。
- 请求体上限 64 MiB；线程之间相互独立。

## 构建与启动

```sh
go build ./...
go test ./...
go build -o bin/coredumpd ./cmd/coredumpd
ADDR=127.0.0.1:18099 ./bin/coredumpd
```

## API

`POST /api/backtrace`（multipart/form-data）：

- `core`：core 文件（单个文件部分）。
- `image`：程序或共享库映像（可多个）。原路径通过该部分的
  `X-Image-Path` 头或 filename 提供，仅用于与 `NT_FILE` 路径匹配
  （精确路径优先，basename 回退）。

响应：

```json
{
  "threads": [
    {
      "tid": 79556, "signal": 11,
      "rip": "0x5555555551b9", "rsp": "0x7ffff73fde20", "rbp": "0x7ffff73fde20",
      "frames": [
        {"address": "0x5555555551b9", "image": "/tmp/case199/mtcrash",
         "function": "boom", "offset": "0x10"}
      ],
      "stop_reason": "frame pointer chain not increasing"
    }
  ]
}
```

## 生成样例 core 并演示（gdb 仅用于生成样例）

```sh
cat > crash.c <<'C'
#include <string.h>
__attribute__((noinline)) void level3(int *p) { *p = 42; }
__attribute__((noinline)) void level2(int *p) { level3(p); }
__attribute__((noinline)) void level1(int *p) { level2(p); }
int main(void) { int *p = NULL; level1(p); return 0; }
C
gcc -g -O0 -fno-omit-frame-pointer -o crash crash.c
gdb -batch -ex run -ex 'generate-core-file core.crash' ./crash

curl -s -F 'core=@core.crash' \
     -F 'image=@./crash;filename=/tmp/case199/crash' \
     -F 'image=@/lib/x86_64-linux-gnu/libc.so.6;filename=/usr/lib/x86_64-linux-gnu/libc.so.6' \
     http://127.0.0.1:18099/api/backtrace | python3 -m json.tool
```

注意：curl 会把 `filename=` 规范化为 basename，如需传递完整原路径，
请用支持自定义部分头的客户端设置 `X-Image-Path`，或服务端按 basename
回退匹配。

## 代码结构

- `internal/corefile`：ELF64 core 解析、note 解析、PT_LOAD 地址读取。
- `internal/unwind`：帧指针回溯（上限 64 帧，带停止原因）。
- `internal/symbol`：映像解析、加载偏移推导、符号定位。
- `internal/server`：Chi HTTP 层（64 MiB 限制、multipart 组装）。
- `cmd/coredumpd`：服务入口（`ADDR` 环境变量，默认 `:8080`）。
