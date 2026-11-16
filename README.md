# pxat-pt2887ci-linux

为 **PXAT / PixelAuth PT2887-CI 指纹模块**（USB `2f0a:1055`）编写的
**libfprint TOD 树外驱动**，通过逆向厂商 Windows 驱动包还原其 PXAT 私有协议后实现。
在 Ubuntu（GNOME）上已实机验证：录入、验证、删除、清空存储、挂起恢复、多手指识别均可用。

> 这不是厂商官方驱动。指纹属于身份凭证，请只在你自己拥有的设备上评估使用，
> **务必保留密码登录方式**。

## 支持的硬件

| | |
|---|---|
| USB ID | `2f0a:1055`（`lsusb` 显示 `PXAT PT2887-CI Module`） |
| 协议 | 私有 PXAT 帧，CRC-16/KERMIT，bulk 端点 `0x02 OUT` / `0x81 IN`，64 字节包 |
| 架构 | **match-on-chip**：指纹模板存在芯片内，主机只保存「手指 ↔ 槽位」映射 |

同厂商还有 `2f0a:8020`（PT2887-SS）等型号，协议相近但 PID 不同，本驱动**只匹配
`1055`**，不会误接管其他设备。

## 工作原理

Ubuntu 的 `libfprint` 有 `+tod1` 分支构建，支持从
`/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/` 动态加载第三方驱动（`.so`）。
本项目产出的就是这个 `.so`：

```
GNOME / PAM / fprintd  →  libfprint TOD loader  →  libpxat_pt2887ci.so
                                                        │
                                          USB bulk 0x02 / 0x81
                                                        │
                                          2f0a:1055 PT2887-CI
```

接入后 GNOME 设置、锁屏、登录、`sudo`（需勾选 PAM）整条链路都能用。
**不需要改内核、不需要 DKMS、不需要重装 fprintd。**

## 快速开始

### 1. 准备

```bash
sudo apt install libfprint-2-tod1 fprintd libpam-fprintd
git clone https://github.com/yanjing-chen/pxat-pt2887ci-linux.git
cd pxat-pt2887ci-linux
```

仓库 `dist/` 里带了已编译好的 4 个二进制，一般不需要自己编译。

### 2. 安装前自检（只读，不碰指纹数据）

```bash
./dist/pxat_probe frames                       # 帧与 CRC 和厂商 DLL 逐字节比对
./dist/check_driver dist/libpxat_pt2887ci.so   # 驱动类注册检查（无需硬件）
FP_TOD_DRIVERS_DIR="$PWD/dist" ./dist/enumerate_test   # 真实枚举：应看到 1 个设备
sudo ./dist/pxat_probe selftest                # 实机协议确认：a1 / 1f 应返回合法帧
```

- `frames` / `check_driver` / `enumerate_test` 全部无需 root。
- `selftest` 期望看到 `a1` 和 `1f` 返回合法 PXAT 帧、CRC 校验通过、索引表 33 字节。
  如果返回 9 字节 NAK（`50584154 c0 0002 9fff`），说明这块芯片的固件行为和预期不符，
  先别装驱动。

其它只读探针命令：

```bash
sudo ./dist/pxat_probe info          # 设备信息 + 序列号
sudo ./dist/pxat_probe index         # 索引表 / 已占用槽位
sudo ./dist/pxat_probe record 10     # 读槽位 10 的 64 字节记录
sudo ./dist/pxat_probe poll 5        # 轮询芯片当前状态
sudo ./dist/pxat_probe verify 10     # 定向验证槽位 10（把手放上去）
```

> 探针默认**只读**。任何可能写芯片的命令（`raw` / `delete` / `enrollwatch`）
> 都必须显式加 `--unsafe`，否则会被拒绝。

### 3. 安装

```bash
sudo ./install.sh
```

脚本会：检查 TOD 版 libfprint → 把 `.so` 装进 `tod-1` 目录（同名旧文件先备份为
`*.bak.<时间戳>`）→ 装 udev 规则并重载 → 重启 fprintd → 打印验证命令。

### 4. 录入与使用

```bash
fprintd-list "$USER"          # 应能看到设备，而不是 "No devices available"
fprintd-enroll "$USER"        # 按提示反复「按下 → 抬起」，每次稍微挪动位置
fprintd-verify "$USER"        # 验证
```

图形界面：`设置 → 系统 → 用户 → 指纹登录`。
启用 sudo / 登录指纹：`sudo pam-auth-update`（勾选 Fingerprint authentication）。

> 录入约需 14 次有效按压；`0xe6`（图像重复/不清晰）不是失败，换个位置继续按即可。

## 已知限制（实机验证结论）

- **多手指识别需要抬手重按**。芯片一次只比对一个槽位，1:N 由驱动循环候选完成；
  而且实测（包括对 Windows 官方驱动的抓包笔记交叉验证）确认：**换槽位时芯片要求
  一次新的手指落下**，手指保持按住不放只会一直返回 `f0`。这是芯片硬限制，不是驱动缺陷。
  实用建议：把最常用的手指排在 fprintd 指纹列表第一位（一次就中），或只录一枚。
- **`AlreadyInUse`**：用指纹登录后，GDM / GNOME 设置可能残留设备占用，导致
  「设置 → 删除指纹」报错。这不是故障，重启 fprintd 即可：
  `sudo systemctl restart fprintd`（然后重开设置窗口）。删除推荐用命令行
  `fprintd-delete "$USER"`。
- 槽位区间默认 `10..19`，可用 `PXAT_SLOT_MIN` / `PXAT_SLOT_MAX` 环境变量调整。

## 排障

| 现象 | 可能原因 / 处理 |
|---|---|
| `No devices available` | `.so` 没放到 `tod-1` 目录，或 fprintd 没重启。看 `journalctl -u fprintd` |
| `Device was already claimed` (AlreadyInUse) | 见上文「已知限制」；`sudo systemctl restart fprintd` |
| 探针 9 字节 NAK | 帧长度/CRC 不对；`./dist/pxat_probe frames` 应与 DLL 完全一致 |
| 探针 `Permission denied` | 用 `sudo`，或重新插拔让 udev `uaccess` 生效 |
| `a1`/`1f` 正常但录入后验不过 | 录入完成后的 `a5` 记录没写成功；看 `LIBFPRINT_DEBUG=1` 日志 |
| 一直 `0xf2`（不匹配） | `33` 后面跟的是**目标槽位**；确认 print 里的槽位号正确 |
| 换槽位后一直 `0xf0` | 芯片在等一次新的手指落下，**抬手重按**即可 |
| 指示灯常亮 | 上一次会话没发 `f2 → f4`；`sudo ./dist/pxat_probe abort` |
| 槽位不对 / 槽位满 | 设置 `PXAT_SLOT_MIN` / `PXAT_SLOT_MAX`（默认 10..19）到 fprintd 环境 |
| 想抓完整 USB 流量 | `sudo modprobe usbmon && sudo cat /sys/kernel/debug/usb/usbmon/1u > cap.log` |

调试日志：

```bash
sudo systemctl stop fprintd 2>/dev/null || true
sudo LIBFPRINT_DEBUG=1 FP_TOD_KEEP_MODULES_OPEN=1 /usr/libexec/fprintd
```

## 协议要点

- **帧**：`"PXAT" + 0xC0 | BE16(10+plen) | EF 01 FF FF 00 00 00 | plen | payload | BE16 CRC-16/KERMIT(payload)`
  `inner_len` 必须把末尾 2 字节 CRC 算进去，否则设备只回 NAK。
- **命令**：`a1` 设备信息 · `1f` 索引表 · `a6` 读记录 · `a5` 写记录 ·
  `f2` 准备 · `33 <slot>` 定向验证 · `31 <slot> 0f 00 00` 录入 ·
  `0c <slot> 00 01` 删除 · `f1` 轮询 · `f4` 中止（**必须前面有 `f2`**）。
- **录入完成后必须发 `a5`** 写 32 字节主机 UUID，否则芯片记录区留 `0x33` 占位符，
  这枚指纹永远验不过。
- **每次 close 都发 `f2 → f4`**：否则芯片停在「武装」状态、指示灯常亮，USB 复位也清不掉。
- **`f1` 是锁存结果寄存器**：手指离开后仍返回最后一次结果，判读轮询输出时要注意，
  非法命令不会清除锁存。
- 芯片不做 1:N，也不存在开启连续比对/1:N 的隐藏命令（`a2` 为纯初始化）——
  这一点已通过 Windows 驱动二进制反汇编、厂商抓包笔记和实机实验三方确认。

完整逆向过程见 [`docs/逆向分析报告.md`](docs/逆向分析报告.md)。

## 目录结构

| 路径 | 说明 |
|---|---|
| `src/pxat_pt2887ci.c` | TOD 驱动源码（probe/open/verify/identify/enroll/list/delete/clear/cancel/close） |
| `tools/pxat_probe.c` | 独立 libusb 协议探针，**不依赖 fprintd**，用于实机验证和排障 |
| `tools/check_driver.c` | 校验 `.so` 能否被 TOD 加载器注册（无需硬件） |
| `tools/enumerate_test.c` | 校验 libfprint 能否把驱动匹配到真实 USB 设备（无需 root） |
| `dist/` | 已编译好的 4 个二进制，**开箱即用** |
| `udev/60-pxat-pt2887ci.rules` | 让当前登录用户无需 sudo 就能跑探针 |
| `install.sh` / `uninstall.sh` | 安装 / 卸载 |
| `docs/逆向分析报告.md` | Windows 驱动包逆向全过程、协议推导、命令表、风险 |

## 卸载

```bash
sudo ./uninstall.sh
```

卸载**不会**删除芯片里的指纹，也不会动 `/var/lib/fprint`；重装驱动后原有记录继续可用。
重装系统也不丢指纹（match-on-chip），装好驱动后重新绑定即可。

## 重新编译

```bash
sudo apt install libfprint-2-tod-dev libusb-1.0-0-dev libglib2.0-dev \
                 libgusb-dev libjson-glib-dev libgudev-1.0-dev pkg-config
make clean && make check
```

没有 root / 离线时，可以把开发版 `.deb` 解包成本地 sysroot 后
`make check SYSROOT=/path/to/sysroot`。

## 风险与限制

1. **写入芯片闪存**：`31`（录入）/ `a5`（写记录）/ `0c`（删除）都会改芯片数据。
   `0c` 只清索引位且**不可逆**，主机侧无法写回；删了就要重新录入。
2. **槽位区间是推断值**：10..19 来自同厂 PT2887-SS 的实测。若 `index` 显示已占用
   槽位在这个区间之外，用 `PXAT_SLOT_MIN/MAX` 调整。
3. **Windows Hello 配对数据不通用**：Linux 侧重新录入/绑定即可，不需要迁移 Windows 模板。
4. 指纹只作便利认证，请保留密码登录；改动 PAM 配置前留一个已开着的 root 会话。

## 许可与出处

本项目自写源码为 **MIT**，见 [`LICENSE`](LICENSE) / [`NOTICE.md`](NOTICE.md)。
协议逆向参考了社区对同厂 PT2887-SS 模块的实测笔记与 MIT 驱动实现
（[dancingonmoon/pixelauth-pt2887-linux](https://github.com/dancingonmoon/pixelauth-pt2887-linux)），
出处与致谢见 `NOTICE.md`。厂商二进制与商标归其所有者，本项目不重新分发任何厂商文件。
