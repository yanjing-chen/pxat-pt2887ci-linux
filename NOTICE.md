# NOTICE — 出处、许可与声明

## 1. 本项目的自写代码

`src/pxat_pt2887ci.c`、`tools/*.c`、`Makefile`、`install.sh`、`uninstall.sh`、
`udev/*`、本文档与 `README.md` 均为本项目自行编写，采用 **MIT 许可**（见 `LICENSE`）。

## 2. 第三方参考

实现过程中参考了以下公开资料，特此致谢：

### dancingonmoon/pixelauth-pt2887-linux（MIT）

- 仓库：https://github.com/dancingonmoon/pixelauth-pt2887-linux
- 许可：MIT License, Copyright (c) 2026 dancingonmoon
- 参考内容：
  - `docs/protocol-pxat.md` —— 用 usbmon 在同厂 `2f0a:8020 PT2887-SS`
    上抓包得到的 PXAT 协议笔记（帧结构、命令表、状态码、索引位图、
    `a5` 记录写入、`0c` 删除语义、1:N 需主机循环等）。
  - `product-b-fprintd/payload/src/pixelauth_pt2887.c` ——
    libfprint TOD 驱动实现，为本项目的状态机组织、libfprint 内部 API 用法、
    `FpPrint` 的 `fpi-data` 槽位表示、特性标志声明等提供了参考。
  - `product-b-fprintd/payload/tools/pa_probe.c` —— 独立 libusb 探针的思路。

本项目**没有复制**该仓库的任何源文件；驱动是面向 `2f0a:1055 PT2887-CI`
重新编写的（不同的硬件 ID、可配置槽位区间、精简状态机、只读优先的探针），
但协议知识来自上述笔记，故保留此致谢。

MIT 许可要求保留版权声明，原文在仓库 `LICENSE` 中：

```
MIT License

Copyright (c) 2026 dancingonmoon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Ubuntu / libfprint / fprintd（GPL / LGPL）

本项目只**动态链接**系统自带的 `libfprint-2`、`libfprint-2-tod`、
`libgusb`、`glib-2.0`、`libusb-1.0`，没有修改、静态链接或重新分发它们。
编译期用到的内部头文件来自 Ubuntu 包 `libfprint-2-tod-dev`
（版本 `1:1.95.2+tod1-1ubuntu2`），仅用于构建，不随本交付物分发。

## 3. 厂商材料

- 输入材料 `06_Fingerprint.zip` 中的 `WBFBioUSB.dll`、`OMSFpDriver.dll`、
  `ACM32FP.bin` 等均为厂商专有二进制，归各自权利人所有。
- 本项目**不重新分发**任何厂商二进制、固件、驱动文件或商标；
  报告中引用的少量字节序列仅作为互操作分析的事实记录。
- `PXAT`、`PT2887-CI`、`Windows Hello` 等名称仅用于指代硬件/协议，
  不表示与厂商有任何关联或背书。

## 4. 免责

- 本项目不是厂商官方驱动，未经厂商认证。
- 指纹是身份凭证。驱动会读写芯片闪存，`0c` 删除操作不可逆。
  请只在自己拥有的设备上评估使用，并保留密码等备用认证方式。
- 软件按「现状」提供，不作任何明示或默示担保。
