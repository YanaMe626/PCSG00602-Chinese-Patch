# PCSG00602 简体中文汉化工程

适用于 PS Vita 日版《忍び、恋うつつ ― 雪月花恋絵巻 ―》`PCSG00602`。仓库包含剧情译文、系统译文、姓名分支补译、字库码表及汉化工具。

| 路径 | 用途 |
| --- | --- |
| `05_AI翻译/` | 剧情正文、说话人、选项和系统文本，以及依女主姓名切换的对白补译 |
| `06_中文字体/` | 思源黑体简体中文 Regular、OFL 许可和生成过的汉化码表 |
| `Python工具/` | CPK 解包和重打包、文本导入、字库生成与校验、可选贴图处理及 Ghidra 标注脚本 |
| `03_文件结构分析/` | 游戏版本、资源结构、原版 ELF 校验和当前补丁构建记录 |

## 从本地原版资源构建

1. 使用 Python 3.12 安装 `requirements.txt`。在 `02_解包资源/PCSG00602_decrypted/` 放入自己从游戏提取的 `PCSG00602.elf`，以及 `data/STORY.cpk` 和 `data/SYSTEM.cpk`。ELF 需匹配项目记录的版本。 [ELF 校验记录](03_文件结构分析/ghidra/decryption_report.json)
2. 在仓库根目录运行以下命令。文本提取会生成构建所用的日文表，导入脚本会校验源位置和字节，并逐条回读打包结果。

   ```powershell
   python -m pip install -r requirements.txt
   python -X utf8 "Python工具/cpk.py" "02_解包资源/PCSG00602_decrypted/data/SYSTEM.cpk" --match "*.ffu" --extract "02_解包资源/SYSTEM"
   python -X utf8 "Python工具/extract_text.py"
   python -X utf8 "Python工具/import_translations.py"
   ```

3. 构建输出写入 `07_修改后的资源/`。用于已配置 rePatch 的 PS Vita 时，退出游戏后，将生成的 `STORY.cpk` 和 `SYSTEM.cpk` 一起复制到 `ux0:rePatch/PCSG00602/data/`。 [rePatch 项目文档](https://github.com/dots-tb/rePatch-reDux0)

## 编辑译文

编辑 UTF-8 TSV 的 `text` 列，保留其他列和行序。`#Name[...]`、`#Color[...]` 等是游戏控制标记。检索或对照原文时，可查看 `extract_text.py` 在本地生成的 `04_日文原文/`。补译表用原字符串的 SHA-256 校验其对应位置。

当前构建记录覆盖 115,580 条剧情记录和 360 条系统文本，包含按姓名切换的两套分支。章节标题、用语集和部分界面贴图仍有日文。 [构建记录](03_文件结构分析/当前补丁校验.json)

## 可选工具

- 从自有原版文件开始时，`decrypt_game.py` 所需的 `psvpfsparser.exe` 和 `self2elf.py` 分别放在 `tools/pfsparser/` 和 `tools/psvdec/`。PFS 工具使用本机提供的 `NINKOI_PFS_CONTRACT_KEY`。
- `patch_textures.py` 使用本地 `11_游戏贴图/` 的素材和原版 `GAME.cpk`、`SYSTEM.cpk`。若只想预览对应的贴图区域，可使用 `--textures-only`。
- Ghidra 可通过 VitaLoaderRedux 导入自己的 ELF 并执行 `LabelNinkoi.java`，复现字库相关函数标注。 [VitaLoaderRedux 项目](https://github.com/CreepNT/VitaLoaderRedux)
