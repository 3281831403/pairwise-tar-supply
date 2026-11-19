# pairwise-tar-supply

## 题面

原本能跑的制品校验在新数据形态下失效：只校验 dist-info 里的哈希，.pth、sitecustomize.py 和 entry_points.txt 的注入点都不查；文件名不归一，带 ./ 前缀、夹 ..、大小写变体都被当成新文件；清单只认有记录的条目，未列文件和重复条目直接放过；权限位不看，可执行位与 setuid 原样保留；依赖混淆完全没检测，reqeusts、urllib3-py 这类近似名照样通过。artifact_guard/manifest.py 是核心，tests/test_manifest.py 15个红。要修的是：注入点文件名单独拒绝；文件名 NFC 归一加越界拒绝；清单必须覆盖全部文件且去重；权限位与算法白名单；对 registry 做编辑距离近似名检测。

## 运行方式

在仓库根目录执行：

```console
python -m pytest tests -q
```

初始状态应恰好为 `15 failed`，且没有 collection error，也没有 import error 或 syntax error。修复 `artifact_guard/manifest.py` 中的契约实现后，目标为 `15 passed`。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 其他 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 约束

`tests/test_manifest.py` 是验收标准，不可修改；测试只依赖标准库与 pytest，不联网、不随机。
