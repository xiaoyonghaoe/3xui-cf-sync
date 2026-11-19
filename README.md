# 3xui-cf-sync

运行在 `3x-ui` 主控服务器上的轻量增量同步器（纯 Python 3 标准库，零外部依赖）。负责把 `3x-ui` 的用户流量、到期时间与多格式订阅内容在**本地校验差异**后增量推送至 Cloudflare KV，配合 [3xui-cf-pages](../3xui-cf-pages) 对外隐藏真实面板与端口。

## 工作流程

1. 将 `3x-ui` 的订阅监听改为仅本机回环（`subListen = 127.0.0.1`），彻底关闭对外订阅端口；
2. 定时任务调用本脚本读取 `/panel/api/inbounds/list` 及本机 `http://127.0.0.1:<subPort>/sub/<subId>`；
3. 本地计算每个用户的规范化 SHA-256 指纹并与 `.sync_state.json` 比对：
   - **配置/节点/启停/到期/可配域名无变化**且流量变化未超阈值 → **跳过，不消耗 CF KV 写配额**；
   - **有变更或新增** → 通过 Cloudflare KV Bulk API 批量增量写入；
   - **已删除用户** → 自动从 KV 清理。

## 快速使用

```bash
cp .env.example .env
# 编辑 .env，填入 XUI 地址/凭据、CF KV 信息以及可配置的 CF_PUBLIC_DOMAIN

# 1. 本地预检（只校验不写入 CF）
python3 sync_to_cf.py --dry-run --print-urls

# 2. 正式执行一次同步
python3 sync_to_cf.py --print-urls

# 3. 安装 systemd 5 分钟定时同步（推荐放在 /opt/3xui-cf-sync）
sudo cp deploy/3xui-cf-sync.service deploy/3xui-cf-sync.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now 3xui-cf-sync.timer
```

## 运行单元测试

```bash
python3 -m unittest discover -s tests -v
```
