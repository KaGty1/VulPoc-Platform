<div align="center">

<h1>VulPoc Platform</h1>

<p>
  <img src="https://img.shields.io/badge/Codex-5.4-111827?style=for-the-badge&logo=openai&logoColor=white" alt="Codex 5.4" />
  <img src="https://img.shields.io/badge/Frontend-Vue%203%20%2B%20Vite-42b883?style=for-the-badge" alt="Vue 3 + Vite" />
  <img src="https://img.shields.io/badge/Backend-Go-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go" />
</p>

<h3>面向线下 CTF 断网环境的本地在线知识库平台</h3>

<p>
  100% 代码由 <b>Codex 5.4</b> 编写 + BUG 修复 + 提交
</p>

</div>

---

## 项目简介

VulPoc Platform 的目标，是给参加线下 CTF 比赛、处于断网环境中的选手，提供一个方便查阅的本地在线知识库平台。

它用于统一整理和检索本地漏洞库、安全笔记与 PDF 指南，让选手在无法联网时，依然可以通过浏览器快速搜索、查看和阅读常用资料。

当前聚合的内容包括：

- `Vulnerability-Wiki-PoC-main`
- `Awesome-POC-master`
- `域渗透攻防`

## 适用场景

- 线下 CTF 比赛
- 红蓝对抗或内网环境演练
- 断网条件下的漏洞资料快速查阅
- 本地漏洞库与安全文档归档管理

## 页面模块

| 模块 | 说明 |
| --- | --- |
| `检索` | 按关键词、CVE、标签、来源快速定位漏洞条目 |
| `域渗透指南` | 按章节浏览 PDF 指南，并支持网页端在线阅读 |
| `统计` | 查看来源、条目数量和基础统计信息 |

## 主要能力

- 多来源漏洞库统一索引
- Markdown / README / 脚本 / JSON / YAML / HTML / 文本解析
- 正文图片自动解析与渲染
- PDF 指南独立成库并支持在线预览
- 适合断网环境使用的本地浏览器查阅体验

## 技术栈

- Frontend: `Vue 3` + `Vite` + `Element Plus`
- Backend: `Go` + `Gin`

## 快速启动

### 1. 启动后端

```bash
cd VulPoc-Platform/backend
GOCACHE=$PWD/.cache/go-build GOMODCACHE=$PWD/.cache/go-mod go run .
```

### 2. 启动前端

```bash
cd VulPoc-Platform/frontend
npm install
npm run dev
```

默认访问地址：

- 前端：`http://localhost:5173`
- 后端：`http://localhost:8080`

如果已经构建前端，也可以直接通过后端访问：

- `http://localhost:8080/`

## 默认数据源配置

后端配置文件：

- `VulPoc-Platform/backend/config/app.json`

默认包含：

- `Vulnerability Wiki PoC`
- `Awesome POC`
- `域渗透指南`

## 项目结构

```text
vulpoc_platform/
├── VulPoc-Platform/
│   ├── backend/
│   └── frontend/
├── Vulnerability-Wiki-PoC-main/
├── Awesome-POC-master/
└── 域渗透攻防/
```

## 说明

- 本项目以“断网也能查”的本地知识库体验为核心
- README 保持简洁，便于快速上手
- 后续新增漏洞库时，只需在后端数据源配置中追加目录即可
