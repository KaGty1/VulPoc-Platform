<template>
  <section class="detail-layout">
    <div class="detail-actions">
      <el-button plain @click="router.push('/')">返回检索页</el-button>
      <el-button plain @click="router.push('/stats')">查看统计</el-button>
    </div>

    <div v-if="loading" class="panel state-card">
      <h3>正在加载详情</h3>
      <p>读取原始文档、PoC 代码与附件信息。</p>
    </div>

    <div v-else-if="!entry" class="panel state-card state-card--error">
      <h3>未找到对应条目</h3>
      <p>该记录可能不存在，或者索引在重新导入后发生了变化。</p>
    </div>

    <template v-else>
      <section v-if="!isPdfEntry" class="panel detail-hero">
        <div class="detail-hero__main">
          <p class="detail-hero__eyebrow">{{ entry.source_name }} / {{ entry.parser_name }}</p>
          <h1>{{ entry.title }}</h1>
          <p class="detail-hero__summary">{{ entry.summary || '暂无摘要' }}</p>
          <div class="detail-hero__chips">
            <span v-if="entry.cve" class="result-badge">{{ entry.cve }}</span>
            <span v-if="entry.file_type" class="result-badge result-badge--soft">{{ entry.file_type }}</span>
            <span v-for="tag in entry.tags" :key="tag" class="tag-chip">{{ tag }}</span>
          </div>
        </div>
        <div class="detail-hero__path">{{ entry.source_path }}</div>
      </section>

      <section v-if="!isPdfEntry" class="detail-grid">
        <article class="panel detail-panel">
          <h2>基础信息</h2>
          <dl class="meta-grid">
            <div>
              <dt>CVE</dt>
              <dd>{{ entry.cve || '未提取' }}</dd>
            </div>
            <div>
              <dt>别名</dt>
              <dd>{{ entry.aliases?.join(' / ') || '无' }}</dd>
            </div>
            <div>
              <dt>影响产品</dt>
              <dd>{{ entry.products?.join(' / ') || '未提取' }}</dd>
            </div>
            <div>
              <dt>影响版本</dt>
              <dd>{{ entry.versions?.join(' / ') || '未提取' }}</dd>
            </div>
            <div>
              <dt>来源类型</dt>
              <dd>{{ entry.source_type || '未知' }}</dd>
            </div>
            <div>
              <dt>作者</dt>
              <dd>{{ entry.author || '未提取' }}</dd>
            </div>
            <div>
              <dt>发布时间</dt>
              <dd>{{ entry.published_at || '未提取' }}</dd>
            </div>
            <div>
              <dt>更新时间</dt>
              <dd>{{ entry.updated_at || '未提取' }}</dd>
            </div>
          </dl>
        </article>

        <article class="panel detail-panel">
          <h2>来源信息</h2>
          <dl class="meta-grid">
            <div>
              <dt>来源仓库</dt>
              <dd>{{ entry.source_name }}</dd>
            </div>
            <div>
              <dt>原始路径</dt>
              <dd>{{ entry.source_path }}</dd>
            </div>
            <div>
              <dt>解析器</dt>
              <dd>{{ entry.parser_name }}</dd>
            </div>
            <div>
              <dt>导入时间</dt>
              <dd>{{ entry.ingested_at }}</dd>
            </div>
          </dl>
        </article>
      </section>

      <section class="detail-sections">
        <article v-if="!isPdfEntry" class="panel detail-panel">
          <h2>漏洞描述</h2>
          <p class="detail-panel__lead">{{ entry.description || '暂无描述' }}</p>
        </article>

        <article class="panel detail-panel">
          <div class="detail-panel__header">
            <h2>正文内容</h2>
            <span>{{ entry.file_type }}</span>
          </div>
          <div v-if="isPdfEntry" class="pdf-preview">
            <iframe v-if="entryPdfUrl" :src="entryPdfUrl" :title="entry.title"></iframe>
          </div>
          <div v-else-if="isMarkdownEntry" class="detail-markdown" v-html="bodyHtml"></div>
          <pre v-else class="code-block"><code>{{ entry.content || '暂无正文内容' }}</code></pre>
        </article>

        <article v-if="!isPdfEntry && entry.poc" class="panel detail-panel">
          <h2>PoC</h2>
          <pre class="code-block"><code>{{ entry.poc }}</code></pre>
        </article>

        <article v-if="!isPdfEntry && entry.exp && entry.exp !== entry.poc" class="panel detail-panel">
          <h2>Exp / 利用脚本</h2>
          <pre class="code-block"><code>{{ entry.exp }}</code></pre>
        </article>

        <article v-if="!isPdfEntry && entry.references?.length" class="panel detail-panel">
          <h2>参考链接</h2>
          <div class="reference-list">
            <a v-for="item in entry.references" :key="item" :href="item" target="_blank" rel="noreferrer">{{ item }}</a>
          </div>
        </article>

        <article v-if="!isPdfEntry && entry.files?.length" class="panel detail-panel">
          <div class="detail-panel__header">
            <h2>相关文件</h2>
            <span>{{ entry.files.length }} 个附件</span>
          </div>

          <div class="asset-layout">
            <div class="asset-list">
              <button
                v-for="file in entry.files"
                :key="file.relative_path"
                type="button"
                class="asset-item"
                :class="{ 'asset-item--active': activePath === file.relative_path }"
                @click="activePath = file.relative_path"
              >
                <strong>{{ file.name }}</strong>
                <span>{{ file.file_type }} / {{ formatSize(file.size) }}</span>
              </button>
            </div>

            <div v-if="activeFile" class="asset-preview">
              <div class="asset-preview__header">
                <div>
                  <h3>{{ activeFile.name }}</h3>
                  <p>{{ activeFile.relative_path }}</p>
                </div>
                <a :href="fileUrl(activeFile)" target="_blank" rel="noreferrer">打开原始文件</a>
              </div>

              <div
                v-if="isMarkdownFile(activeFile)"
                class="detail-markdown"
                v-html="renderMarkdown(activeFile.inline_content, activeFile.relative_path)"
              ></div>
              <pre v-else-if="isTextFile(activeFile)" class="code-block"><code>{{ activeFile.inline_content || '文件体积较大，当前未内联展示。' }}</code></pre>
              <div v-else-if="isImageFile(activeFile)" class="image-preview">
                <img :src="fileUrl(activeFile)" :alt="activeFile.name" />
              </div>
              <div v-else-if="isPdfFile(activeFile)" class="pdf-preview pdf-preview--compact">
                <iframe :src="fileUrl(activeFile)" :title="activeFile.name"></iframe>
              </div>
              <div v-else class="download-card">
                <p>该文件类型更适合直接下载或在新窗口打开。</p>
                <a class="download-card__link" :href="fileUrl(activeFile)" target="_blank" rel="noreferrer">打开附件</a>
              </div>
            </div>
          </div>
        </article>
      </section>
    </template>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import MarkdownIt from 'markdown-it'
import { fetchEntry } from '../api/knowledge'

const route = useRoute()
const router = useRouter()
const loading = ref(true)
const entry = ref(null)
const activePath = ref('')

const isMarkdownEntry = computed(() => ['markdown', 'readme'].includes(entry.value?.file_type))
const isPdfEntry = computed(() => entry.value?.file_type === 'pdf')
const bodyHtml = computed(() => renderMarkdown(entry.value?.content || entry.value?.description || '暂无可用内容', entry.value?.source_path))
const primaryFile = computed(() => {
  const files = entry.value?.files || []
  return files.find((file) => file.file_type === 'pdf')
    || files.find((file) => file.relative_path === entry.value?.source_path)
    || files[0]
    || null
})
const entryPdfUrl = computed(() => (primaryFile.value ? fileUrl(primaryFile.value) : ''))
const activeFile = computed(() => {
  const files = entry.value?.files || []
  return files.find((file) => file.relative_path === activePath.value) || files[0] || null
})
const assetUrlMap = computed(() => {
  const files = entry.value?.files || []
  return files.reduce((acc, file) => {
    acc[file.relative_path] = fileUrl(file)
    return acc
  }, {})
})

async function loadDetail() {
  loading.value = true
  try {
    entry.value = await fetchEntry(route.params.id)
    activePath.value = pickDefaultFile(entry.value?.files || [])
  } catch (error) {
    console.error('detail failed', error)
    entry.value = null
  } finally {
    loading.value = false
  }
}

function renderMarkdown(content, baseRelativePath = '') {
  const renderer = new MarkdownIt({
    html: true,
    linkify: true,
    breaks: true,
  })

  const defaultImageRule = renderer.renderer.rules.image || ((tokens, idx, options, env, self) => self.renderToken(tokens, idx, options))
  renderer.renderer.rules.image = (tokens, idx, options, env, self) => {
    const token = tokens[idx]
    const src = token.attrGet('src')
    if (src) {
      token.attrSet('src', resolveAssetUrl(src, baseRelativePath))
    }
    return defaultImageRule(tokens, idx, options, env, self)
  }

  return rewriteImageSrcs(renderer.render(content || '暂无可用内容'), baseRelativePath)
}

function pickDefaultFile(files) {
  if (!files.length) {
    return ''
  }

  const preferred = files.find((file) => isMarkdownFile(file))
    || files.find((file) => isTextFile(file))
    || files[0]

  return preferred.relative_path
}

function isMarkdownFile(file) {
  return file?.file_type === 'readme' || file?.file_type === 'markdown'
}

function isTextFile(file) {
  return ['markdown', 'readme', 'script', 'json', 'yaml', 'html', 'text', 'xml', 'csv'].includes(file?.file_type)
}

function isImageFile(file) {
  return file?.file_type === 'image'
}

function isPdfFile(file) {
  return file?.file_type === 'pdf'
}

function fileUrl(file) {
  if (!file) {
    return ''
  }
  if (file.download_url) {
    return file.download_url
  }
  const entryId = entry.value?.id
  const relativePath = file.relative_path
  if (!entryId || !relativePath) {
    return ''
  }
  return `/api/v1/entries/${entryId}/assets?path=${encodeURIComponent(relativePath)}`
}

function resolveAssetUrl(src, baseRelativePath = '') {
  if (!src || /^(https?:|data:|#)/i.test(src)) {
    return src
  }
  const normalized = normalizeRelativePath(src, baseRelativePath)
  return assetUrlMap.value[normalized] || src
}

function rewriteImageSrcs(html, baseRelativePath = '') {
  return (html || '').replace(
    /(<img\b[^>]*?\bsrc=["'])([^"']+)(["'][^>]*>)/gi,
    (_, prefix, src, suffix) => `${prefix}${resolveAssetUrl(src, baseRelativePath)}${suffix}`,
  )
}

function normalizeRelativePath(relativePath, baseRelativePath = '') {
  const baseParts = (baseRelativePath || '').split('/').filter(Boolean)
  if (baseParts.length) {
    baseParts.pop()
  }
  const targetParts = relativePath.split('/')
  for (const part of targetParts) {
    if (!part || part === '.') {
      continue
    }
    if (part === '..') {
      if (baseParts.length) {
        baseParts.pop()
      }
      continue
    }
    baseParts.push(part)
  }
  return baseParts.join('/')
}

function formatSize(size) {
  if (!size) {
    return '未知'
  }
  if (size < 1024) {
    return `${size} B`
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`
  }
  return `${(size / (1024 * 1024)).toFixed(1)} MB`
}

onMounted(() => {
  loadDetail()
})
</script>
