<template>
  <section class="page-stack">
    <section class="panel">
      <div class="page-head">
        <div>
          <h1>域渗透指南</h1>
          <p>浏览 `域渗透攻防` 资料库，按章节快速查阅 PDF 指南并进入在线阅读页。</p>
        </div>
        <div class="page-head__stats">
          <span>{{ guideEntries.length }} 篇指南</span>
          <span>{{ chapterOptions.length }} 个章节</span>
        </div>
      </div>

      <div class="guide-toolbar">
        <el-input
          v-model="keyword"
          clearable
          size="large"
          placeholder="搜索章节名、主题名、CVE"
          @keyup.enter="loadGuides"
        />
        <el-select v-model="activeChapter" clearable placeholder="筛选章节">
          <el-option v-for="item in chapterOptions" :key="item" :label="item" :value="item" />
        </el-select>
        <div class="search-grid__actions">
          <el-button type="primary" :loading="loading" @click="loadGuides">检索指南</el-button>
          <el-button @click="resetFilters">重置</el-button>
        </div>
      </div>

      <div v-if="chapterOptions.length" class="quick-tags">
        <button
          v-for="item in chapterOptions"
          :key="item"
          type="button"
          class="tag-chip"
          @click="activeChapter = item"
        >
          {{ item }}
        </button>
      </div>
    </section>

    <section class="panel">
      <div class="list-head">
        <div>
          <h2>指南目录</h2>
          <p>{{ loading ? '正在加载 PDF 指南...' : `当前展示 ${filteredEntries.length} 篇` }}</p>
        </div>
      </div>

      <div v-if="errorMessage" class="state-box state-box--error">
        {{ errorMessage }}
      </div>

      <div v-else-if="!loading && !filteredEntries.length" class="state-box">
        当前没有匹配的域渗透指南，可以尝试更短的关键词或切换章节。
      </div>

      <section v-else class="guide-groups">
        <article v-for="group in groupedEntries" :key="group.name" class="guide-group">
          <div class="guide-group__head">
            <h3>{{ group.name }}</h3>
            <span>{{ group.items.length }} 篇</span>
          </div>

          <div class="guide-card-grid">
            <button
              v-for="item in group.items"
              :key="item.id"
              type="button"
              class="guide-card"
              @click="openDetail(item.id)"
            >
              <div class="guide-card__top">
                <span class="badge badge--muted">PDF</span>
                <span v-if="item.cve" class="badge">{{ item.cve }}</span>
              </div>
              <h4>{{ item.title }}</h4>
              <p>{{ item.summary || item.source_path }}</p>
              <div class="guide-card__meta">
                <span>{{ fileName(item.source_path) }}</span>
                <span>{{ item.source_name }}</span>
              </div>
            </button>
          </div>
        </article>
      </section>
    </section>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { searchEntries } from '../api/knowledge'

const GUIDE_SOURCE = '域渗透指南'
const chapterOrder = {
  第一章: 1,
  第二章: 2,
  第三章: 3,
  第四章: 4,
  第五章: 5,
  第六章: 6,
  第七章: 7,
  第八章: 8,
  第九章: 9,
  第十章: 10,
}

const router = useRouter()
const loading = ref(false)
const errorMessage = ref('')
const keyword = ref('')
const activeChapter = ref('')
const guideEntries = ref([])

const chapterOptions = computed(() => {
  const names = new Set()
  for (const item of guideEntries.value) {
    names.add(chapterName(item.source_path))
  }
  return Array.from(names).sort(compareChapter)
})

const filteredEntries = computed(() => {
  if (!activeChapter.value) {
    return guideEntries.value
  }
  return guideEntries.value.filter((item) => chapterName(item.source_path) === activeChapter.value)
})

const groupedEntries = computed(() => {
  const groups = new Map()
  for (const item of filteredEntries.value) {
    const name = chapterName(item.source_path)
    if (!groups.has(name)) {
      groups.set(name, [])
    }
    groups.get(name).push(item)
  }

  return Array.from(groups.entries())
    .sort((a, b) => compareChapter(a[0], b[0]))
    .map(([name, items]) => ({
      name,
      items: items.slice().sort((a, b) => a.title.localeCompare(b.title, 'zh-CN')),
    }))
})

async function loadGuides() {
  loading.value = true
  errorMessage.value = ''
  try {
    const result = await searchEntries({
      keyword: keyword.value.trim(),
      source: GUIDE_SOURCE,
      file_type: 'pdf',
      page: 1,
      page_size: 500,
    })
    guideEntries.value = result.list || []
  } catch (error) {
    console.error('load guides failed', error)
    errorMessage.value = '域渗透指南暂时无法加载。'
    guideEntries.value = []
  } finally {
    loading.value = false
  }
}

function resetFilters() {
  keyword.value = ''
  activeChapter.value = ''
  loadGuides()
}

function openDetail(id) {
  router.push(`/vulns/${id}`)
}

function chapterName(sourcePath = '') {
  return sourcePath.split('/').filter(Boolean)[0] || '未分类'
}

function fileName(sourcePath = '') {
  const parts = sourcePath.split('/').filter(Boolean)
  return parts[parts.length - 1] || sourcePath
}

function compareChapter(left, right) {
  const leftRank = chapterOrder[left] || Number.MAX_SAFE_INTEGER
  const rightRank = chapterOrder[right] || Number.MAX_SAFE_INTEGER
  if (leftRank === rightRank) {
    return left.localeCompare(right, 'zh-CN')
  }
  return leftRank - rightRank
}

onMounted(() => {
  loadGuides()
})
</script>
