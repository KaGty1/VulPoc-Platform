<template>
  <section class="page-stack">
    <section class="panel">
      <div class="page-head">
        <div>
          <h1>漏洞知识检索</h1>
          <p>按关键词、CVE、标签、来源和文件类型快速定位本地漏洞文档。</p>
        </div>
        <div class="page-head__stats">
          <span>{{ formatNumber(stats.total_entries) }} 条记录</span>
          <span>{{ formatNumber(stats.source_count) }} 个来源</span>
        </div>
      </div>

      <div class="search-grid">
        <el-input
          v-model="filters.keyword"
          clearable
          size="large"
          placeholder="输入产品名、漏洞类型、接口、路径或描述关键词"
          @keyup.enter="runSearch({ resetPage: true })"
        />
        <el-input
          v-model="filters.cve"
          clearable
          placeholder="CVE 编号"
          @keyup.enter="runSearch({ resetPage: true })"
        />
        <el-select v-model="filters.source" clearable placeholder="来源">
          <el-option v-for="item in sources" :key="item.path" :label="item.name" :value="item.name" />
        </el-select>
        <el-select v-model="filters.tag" clearable filterable placeholder="标签">
          <el-option v-for="item in tags" :key="item.name" :label="`${item.name} (${item.count})`" :value="item.name" />
        </el-select>
        <el-select v-model="filters.fileType" clearable placeholder="文件类型">
          <el-option v-for="item in fileTypeOptions" :key="item.value" :label="item.label" :value="item.value" />
        </el-select>
        <div class="search-grid__actions">
          <el-button type="primary" :loading="loading" @click="runSearch({ resetPage: true })">搜索</el-button>
          <el-button @click="resetFilters">重置</el-button>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="list-head">
        <div>
          <h2>搜索结果</h2>
          <p>{{ loading ? '正在检索...' : `共 ${searchState.total} 条结果` }}</p>
        </div>
        <div class="list-head__meta">
          <span>第 {{ searchState.page }} 页</span>
          <span>每页 {{ searchState.pageSize }} 条</span>
        </div>
      </div>

      <div v-if="topTags.length" class="quick-tags">
        <button
          v-for="item in topTags"
          :key="item.name"
          type="button"
          class="tag-chip"
          @click="applyTag(item.name)"
        >
          {{ item.name }}
        </button>
      </div>

      <div v-if="errorMessage" class="state-box state-box--error">
        {{ errorMessage }}
      </div>

      <section v-if="searchState.list.length" class="result-list">
        <article
          v-for="item in searchState.list"
          :key="item.id"
          class="result-item"
          @click="openDetail(item.id)"
        >
          <div class="result-item__main">
            <div class="result-item__top">
              <h3>{{ item.title }}</h3>
              <div class="result-item__badges">
                <span v-if="item.cve" class="badge">{{ item.cve }}</span>
                <span v-if="item.file_type" class="badge badge--muted">{{ item.file_type }}</span>
              </div>
            </div>

            <p class="result-item__summary">{{ item.summary || '暂无摘要' }}</p>

            <div class="result-item__meta">
              <span>{{ item.source_name }}</span>
              <span>{{ item.source_path }}</span>
              <span v-if="item.parser_name">{{ item.parser_name }}</span>
            </div>

            <div v-if="item.tags?.length" class="result-item__tags">
              <span v-for="tag in item.tags.slice(0, 6)" :key="tag" class="tag-chip tag-chip--soft">{{ tag }}</span>
            </div>
          </div>
        </article>
      </section>

      <div v-else-if="!loading" class="state-box">
        没有匹配结果，可以尝试更短的关键词、指定 CVE 或切换标签。
      </div>

      <div v-if="searchState.total > 0" class="pagination-wrap">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :page-sizes="[12, 24, 48]"
          :total="searchState.total"
          layout="total, sizes, prev, pager, next"
          @current-change="runSearch"
          @size-change="handlePageSizeChange"
        />
      </div>
    </section>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { fetchSources, fetchStats, fetchTags, searchEntries } from '../api/knowledge'

const route = useRoute()
const router = useRouter()
const page = ref(1)
const pageSize = ref(12)
const loading = ref(false)
const errorMessage = ref('')
const sources = ref([])
const tags = ref([])
const stats = reactive({
  total_entries: 0,
  source_count: 0,
})
const filters = reactive({
  keyword: '',
  cve: '',
  tag: '',
  source: '',
  fileType: '',
})
const searchState = reactive({
  list: [],
  total: 0,
  page: 1,
  pageSize: 12,
})

const fileTypeOptions = [
  { label: 'Markdown / README', value: 'markdown' },
  { label: 'PDF', value: 'pdf' },
  { label: '脚本', value: 'script' },
  { label: 'JSON', value: 'json' },
  { label: 'YAML', value: 'yaml' },
  { label: 'HTML', value: 'html' },
  { label: 'Text / XML / CSV', value: 'text' },
]

const topTags = computed(() => tags.value.slice(0, 12))

async function runSearch(options = {}) {
  if (options.resetPage) {
    page.value = 1
  }

  loading.value = true
  errorMessage.value = ''
  try {
    const payload = await searchEntries({
      keyword: filters.keyword.trim(),
      cve: filters.cve.trim(),
      tag: filters.tag,
      source: filters.source,
      file_type: filters.fileType,
      page: page.value,
      page_size: pageSize.value,
    })
    searchState.list = payload.list || []
    searchState.total = payload.total || 0
    searchState.page = payload.page || page.value
    searchState.pageSize = payload.page_size || pageSize.value
  } catch (error) {
    console.error('search failed', error)
    errorMessage.value = '检索接口暂时不可用。'
    searchState.list = []
    searchState.total = 0
  } finally {
    loading.value = false
  }
}

function handlePageSizeChange() {
  page.value = 1
  runSearch()
}

function resetFilters() {
  filters.keyword = ''
  filters.cve = ''
  filters.tag = ''
  filters.source = ''
  filters.fileType = ''
  page.value = 1
  runSearch()
}

function applyTag(tag) {
  filters.tag = tag
  runSearch({ resetPage: true })
}

function openDetail(id) {
  router.push(`/vulns/${id}`)
}

async function loadFilterData() {
  try {
    const [sourceList, tagList, statsData] = await Promise.all([
      fetchSources(),
      fetchTags(),
      fetchStats(),
    ])
    sources.value = sourceList
    tags.value = tagList
    Object.assign(stats, statsData || {})
  } catch (error) {
    console.error('load filters failed', error)
  }
}

function formatNumber(value) {
  return new Intl.NumberFormat('zh-CN').format(value || 0)
}

onMounted(() => {
  if (typeof route.query.tag === 'string') {
    filters.tag = route.query.tag
  }
  loadFilterData()
  runSearch()
})
</script>
