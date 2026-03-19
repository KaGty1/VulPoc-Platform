<template>
  <section class="page-stack">
    <section class="panel">
      <div class="page-head">
        <div>
          <h1>导入统计</h1>
          <p>查看当前知识库加载的来源、解析器和文件扫描情况。</p>
        </div>
        <el-button @click="router.push('/')">返回检索</el-button>
      </div>
    </section>

    <section class="panel">
      <div class="simple-metrics">
        <div class="simple-metrics__item">
          <span>总条目</span>
          <strong>{{ stats.total_entries || 0 }}</strong>
        </div>
        <div class="simple-metrics__item">
          <span>来源数量</span>
          <strong>{{ stats.source_count || 0 }}</strong>
        </div>
        <div class="simple-metrics__item">
          <span>解析器数量</span>
          <strong>{{ stats.parser_count || 0 }}</strong>
        </div>
        <div class="simple-metrics__item">
          <span>扫描文件</span>
          <strong>{{ stats.import?.files_scanned || 0 }}</strong>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="list-head">
        <div>
          <h2>导入摘要</h2>
        </div>
      </div>
      <div class="stats-grid-simple">
        <div class="stats-grid-simple__item">
          <span>创建条目</span>
          <strong>{{ stats.import?.entries_created || 0 }}</strong>
        </div>
        <div class="stats-grid-simple__item">
          <span>扫描目录</span>
          <strong>{{ stats.import?.directories_scanned || 0 }}</strong>
        </div>
        <div class="stats-grid-simple__item">
          <span>跳过文件</span>
          <strong>{{ stats.import?.files_skipped || 0 }}</strong>
        </div>
        <div class="stats-grid-simple__item">
          <span>解析失败</span>
          <strong>{{ stats.import?.parse_failed || 0 }}</strong>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="list-head">
        <div>
          <h2>来源目录</h2>
        </div>
      </div>
      <el-table :data="sources" stripe>
        <el-table-column prop="name" label="来源" min-width="180" />
        <el-table-column prop="type" label="类型" width="120" />
        <el-table-column prop="entries" label="条目数" width="100" />
        <el-table-column prop="files_scanned" label="扫描文件" width="120" />
        <el-table-column prop="parse_failed" label="失败" width="90" />
      </el-table>
    </section>

    <section class="panel">
      <div class="list-head">
        <div>
          <h2>已启用解析器</h2>
        </div>
      </div>
      <div class="quick-tags">
        <span v-for="item in stats.supported_parsers || []" :key="item" class="tag-chip tag-chip--soft">{{ item }}</span>
      </div>
    </section>
  </section>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { fetchSources, fetchStats } from '../api/knowledge'

const router = useRouter()
const stats = ref({})
const sources = ref([])

onMounted(async () => {
  try {
    const [statsData, sourceData] = await Promise.all([
      fetchStats(),
      fetchSources(),
    ])
    stats.value = statsData || {}
    sources.value = sourceData || []
  } catch (error) {
    console.error('load stats failed', error)
  }
})
</script>
