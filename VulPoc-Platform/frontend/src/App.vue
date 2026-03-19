<template>
  <div class="app-shell">
    <header class="app-header">
      <div class="app-header__inner">
        <button class="app-brand" type="button" @click="router.push('/')">
          <span class="app-brand__title">VulPoc Platform</span>
          <span class="app-brand__subtitle">本地漏洞知识库</span>
        </button>

        <nav class="app-nav">
          <router-link to="/" class="app-nav__link" :class="{ 'is-active': route.name === 'home' }">
            检索
          </router-link>
          <router-link to="/domain-guide" class="app-nav__link" :class="{ 'is-active': route.name === 'domain-guide' }">
            域渗透指南
          </router-link>
          <router-link to="/stats" class="app-nav__link" :class="{ 'is-active': route.name === 'stats' }">
            统计
          </router-link>
        </nav>
      </div>
    </header>

    <main class="app-main">
      <router-view />
    </main>
  </div>
</template>

<script setup>
import { useRoute, useRouter } from 'vue-router'

const route = useRoute()
const router = useRouter()
</script>
