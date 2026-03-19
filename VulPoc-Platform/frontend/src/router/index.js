import { createRouter, createWebHistory } from 'vue-router'

import Home from '../views/Home.vue'
import Detail from '../views/Detail.vue'
import Stats from '../views/Stats.vue'
import DomainGuide from '../views/DomainGuide.vue'

export default createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      name: 'home',
      component: Home,
    },
    {
      path: '/vulns/:id',
      name: 'detail',
      component: Detail,
      props: true,
    },
    {
      path: '/stats',
      name: 'stats',
      component: Stats,
    },
    {
      path: '/domain-guide',
      name: 'domain-guide',
      component: DomainGuide,
    },
  ],
})
