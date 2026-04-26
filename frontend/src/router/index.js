import { createRouter, createWebHistory } from 'vue-router'
import ScanPage from '../views/ScanPage.vue'
import TaskList from '../views/TaskList.vue'
import ResultPage from '../views/ResultPage.vue'

const routes = [
  {
    path: '/',
    redirect: '/scan'
  },
  {
    path: '/scan',
    name: 'ScanPage',
    component: ScanPage
  },
  {
    path: '/tasks',
    name: 'TaskList',
    component: TaskList
  },
  {
    path: '/results/:taskId',
    name: 'ResultPage',
    component: ResultPage,
    props: true
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
