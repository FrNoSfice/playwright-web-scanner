<template>
  <div>
    <el-card>
      <template #header>
        <div class="header-row">
          <span>扫描任务列表</span>
          <el-button type="primary" @click="loadTasks">刷新</el-button>
        </div>
      </template>

      <el-table :data="taskList" border style="width: 100%">
        <el-table-column prop="id" label="任务ID" width="90" />
        <el-table-column prop="task_name" label="任务名称" width="180" />
        <el-table-column prop="target_url" label="目标URL" />
        <el-table-column prop="scan_depth" label="深度" width="80" />
        <el-table-column prop="scan_status" label="状态" width="120">
          <template #default="scope">
            <el-tag :type="getStatusType(scope.row.scan_status)">
              {{ getStatusText(scope.row.scan_status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180" />
        <el-table-column label="操作" width="320">
          <template #default="scope">
            <el-button
              size="small"
              type="success"
              @click="handleStart(scope.row.id)"
              :disabled="scope.row.scan_status === 1"
            >
              开始扫描
            </el-button>

            <el-button size="small" @click="goResult(scope.row.id)">
              查看结果
            </el-button>

            <el-button
              size="small"
              type="danger"
              @click="handleDelete(scope.row)"
              :disabled="scope.row.scan_status === 1"
            >
              删除任务
            </el-button>
          </template>
</el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getTaskList, startScan, deleteTask } from '../api/task'

const router = useRouter()
const taskList = ref([])

const getStatusText = (status) => {
  const map = {
    0: '未开始',
    1: '扫描中',
    2: '已完成',
    3: '失败'
  }
  return map[status] || '未知'
}

const getStatusType = (status) => {
  const map = {
    0: 'info',
    1: 'warning',
    2: 'success',
    3: 'danger'
  }
  return map[status] || 'info'
}

const loadTasks = async () => {
  try {
    const res = await getTaskList()
    taskList.value = res.data.data || []
  } catch (error) {
    ElMessage.error('获取任务列表失败')
    console.error(error)
  }
}

const handleStart = async (taskId) => {
  try {
    const res = await startScan(taskId)
    ElMessage.success(res.data.message || '扫描已启动')
    loadTasks()
  } catch (error) {
    ElMessage.error(error?.response?.data?.message || '启动扫描失败')
    console.error(error)
  }
}

const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm(
      `确认删除任务“${row.task_name}”吗？删除后页面记录、漏洞结果和扫描日志会一并清除。`,
      '删除确认',
      {
        confirmButtonText: '确认删除',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )

    const res = await deleteTask(row.id)
    ElMessage.success(res.data.message || '删除成功')
    loadTasks()
  } catch (error) {
    if (error === 'cancel' || error === 'close') {
      return
    }
    ElMessage.error(error?.response?.data?.message || '删除任务失败')
    console.error(error)
  }
}

const goResult = (taskId) => {
  router.push(`/results/${taskId}`)
}

onMounted(() => {
  loadTasks()
})
</script>

<style scoped>
.header-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>