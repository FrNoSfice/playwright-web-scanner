<template>
  <div>
    <el-row :gutter="20" class="stats-row">
      <el-col :span="6">
        <el-card>
          <div class="stat-item">
            <div class="stat-label">成功扫描页数</div>
            <div class="stat-value success">{{ taskInfo.success_pages || 0 }}</div>
          </div>
        </el-card>
      </el-col>

      <el-col :span="6">
        <el-card>
          <div class="stat-item">
            <div class="stat-label">失败扫描页数</div>
            <div class="stat-value danger">{{ taskInfo.failed_pages || 0 }}</div>
          </div>
        </el-card>
      </el-col>

      <el-col :span="6">
        <el-card>
          <div class="stat-item">
            <div class="stat-label">漏洞总数</div>
            <div class="stat-value warning">{{ resultList.length }}</div>
          </div>
        </el-card>
      </el-col>

      <el-col :span="6">
        <el-card>
          <div class="stat-item">
            <div class="stat-label">任务状态</div>
            <div class="stat-value">
              <el-tag :type="getStatusType(taskInfo.scan_status)">
                {{ getStatusText(taskInfo.scan_status) }}
              </el-tag>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card>
      <template #header>
        <div class="header-row">
          <span>扫描结果 - 任务 {{ taskId }}</span>
          <el-button @click="loadData">刷新</el-button>
        </div>
      </template>

      <el-table :data="resultList" border style="width: 100%">
  <el-table-column label="编号" width="80">
    <template #default="scope">
      {{ scope.$index + 1 }}
    </template>
  </el-table-column>

  <el-table-column prop="vuln_name" label="漏洞名称" width="180" />
  <el-table-column prop="vuln_type" label="漏洞类型" width="140" />
  <el-table-column prop="risk_level" label="风险等级" width="100">
    <template #default="scope">
      <el-tag :type="getRiskType(scope.row.risk_level)">
        {{ getRiskText(scope.row.risk_level) }}
      </el-tag>
    </template>
  </el-table-column>
  <el-table-column prop="page_url" label="所在页面" />
  <el-table-column prop="param_name" label="参数名" width="120" />
  <el-table-column prop="suggestion" label="修复建议" />
</el-table>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getResult, getTaskDetail } from '../api/task'

const route = useRoute()
const taskId = route.params.taskId
const resultList = ref([])
const taskInfo = ref({})

const getRiskText = (level) => {
  const map = {
    1: '低危',
    2: '中危',
    3: '高危'
  }
  return map[level] || '未知'
}

const getRiskType = (level) => {
  const map = {
    1: 'info',
    2: 'warning',
    3: 'danger'
  }
  return map[level] || 'info'
}

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

const loadData = async () => {
  try {
    const [resultRes, taskRes] = await Promise.all([
      getResult(taskId),
      getTaskDetail(taskId)
    ])

    resultList.value = resultRes.data.data || []
    taskInfo.value = taskRes.data.data || {}
  } catch (error) {
    ElMessage.error('获取扫描结果失败')
    console.error(error)
  }
}

onMounted(() => {
  loadData()
})
</script>

<style scoped>
.stats-row {
  margin-bottom: 20px;
}

.stat-item {
  text-align: center;
}

.stat-label {
  font-size: 14px;
  color: #666;
  margin-bottom: 10px;
}

.stat-value {
  font-size: 28px;
  font-weight: bold;
}

.success {
  color: #67c23a;
}

.danger {
  color: #f56c6c;
}

.warning {
  color: #e6a23c;
}

.header-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>