<template>
  <div class="page">
    <el-card class="scan-card">
      <template #header>
        <span>新建扫描任务</span>
      </template>

      <el-form :model="form" label-width="100px">
        <el-form-item label="目标网址">
          <el-input v-model="form.target_url" placeholder="请输入目标URL，例如 http://127.0.0.1/dvwa/" />
        </el-form-item>

        <el-form-item label="任务名称">
          <el-input v-model="form.task_name" placeholder="请输入任务名称" />
        </el-form-item>

        <el-form-item label="扫描深度">
          <el-input-number v-model="form.scan_depth" :min="1" :max="5" />
        </el-form-item>

        <el-form-item label="备注">
          <el-input
            v-model="form.remark"
            type="textarea"
            placeholder="可填写任务说明"
          />
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="handleCreateTask" :loading="loading">
            创建任务
          </el-button>
          <el-button @click="resetForm">重置</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="tips-card">
      <template #header>
        <span>系统说明</span>
      </template>
      <p>1. 输入需要扫描的目标网址。</p>
      <p>2. 创建任务后，在任务列表中启动扫描。</p>
      <p>3. 扫描完成后，可查看漏洞结果和风险等级。</p>
    </el-card>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { createTask } from '../api/task'

const loading = ref(false)

const form = reactive({
  target_url: '',
  task_name: '',
  scan_depth: 1,
  remark: ''
})

const resetForm = () => {
  form.target_url = ''
  form.task_name = ''
  form.scan_depth = 1
  form.remark = ''
}

const handleCreateTask = async () => {
  if (!form.target_url) {
    ElMessage.warning('请输入目标网址')
    return
  }

  if (!form.task_name) {
    ElMessage.warning('请输入任务名称')
    return
  }

  try {
    loading.value = true
    const res = await createTask(form)
    ElMessage.success(res.data.message || '任务创建成功')
    resetForm()
  } catch (error) {
    ElMessage.error('任务创建失败')
    console.error(error)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.page {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 20px;
}

.scan-card,
.tips-card {
  min-height: 360px;
}
</style>