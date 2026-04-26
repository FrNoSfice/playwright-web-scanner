import axios from 'axios'

const request = axios.create({
  baseURL: 'http://127.0.0.1:5000',
  timeout: 10000
})

export function createTask(data) {
  return request.post('/task/create', data)
}

export function getTaskList() {
  return request.get('/task/list')
}

export function startScan(taskId) {
  return request.post(`/scan/start/${taskId}`)
}

export function getResult(taskId) {
  return request.get(`/result/${taskId}`)
}

export function getTaskDetail(taskId) {
  return request.get(`/task/${taskId}`)
}

export function deleteTask(taskId) {
  return request.post(`/task/delete/${taskId}`)
}