<template>
  <div class="header">
    <div class="logo">Web安全扫描原型系统</div>
    <div class="nav">
      <router-link to="/scan" class="nav-link">开始扫描</router-link>
      <router-link to="/tasks" class="nav-link">任务列表</router-link>
    </div>
  </div>
</template>

<style scoped>
.header {
  height: 60px;
  background: #409eff;
  color: white;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 28px;
}

.logo {
  font-size: 20px;
  font-weight: bold;
}

.nav {
  display: flex;
  gap: 20px;
}

.nav-link {
  color: white;
  text-decoration: none;
  font-size: 15px;
}

.nav-link.router-link-active {
  font-weight: bold;
  border-bottom: 2px solid white;
  padding-bottom: 2px;
}
</style>