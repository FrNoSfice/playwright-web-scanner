<template>
  <div class="app-container">
    <AppHeader />
    <div class="main-content">
      <router-view />
    </div>
  </div>
</template>

<script setup>
import AppHeader from './components/AppHeader.vue'
</script>

<style>
body {
  margin: 0;
  font-family: Arial, "Microsoft YaHei", sans-serif;
  background: #f5f7fa;
}

* {
  box-sizing: border-box;
}

.app-container {
  min-height: 100vh;
}

.main-content {
  padding: 24px;
}
</style>