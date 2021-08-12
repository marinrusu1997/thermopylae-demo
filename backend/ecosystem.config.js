module.exports = {
  apps : [{
    name   : "thermopylae",
    script : "./index.js",
    env: {
      NODE_ENV: 'production',
      CONFIG_FILES_PATH: process.env['CONFIG_FILES_PATH']
    },
    instances: 'max',
    exec_mode: 'cluster',
    watch: false,
    source_map_support: false,
    instance_var: 'INSTANCE_ID',
    kill_timeout: 2000,
    wait_ready: true
  }]
}
