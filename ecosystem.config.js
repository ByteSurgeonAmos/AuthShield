
module.exports = {
  apps: [
    {
      name: "XMOBIT-Auth-Engine",
      script: "node dist/main",
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "1G",
      
      env_staging: {
        NODE_ENV: "staging",
        PORT: 3003,
        ADMIN_DEFAULT_PASSWORD: "xmobit@12345",
        DATABASE_URL: "postgresql://datahub-admin:D4t4HubAdmin_7r9KzP2w@165.73.244.226:5432/datahub",
        TEMP_JWT_SECRET: "47411d04278145e15dfc98fc8b177786c27bf3562ebd66d3123a1eda0ebe038e",
        JWT_SECRET: "47411d04278145e15dfc98fc8b177786c27bf3562ebd66d3123a1eda0ebe038e",
        NOTIFICATIONS_EMAIL: "no.reply@xmobit.com",
        EMAIL_PASS: "tyik2.Cp",
        BASE_URL: "https://staging.xmobit.com",
        TIARA_API_TOKEN: "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiI1NzQiLCJvaWQiOjU3NCwidWlkIjoiZmJhNzdmNjEtM2ZkYy00YjFlLWI2MjAtM2I0OGI3MDg1ODhkIiwiYXBpZCI6NTQ4LCJpYXQiOjE3NDc5NDM0NzAsImV4cCI6MjA4Nzk0MzQ3MH0.FrXUlgMu_qjaNVMdtlVn6NYvinLoqkcFuHRGHvq19FF7vv7jeX9y8IQF8wGaOwKSRS5tzsxQv-4i-EbHcwbSQw",
        SMS_SENDER_ID: "CONNECT",
        FORCE_SYNC: "true"
      },
      env_production: {
        NODE_ENV: "production",
        PORT: 3003,
        ADMIN_DEFAULT_PASSWORD: "xmobit@12345",
        DATABASE_URL: "postgresql://datahub-prod-admin:Dh7\$mK9pQ2vX8nL3wR6tY4uE@86.48.1.16:5432/datahub-prod",
        TEMP_JWT_SECRET: "47411d04278145e15dfc98fc8b177786c27bf3562ebd66d3123a1eda0ebe038e",
        JWT_SECRET: "47411d04278145e15dfc98fc8b177786c27bf3562ebd66d3123a1eda0ebe038e",
        NOTIFICATIONS_EMAIL: "no.reply@xmobit.com",
        EMAIL_PASS: "tyik2.Cp",
        BASE_URL: "https://xmobit.com",

        TIARA_API_TOKEN: "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiI1NzQiLCJvaWQiOjU3NCwidWlkIjoiZmJhNzdmNjEtM2ZkYy00YjFlLWI2MjAtM2I0OGI3MDg1ODhkIiwiYXBpZCI6NTQ4LCJpYXQiOjE3NDc5NDM0NzAsImV4cCI6MjA4Nzk0MzQ3MH0.FrXUlgMu_qjaNVMdtlVn6NYvinLoqkcFuHRGHvq19FF7vv7jeX9y8IQF8wGaOwKSRS5tzsxQv-4i-EbHcwbSQw",

        SMS_SENDER_ID: "CONNECT",
        FORCE_SYNC: "true"
      }
    }
  ]
};
