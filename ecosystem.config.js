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
        SSL:"false",
        API_KEY:"6d956be59be9acc5461b4e057e99195a0321386352d25b946b647c2f3667149e",
        ADMIN_DEFAULT_PASSWORD:"xmobit@12345",
        DATABASE_URL: "postgresql://datahub-admin:D4t4HubAdmin_7r9KzP2w@165.73.244.226:5432/datahub",
        TEMP_JWT_SECRET: "47411d04278145e15dfc98fc8b177786c27bf3562ebd66d3123a1eda0ebe038e",
        JWT_SECRET: "47411d04278145e15dfc98fc8b177786c27bf3562ebd66d3123a1eda0ebe038e",
        NOTIFICATIONS_EMAIL:"no.reply@xmobit.com",
        EMAIL_PASS:"tyik2.Cp",
        BASE_URL: "https://staging.xmobit.com",
        TIARA_API_TOKEN:"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiI1NzQiLCJvaWQiOjU3NCwidWlkIjoiZmJhNzdmNjEtM2ZkYy00YjFlLWI2MjAtM2I0OGI3MDg1ODhkIiwiYXBpZCI6NTQ4LCJpYXQiOjE3NDc5NDM0NzAsImV4cCI6MjA4Nzk0MzQ3MH0.FrXUlgMu_qjaNVMdtlVn6NYvinLoqkcFuHRGHvq19FF7vv7jeX9y8IQF8wGaOwKSRS5tzsxQv-4i-EbHcwbSQw",
        SMS_SENDER_ID: "CONNECT",
        FORCE_SYNC: "false",
        TIARA_BASE_URL:"https://api2.tiaraconnect.io/api/messaging/sendsms",
        BTC_WALLET_API_URL:"http://165.73.244.226:8090/api/v1/wallets",
        BTC_API_TOKEN:"92fKX7pLm3qZD8vN4Yt1WsJg5RBhUoAV",
        ADMIN_DEFAULT_PASSWORD: "xmobit@12345",
        MONERO_WALLET_API_URL: "http://86.48.1.16:8084/api/v1/monero/create-fund-wallet-async",
        XMR_API_TOKEN: "u6HmroO3kqb4kDZdff0kl1pXlaYDqRyg",
        HMAC_SECRET: "pM4W33Jse6OFMbKFLjyUQweCFvGllhnD",
        API_KEY: "6d956be59be9acc5461b4e057e99195a0321386352d25b946b647c2f3667149e"
      },
      env_production: {
        NODE_ENV: "production",
        PORT: 3003,
        API_KEY:"68b7d145a58b4ceff701528ace1b95d5ef202494fc3852d5a85ead4a43f9e994",
        ADMIN_DEFAULT_PASSWORD: "xmobit@1345",
        DATABASE_URL: "postgresql://datahub-prod-admin:Dh7\$mK9pQ2vX8nL3wR6tY4uE@86.48.1.16:5432/datahub-prod",
        TEMP_JWT_SECRET: "47411d04278145e15dfc98fc8b1777868b7d145a58b4ceff701528ace1b95d5ef202494fc3852d5a85ead4a43f9e9946c27bf3562ebd66d3123a1eda0ebe038e",
        JWT_SECRET: "47411d0427814568b7d145a58b4ceff701528ace1b95d5ef202494fc3852d5a85ead4a43f9e994e15dfc98fc8b177786c27bf3562ebd66d3123a1eda0ebe038e",
        NOTIFICATIONS_EMAIL: "no.reply@xmobit.com",
        EMAIL_PASS: "tyik2.Cp",
        BASE_URL: "https://xmobit.com",
        TIARA_BASE_URL: "https://api2.tiaraconnect.io/api/messaging/sendsms",
        HMAC_SECRET: "pM4W33Jse6OFMbKFLjyUQweCFvGllhnD", 
        TIARA_API_TOKEN: "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiI1NzQiLCJvaWQiOjU3NCwidWlkIjoiZmJhNzdmNjEtM2ZkYy00YjFlLWI2MjAtM2I0OGI3MDg1ODhkIiwiYXBpZCI6NTQ4LCJpYXQiOjE3NDc5NDM0NzAsImV4cCI6MjA4Nzk0MzQ3MH0.FrXUlgMu_qjaNVMdtlVn6NYvinLoqkcFuHRGHvq19FF7vv7jeX9y8IQF8wGaOwKSRS5tzsxQv-4i-EbHcwbSQw",
        MONERO_WALLET_API_URL: "http://127.0.0.1:8084/api/v1/monero/create-fund-wallet-async",
        BTC_WALLET_API_URL:"http://127.0.0.1:8090/api/v1/wallets", 
        BTC_API_TOKEN:"ba031e6926b09010047ac6d11936d419897b5bbbc7a2f840f279e8a2886b151e",
        XMR_API_TOKEN: "u6HmroO3kqb4kDZdff0kl1pXlaYDqRyg",
        SMS_SENDER_ID: "CONNECT",
        FORCE_SYNC: "false"
      }
    }
  ]
};
