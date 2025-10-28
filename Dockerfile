# 使用官方 Node.js 运行时作为基础镜像
FROM node:20-alpine

# 设置工作目录
WORKDIR /app

# 复制 package.json 和 package-lock.json
COPY package*.json ./

# 安装所有依赖（包括开发依赖，用于构建）
RUN npm ci

# 复制源代码
COPY . .

# 构建应用
RUN npm run build

# 清理开发依赖以减小镜像大小
RUN npm prune --production

# 暴露端口（Render 会自动设置 PORT 环境变量）
EXPOSE 3000

# 启动应用
CMD ["npm", "start"]
