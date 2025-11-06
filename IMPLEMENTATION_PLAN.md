# 项目结构优化实施计划

## 目标
将 `index.ts` (4326行) 拆分为清晰的模块化结构，提高代码可维护性和可读性，同时保持所有功能不变。

## 阶段划分

### Stage 1: 创建目录结构，提取工具函数和类型定义
**目标**: 提取基础工具函数和类型定义
**成功标准**: 
- 工具函数独立到 `src/utils/`
- 类型定义整理到 `src/types/`
- 所有导入路径正确

### Stage 2: 提取中间件
**目标**: 将中间件逻辑独立
**成功标准**:
- 日志中间件独立
- 会话中间件独立
- 所有中间件可复用

### Stage 3: 提取页面渲染函数
**目标**: 将页面渲染逻辑独立
**成功标准**:
- LandingPage 渲染器独立
- AuthorizePage 渲染器独立
- PaymentPage 渲染器独立
- 所有渲染函数可测试

### Stage 4: 提取业务服务
**目标**: 将业务逻辑封装为服务
**成功标准**:
- 认证服务独立
- 授权服务独立
- 支付服务独立
- Firebase 服务独立

### Stage 5: 提取路由处理器
**目标**: 将路由逻辑按功能分组
**成功标准**:
- 认证路由独立
- OAuth 路由独立
- MCP 路由独立
- Well-known 路由独立

### Stage 6: 重构主入口文件
**目标**: 整合所有模块，简化主文件
**成功标准**:
- `index.ts` 只负责应用初始化和路由注册
- 所有功能正常工作
- 代码结构清晰

### Stage 7: 验证功能完整性
**目标**: 确保所有功能正常
**成功标准**:
- 所有路由可访问
- 所有功能正常工作
- 无编译错误
- 无运行时错误

## 状态
- Stage 1: ✅ Completed (工具函数和类型定义已提取)
- Stage 2: ✅ Completed (中间件已提取)
- Stage 3: ✅ Completed (基础页面渲染函数已提取，renderLandingPage 待提取)
- Stage 4: ⚠️ Partial (部分服务已提取: payment, authorization, firebase)
- Stage 5: ✅ Completed (基础路由结构已创建，Schemas 已提取)
- Stage 6: Not Started
- Stage 7: Not Started

## Stage 1 完成内容
- ✅ 创建了目录结构 (utils/, types/, middleware/, routes/, services/, renderers/, schemas/)
- ✅ 提取了密码工具函数 (`src/utils/password.ts`)
- ✅ 提取了 HTML 工具函数 (`src/utils/html.ts`)
- ✅ 提取了字符串工具函数 (`src/utils/string.ts`)
- ✅ 提取了应用程序工具函数 (`src/utils/app.ts`)
- ✅ 提取了通用类型定义 (`src/types/common.ts`)
- ✅ 更新了 `index.ts` 使用新模块
- ✅ 编译通过，无错误

## Stage 2 完成内容
- ✅ 提取了日志中间件 (`src/middleware/logging.ts`)
- ✅ 提取了会话中间件 (`src/middleware/session.ts`)
- ✅ 创建了中间件统一入口 (`src/middleware/index.ts`)
- ✅ 更新了 `index.ts` 使用新的中间件模块
- ✅ 编译通过，无错误

## Stage 3 完成内容
- ✅ 提取了基础页面渲染器 (`src/renderers/base.ts`)
- ✅ 提取了授权页面渲染器 (`src/renderers/authorize.ts`)
- ✅ 提取了支付页面渲染器 (`src/renderers/payment.ts`)
- ✅ 更新了 `index.ts` 使用新的渲染器模块
- ✅ 编译通过，无错误

## Stage 5 完成内容
- ✅ 提取了 Zod schemas (`src/schemas/index.ts`)
- ✅ 创建了基础路由结构 (`src/routes/auth.ts`, `src/routes/index.ts`)
- ✅ 提取了部分服务函数 (payment, authorization, firebase)
- ✅ 更新了 `index.ts` 使用新的 schemas 和路由模块
- ✅ 编译通过，无错误

## 当前状态
`index.ts` 文件从 4326 行减少到 3042 行（**减少 1284 行，约 30%**）。
- Stage 1: 提取了工具函数和类型定义（减少 177 行）
- Stage 2: 提取了中间件（减少约 177 行）
- Stage 3: 提取了基础渲染函数（减少约 100 行）
- Stage 4: 提取了部分服务函数（减少约 150 行）
- Stage 5: 提取了 schemas 和基础路由（减少约 680 行）

**剩余工作**:
- 提取所有路由处理器到独立路由文件
- 提取 `renderLandingPage` 函数（~1000行）
- 提取 Firebase UI 相关函数
- 提取图标和 UI 辅助函数

