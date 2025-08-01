# Redis 分布式锁行为说明

## 🔧 修改后的锁方法行为

### 1. `Lock(ctx, key)` - 阻塞式（默认超时）
```go
unlock, err := locker.Lock(ctx, "user123")
```
- **行为**: 阻塞等待，使用默认超时时间（30秒）
- **使用场景**: 关键业务操作，用户期望等待的场景  
- **适用于**: 购买商品、支付处理、账户操作

### 2. `TryLock(ctx, key)` - 非阻塞（立即返回）
```go
unlock, err := locker.TryLock(ctx, "user123")
if unlock == nil {
    // 未获取到锁，但不是错误
    return
}
```
- **行为**: 立即返回，不等待
- **使用场景**: 可选操作，性能敏感的场景
- **适用于**: 点赞、评论、统计、缓存更新

### 3. `LockWithTimeout(ctx, key, timeout)` - 阻塞式（自定义超时）
```go
unlock, err := locker.LockWithTimeout(ctx, "user123", 60*time.Second)
```
- **行为**: 阻塞等待，使用自定义超时时间
- **使用场景**: 需要特殊超时设置的场景
- **适用于**: VIP服务、长时间操作、特殊业务需求

## 📊 行为对比表

| 方法 | 阻塞性 | 超时时间 | 返回时机 | 适用场景 |
|------|--------|----------|----------|----------|
| `Lock` | ✅ 阻塞 | 默认30秒 | 获取到锁或超时 | 关键业务操作 |
| `TryLock` | ❌ 非阻塞 | 无超时 | 立即返回 | 可选操作 |
| `LockWithTimeout` | ✅ 阻塞 | 自定义 | 获取到锁或超时 | 特殊超时需求 |

## 🎯 使用建议

### ✅ 推荐使用场景

**Lock（阻塞式）**
```go
// 购买商品 - 用户期望等待
unlock, err := locker.Lock(ctx, fmt.Sprintf("buy:%s", userID))
if err != nil {
    return fmt.Errorf("系统繁忙，请稍后重试")
}
defer unlock(ctx)
```

**TryLock（非阻塞）**
```go
// 点赞操作 - 立即反馈
unlock, err := locker.TryLock(ctx, fmt.Sprintf("like:%s", userID))
if unlock == nil {
    return fmt.Errorf("点赞太频繁，请稍后再试")
}
defer unlock(ctx)
```

**LockWithTimeout（自定义超时）**
```go
// VIP购买 - 更长等待时间
unlock, err := locker.LockWithTimeout(ctx, fmt.Sprintf("vip:%s", userID), 60*time.Second)
if err != nil {
    return fmt.Errorf("VIP服务繁忙，请稍后重试")
}
defer unlock(ctx)
```

## 🔄 迁移指南

如果您之前使用的是旧版本的非阻塞 `Lock`：

```go
// 旧版本（非阻塞）
unlock, err := locker.Lock(ctx, key)
if err != nil {
    // 立即失败
    return err
}

// 新版本 - 选择合适的方法：

// 1. 如果希望等待 → 使用新的 Lock（阻塞式）
unlock, err := locker.Lock(ctx, key)

// 2. 如果希望立即返回 → 使用 TryLock
unlock, err := locker.TryLock(ctx, key)
if unlock == nil {
    // 未获取到锁
    return 
}

// 3. 如果需要自定义超时 → 使用 LockWithTimeout
unlock, err := locker.LockWithTimeout(ctx, key, 10*time.Second)
```

## 💡 最佳实践

1. **金钱相关操作** → 使用 `Lock` 或 `LockWithTimeout`
2. **用户体验关键操作** → 使用 `Lock`
3. **可选功能** → 使用 `TryLock`
4. **高频操作** → 使用 `TryLock`
5. **特殊超时需求** → 使用 `LockWithTimeout`

记住：**宁可让用户等待几秒钟，也不要让用户收到莫名其妙的失败信息！** 🎯