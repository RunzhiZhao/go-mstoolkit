package lock

import (
	"context"
	"time"
)

type UnLockFunc func(ctx context.Context) error

type Locker interface {
	// Lock 获取锁（阻塞式，使用默认超时时间）
	Lock(ctx context.Context, key string) (UnLockFunc, error)
	// TryLock 尝试获取锁（非阻塞，立即返回）
	TryLock(ctx context.Context, key string) (UnLockFunc, error)
	// LockWithTimeout 在超时时间内等待获取锁（阻塞式）
	LockWithTimeout(ctx context.Context, key string, timeout time.Duration) (UnLockFunc, error)
}
