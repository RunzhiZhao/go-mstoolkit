package lock

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var (
	ErrLockNotAcquired = errors.New("failed to acquire lock")
	ErrLockTimeout     = errors.New("lock timeout")
	ErrNotLockOwner    = errors.New("not the lock owner")
)

var (
	defaultTTL     = 5 * time.Second
	defaultTimeout = 30 * time.Second
)

// 解锁的 Lua 脚本，确保只删除自己持有的锁
const unlockScript = `
if redis.call("get",KEYS[1]) == ARGV[1] then
    return redis.call("del",KEYS[1])
else
    return 0
end`

type redisLocker struct {
	rd             *redis.Client
	keyPrefix      string
	ttl            time.Duration
	defaultTimeout time.Duration // 默认等待锁的超时时间
}

type RedisLockerOption func(l *redisLocker)

func WithKeyPrefix(keyPrefix string) RedisLockerOption {
	return func(l *redisLocker) {
		l.keyPrefix = keyPrefix
	}
}

func WithTTL(ttl time.Duration) RedisLockerOption {
	return func(l *redisLocker) {
		l.ttl = ttl
	}
}

func WithDefaultTimeout(timeout time.Duration) RedisLockerOption {
	return func(l *redisLocker) {
		l.defaultTimeout = timeout
	}
}

func NewRedisLocker(rd *redis.Client, opts ...RedisLockerOption) Locker {
	l := &redisLocker{
		rd:             rd,
		keyPrefix:      "",
		ttl:            defaultTTL,
		defaultTimeout: defaultTimeout, // 默认等待30秒
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// 构建完整的key
func (l *redisLocker) buildFullKey(key string) string {
	if l.keyPrefix == "" {
		return key
	}
	return fmt.Sprintf("%s:%s", l.keyPrefix, key)
}

// Lock 获取锁(阻塞式，使用默认超时时间)
func (l *redisLocker) Lock(ctx context.Context, key string) (UnLockFunc, error) {
	return l.LockWithTimeout(ctx, key, l.defaultTimeout)
}

// lockNonBlocking 非阻塞获取锁（内部方法）
func (l *redisLocker) lockNonBlocking(ctx context.Context, key string) (UnLockFunc, error) {
	fullKey := l.buildFullKey(key)
	// 生成唯一的锁标识
	lockValue := uuid.New().String()

	// 使用SET命令的NX选项实现原子性加锁
	result := l.rd.SetNX(ctx, fullKey, lockValue, l.ttl)
	if result.Err() != nil {
		return nil, result.Err()
	}

	if !result.Val() {
		return nil, ErrLockNotAcquired
	}

	// 返回解锁函数，使用闭包保存锁的值
	return func(ctx context.Context) error {
		return l.unlock(ctx, fullKey, lockValue)
	}, nil
}

// TryLock 尝试获取锁(非阻塞)
func (l *redisLocker) TryLock(ctx context.Context, key string) (UnLockFunc, error) {
	unLockFunc, err := l.lockNonBlocking(ctx, key)
	if err != nil {
		if errors.Is(err, ErrLockNotAcquired) {
			return nil, nil // 未获取到锁，但不是错误
		}
		return nil, err
	}
	return unLockFunc, nil
}

// LockWithTimeout 在超时时间内等待获取锁（阻塞式）
func (l *redisLocker) LockWithTimeout(ctx context.Context, key string, timeout time.Duration) (UnLockFunc, error) {
	deadline := time.Now().Add(timeout)
	retryInterval := 10 * time.Millisecond // 重试间隔

	for time.Now().Before(deadline) {
		// 检查 context 是否已取消
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// 尝试获取锁
		unlockFunc, err := l.lockNonBlocking(ctx, key)
		if err == nil {
			return unlockFunc, nil // 成功获取锁
		}

		// 如果不是"锁被占用"的错误，直接返回
		if !errors.Is(err, ErrLockNotAcquired) {
			return nil, err
		}

		// 等待一段时间后重试
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryInterval):
			// 动态调整重试间隔，避免过于频繁的请求
			if retryInterval < 100*time.Millisecond {
				retryInterval *= 2
			}
		}
	}
	return nil, ErrLockTimeout
}

// unlock 内部解锁方法，使用 Lua 脚本确保原子性
func (l *redisLocker) unlock(ctx context.Context, fullKey, lockValue string) error {
	result := l.rd.Eval(ctx, unlockScript, []string{fullKey}, lockValue)
	if result.Err() != nil {
		return result.Err()
	}

	// 检查脚本执行结果
	if result.Val().(int64) == 0 {
		return ErrNotLockOwner
	}

	return nil
}
