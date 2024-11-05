package auth

import (
	"crypto/rsa" // 用于RSA加密/解密
	"net/http"   // HTTP相关功能
	"strings"    // 字符串操作工具

	// 引入Casbin相关包，Casbin用于权限控制
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/persist"

	// JWT相关库，用于处理JSON Web Token
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/dgrijalva/jwt-go/test"

	// Micro框架相关包
	"github.com/micro/cli/v2"
	"github.com/micro/go-micro/v2/errors"
	"github.com/micro/micro/v2/plugin"
)

const id = "micro.x-gateway.auth" // 插件的标识符

var adapters map[string]persist.Adapter // 存储注册的Casbin适配器
var watchers map[string]persist.Watcher // 存储注册的Casbin观察者

// 初始化函数，初始化Casbin的适配器和观察者映射
func init() {
	adapters = make(map[string]persist.Adapter)
	watchers = make(map[string]persist.Watcher)
}

// RegisterAdapter 注册认证插件的适配器
func RegisterAdapter(key string, a persist.Adapter) {
	adapters[key] = a
}

// RegisterWatcher 注册认证插件的观察者
func RegisterWatcher(key string, w persist.Watcher) {
	watchers[key] = w
}

// Auth 结构体表示认证插件
type Auth struct {
	options  Options          // 插件配置选项
	enforcer *casbin.Enforcer // Casbin的权限控制器
	pubUser  string           // 公共用户的用户名
	pubKey   *rsa.PublicKey   // 公共密钥，用于JWT验证
}

// keyFunc 用于解析JWT中的公钥
func (a *Auth) keyFunc(*jwt.Token) (interface{}, error) {
	return a.pubKey, nil
}

// handler 中间件函数，处理认证和授权逻辑
func (a *Auth) handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 跳过认证的请求
		if a.options.skipperFunc(r) {
			h.ServeHTTP(w, r)
			return
		}

		path := r.URL.Path
		method := r.Method

		// 处理公共接口
		if a.pubUser != "" {
			// 检查公共用户是否有权限访问该路径和方法
			allowed, err := a.enforcer.Enforce(a.pubUser, path, method)
			if err != nil {
				// 处理错误并返回响应
				a.options.responseHandler(w, r, errors.InternalServerError(id, err.Error()))
				return
			} else if allowed {
				// 如果允许访问，继续处理请求
				h.ServeHTTP(w, r)
				return
			}
		}

		// JWT验证
		token, err := request.ParseFromRequest(
			r,
			request.AuthorizationHeaderExtractor, // 从Authorization头提取JWT
			a.keyFunc,                            // 使用公钥进行验证
			request.WithClaims(a.options.claims), // 使用自定义的Claims类型
		)

		// 处理JWT解析失败的情况
		if err != nil || token == nil {
			a.options.responseHandler(w, r, errors.Unauthorized(id, "JWT token parse token=nil or with error: %v", err.Error()))
			return
		}

		// 验证JWT的有效性
		if !token.Valid {
			a.options.responseHandler(w, r, errors.Unauthorized(id, "JWT token invalid"))
			return
		}

		// 使用Casbin进行访问控制
		if allowed, err := a.enforcer.Enforce(a.options.claimsSubjectFunc(token.Claims), path, method); err != nil {
			a.options.responseHandler(w, r, errors.InternalServerError(id, err.Error()))
			return
		} else if !allowed {
			// 如果Casbin控制不允许访问，返回Forbidden错误
			a.options.responseHandler(w, r, errors.Forbidden(id, "Casbin access control not allowed"))
			return
		}

		// 在响应头中添加信息
		a.options.headerFunc(r, token.Claims)

		// 请求通过认证和授权后，继续执行原始的HTTP处理逻辑
		h.ServeHTTP(w, r)
	})
}

// NewPlugin 创建一个新的认证插件实例
func NewPlugin(opts ...Option) plugin.Plugin {
	options := newOptions(opts...) // 解析传入的配置项

	a := &Auth{
		options: options, // 配置插件选项
	}

	var egAdapter, egWatcher []string
	for k := range adapters {
		egAdapter = append(egAdapter, k) // 将所有注册的适配器的键名添加到列表中
	}
	for k := range watchers {
		egWatcher = append(egWatcher, k) // 将所有注册的观察者的键名添加到列表中
	}

	// 创建并返回一个插件实例
	return plugin.NewPlugin(
		plugin.WithName("Auth"), // 设置插件名称为 "Auth"
		plugin.WithFlag(
			// 添加配置参数，允许通过CLI命令行传入配置
			&cli.StringFlag{
				Name:  "auth_pub_key",
				Usage: "Auth public key file",
				Value: "./conf/auth_key.pub", // 默认公钥文件路径
			},
			&cli.StringFlag{
				Name:  "casbin_model",
				Usage: "Casbin model config file",
				Value: "./conf/casbin_model.conf", // 默认Casbin模型配置文件路径
			},
			&cli.StringFlag{
				Name:  "casbin_adapter",
				Usage: "Casbin registered adapter {" + strings.Join(egAdapter, ", ") + "}",
				Value: "default", // 默认适配器
			},
			&cli.StringFlag{
				Name:  "casbin_watcher",
				Usage: "Casbin registered watcher {" + strings.Join(egWatcher, ", ") + "}",
				Value: "default", // 默认观察者
			},
			&cli.StringFlag{
				Name:  "casbin_public_user",
				Usage: "Casbin public user",
				Value: "public", // 默认公共用户
			},
		),
		plugin.WithHandler(a.handler), // 设置处理HTTP请求的handler
		plugin.WithInit(func(ctx *cli.Context) error {
			// 从CLI上下文中获取配置项
			a.pubUser = ctx.String("casbin_public_user")     // 公共用户
			pubKey := ctx.String("auth_pub_key")             // 公钥路径
			a.pubKey = test.LoadRSAPublicKeyFromDisk(pubKey) // 加载公钥

			// Casbin配置
			model := ctx.String("casbin_model")
			adapter := ctx.String("casbin_adapter")
			watcher := ctx.String("casbin_watcher")

			// 初始化Casbin的Enforcer实例
			var e *casbin.Enforcer
			if a, ok := adapters[adapter]; ok {
				var err error
				e, err = casbin.NewEnforcer(model, a) // 创建Casbin的Enforcer实例
				if err != nil {
					return err
				}
			} else {
				return errors.New(id, "adapter not exist", http.StatusInternalServerError)
			}

			// 加载Casbin的权限策略
			e.LoadPolicy()

			// 设置观察者
			if w, ok := watchers[watcher]; ok {
				e.SetWatcher(w) // 设置Casbin的Watcher
			}

			a.enforcer = e // 将Enforcer赋值给Auth实例

			return nil
		}),
	)
}
