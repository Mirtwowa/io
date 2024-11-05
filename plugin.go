package main

import (
	"io"
	"net/http"
	"time"

	// 引入Casbin的文件适配器，用于权限控制
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	// 引入网关的API接口包
	"github.com/micro-in-cn/x-gateway/api"
	// 引入网关的认证插件包
	"github.com/micro-in-cn/x-gateway/plugin/auth"
	// 引入网关的度量（metrics）插件包
	"github.com/micro-in-cn/x-gateway/plugin/metrics"
	// 引入网关的OpenTracing插件包
	"github.com/micro-in-cn/x-gateway/plugin/opentracing"
	// 引入网关的追踪（tracer）插件包
	tracer "github.com/micro-in-cn/x-gateway/plugin/trace"
	// 引入响应工具包
	"github.com/micro-in-cn/x-gateway/utils/response"
	// 引入micro日志包
	"github.com/micro/go-micro/v2/util/log"
	// 引入限流工具包
	"golang.org/x/time/rate"
)

var (
	apiTracerCloser io.Closer // 定义一个Closer类型的变量，用于追踪关闭器
)

func cleanWork() error {
	// 关闭apiTracerCloser（Jaeger追踪的关闭器）
	apiTracerCloser.Close()

	return nil
}

// 插件注册
func init() {
	// 初始化认证插件
	initAuth()
	// 初始化度量插件
	initMetrics()
	// 初始化追踪插件
	initTrace()
}

// 初始化认证插件
func initAuth() {
	// 创建一个Casbin文件适配器，加载权限策略
	casb := fileadapter.NewAdapter("./conf/casbin_policy.csv")
	// 注册适配器为默认适配器
	auth.RegisterAdapter("default", casb)

	// 创建认证插件，配置响应处理和请求跳过判断函数
	authPlugin := auth.NewPlugin(
		// 设置响应处理器为默认响应处理器
		auth.WithResponseHandler(response.DefaultResponseHandler),
		// 设置跳过函数，所有请求都不跳过认证（此处返回false，表示不跳过）
		auth.WithSkipperFunc(func(r *http.Request) bool {
			return false
		}),
	)
	// 注册认证插件到API中
	api.Register(authPlugin)
}

// 初始化度量插件
func initMetrics() {
	// 注册度量插件，设置命名空间和跳过函数
	api.Register(metrics.NewPlugin(
		// 设置命名空间为"xgateway"，仅支持字母、数字和下划线、冒号
		metrics.WithNamespace("xgateway"),
		// 设置子系统为空字符串
		metrics.WithSubsystem(""),
		// 设置跳过函数，所有请求都不跳过度量（此处返回false，表示不跳过）
		metrics.WithSkipperFunc(func(r *http.Request) bool {
			return false
		}),
	))
}

// 初始化追踪插件
func initTrace() {
	// 创建Jaeger追踪器，配置服务名称和服务器地址
	apiTracer, apiCloser, err := tracer.NewJaegerTracer("go.micro.x-gateway", "127.0.0.1:6831")
	if err != nil {
		// 如果创建Jaeger追踪器失败，打印错误日志
		log.Fatalf("opentracing tracer create error:%v", err)
	}
	// 创建一个限流器，设置每秒100次的限流频率，允许最多10个事件
	limiter := rate.NewLimiter(rate.Every(time.Millisecond*100), 10)
	// 将追踪关闭器保存在全局变量中，以便后续关闭
	apiTracerCloser = apiCloser
	// 注册OpenTracing插件，设置追踪器和跳过函数
	api.Register(opentracing.NewPlugin(
		// 设置使用的Jaeger追踪器
		opentracing.WithTracer(apiTracer),
		// 设置跳过函数，根据限流器控制是否跳过追踪
		opentracing.WithSkipperFunc(func(r *http.Request) bool {
			// 如果限流器不允许，跳过追踪
			if !limiter.Allow() {
				return true
			}
			return false
		}),
	))
}
