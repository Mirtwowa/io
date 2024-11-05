// Package api is an API Gateway
package api

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-acme/lego/v3/providers/dns/cloudflare"
	"github.com/gorilla/mux"
	"github.com/micro-in-cn/x-gateway/internal/handler"
	"github.com/micro-in-cn/x-gateway/internal/helper"
	"github.com/micro-in-cn/x-gateway/internal/stats"
	"github.com/micro/cli/v2"
	"github.com/micro/go-micro/v2"
	ahandler "github.com/micro/go-micro/v2/api/handler"
	aapi "github.com/micro/go-micro/v2/api/handler/api"
	"github.com/micro/go-micro/v2/api/handler/event"
	ahttp "github.com/micro/go-micro/v2/api/handler/http"
	arpc "github.com/micro/go-micro/v2/api/handler/rpc"
	"github.com/micro/go-micro/v2/api/handler/web"
	"github.com/micro/go-micro/v2/api/resolver"
	"github.com/micro/go-micro/v2/api/resolver/grpc"
	"github.com/micro/go-micro/v2/api/resolver/host"
	rrmicro "github.com/micro/go-micro/v2/api/resolver/micro"
	"github.com/micro/go-micro/v2/api/resolver/path"
	"github.com/micro/go-micro/v2/api/router"
	regRouter "github.com/micro/go-micro/v2/api/router/registry"
	"github.com/micro/go-micro/v2/api/server"
	"github.com/micro/go-micro/v2/api/server/acme"
	"github.com/micro/go-micro/v2/api/server/acme/autocert"
	"github.com/micro/go-micro/v2/api/server/acme/certmagic"
	httpapi "github.com/micro/go-micro/v2/api/server/http"
	cfstore "github.com/micro/go-micro/v2/store/cloudflare"
	"github.com/micro/go-micro/v2/sync/lock/memory"
	"github.com/micro/go-micro/v2/util/log"
	"github.com/micro/micro/v2/plugin"
)

// basic vars
var (
	Name                  = "go.micro.apigateway"        // API 网关的默认名称
	Address               = ":8080"                      // 默认监听地址
	Handler               = "meta"                       // 默认处理器类型
	Resolver              = "micro"                      // 默认解析器类型
	RPCPath               = "/rpc"                       // RPC 处理路径
	APIPath               = "/"                          // API 请求路径
	ProxyPath             = "/{service:[a-zA-Z0-9]+}"    // 代理路径
	Namespace             = "go.micro.api"               // 命名空间
	HeaderPrefix          = "X-Micro-"                   // HTTP 请求头前缀
	EnableRPC             = false                        // 是否启用 RPC
	ACMEProvider          = "autocert"                   // 默认的 ACME 提供者
	ACMEChallengeProvider = "cloudflare"                 // 默认的 ACME 挑战提供者
	ACMECA                = acme.LetsEncryptProductionCA // 默认的 ACME CA（Let's Encrypt）
)

func run(ctx *cli.Context, srvOpts ...micro.Option) {
	// 设置日志名称为 "api"
	log.Name("api")

	if len(ctx.String("server_name")) > 0 {
		Name = ctx.String("server_name") // 读取服务名称
	}
	if len(ctx.String("address")) > 0 {
		Address = ctx.String("address") // 读取监听地址
	}
	if len(ctx.String("handler")) > 0 {
		Handler = ctx.String("handler") // 读取处理器类型
	}
	if len(ctx.String("namespace")) > 0 {
		Namespace = ctx.String("namespace") //读取命名空间
	}
	if len(ctx.String("resolver")) > 0 {
		Resolver = ctx.String("resolver") //读取解析器类型
	}
	if len(ctx.String("enable_rpc")) > 0 {
		EnableRPC = ctx.Bool("enable_rpc") //检查是否启动rpc
	}
	if len(ctx.String("acme_provider")) > 0 {
		ACMEProvider = ctx.String("acme_provider") //读取ACME
	}

	// Init plugins
	for _, p := range Plugins() {
		p.Init(ctx)
	}

	// Init API
	var opts []server.Option
	//如果启用ACME
	if ctx.Bool("enable_acme") {
		hosts := helper.ACMEHosts(ctx)                  //获取 认证的主机列表
		opts = append(opts, server.EnableACME(true))    //启用ACME
		opts = append(opts, server.ACMEHosts(hosts...)) //设置ACME主机
		switch ACMEProvider {
		case "autocert":
			opts = append(opts, server.ACMEProvider(autocert.NewProvider()))
		case "certmagic":
			if ACMEChallengeProvider != "cloudflare" {
				log.Fatal("The only implemented DNS challenge provider is cloudflare")
			}
			apiToken, accountID := os.Getenv("CF_API_TOKEN"), os.Getenv("CF_ACCOUNT_ID")
			kvID := os.Getenv("KV_NAMESPACE_ID")
			if len(apiToken) == 0 || len(accountID) == 0 {
				log.Fatal("env variables CF_API_TOKEN and CF_ACCOUNT_ID must be set")
			}
			if len(kvID) == 0 {
				log.Fatal("env var KV_NAMESPACE_ID must be set to your cloudflare workers KV namespace ID")
			}

			cloudflareStore := cfstore.NewStore(
				cfstore.Token(apiToken),
				cfstore.Account(accountID),
				cfstore.Namespace(kvID),
			)
			storage := certmagic.NewStorage(
				memory.NewLock(),
				cloudflareStore,
			)
			config := cloudflare.NewDefaultConfig()
			config.AuthToken = apiToken
			config.ZoneToken = apiToken
			challengeProvider, err := cloudflare.NewDNSProviderConfig(config)
			if err != nil {
				log.Fatal(err.Error())
			}

			opts = append(opts,
				server.ACMEProvider(
					certmagic.NewProvider(
						acme.AcceptToS(true),
						acme.CA(ACMECA),
						acme.Cache(storage),
						acme.ChallengeProvider(challengeProvider),
						acme.OnDemand(false),
					),
				),
			)
		default:
			log.Fatalf("%s is not a valid ACME provider\n", ACMEProvider)
		}
	} else if ctx.Bool("enable_tls") {
		config, err := helper.TLSConfig(ctx)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		opts = append(opts, server.EnableTLS(true))
		opts = append(opts, server.TLSConfig(config))
	}

	// create the router
	var h http.Handler
	r := mux.NewRouter()
	h = r
	//如果启动统计信息收集
	if ctx.Bool("enable_stats") {
		st := stats.New()
		r.HandleFunc("/stats", st.StatsHandler)
		h = st.ServeHTTP(r)
		err := st.Start()
		if err != nil {
			return
		}
		defer func(st *stats.Stats) {
			err := st.Stop()
			if err != nil {

			}
		}(st)
	}
	//注册根路径
	// return version and list of services
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		helper.ServeCORS(w, r)

		if r.Method == "OPTIONS" {
			return
		}

		response := fmt.Sprintf(`{"version": "%s"}`, ctx.App.Version)
		w.Write([]byte(response))
	})

	// strip favicon.ico
	r.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {})

	srvOpts = append(srvOpts, micro.Name(Name)) // 设置微服务名称
	if i := time.Duration(ctx.Int("register_ttl")); i > 0 {
		srvOpts = append(srvOpts, micro.RegisterTTL(i*time.Second)) // 设置服务注册的 TTL（生存时间）
	}
	if i := time.Duration(ctx.Int("register_interval")); i > 0 {
		srvOpts = append(srvOpts, micro.RegisterInterval(i*time.Second)) // 设置服务注册的间隔时间
	}

	// initialise service
	service := micro.NewService(srvOpts...) // 使用 srvOpts 配置初始化服务

	// register rpc handler
	if EnableRPC { // 如果启用了 RPC
		log.Logf("Registering RPC Handler at %s", RPCPath) // 记录注册 RPC Handler 的日志
		r.HandleFunc(RPCPath, handler.RPC)                 // 注册 RPC 请求的处理器
	}

	// resolver options
	ropts := []resolver.Option{
		resolver.WithNamespace(Namespace), // 设置命名空间
		resolver.WithHandler(Handler),     // 设置请求处理器类型
	}

	// default resolver
	rr := rrmicro.NewResolver(ropts...) // 默认解析器是 rrmicro 解析器，使用配置的解析器选项

	// 根据配置选择不同的解析器
	switch Resolver {
	case "host":
		rr = host.NewResolver(ropts...) // 使用 host 解析器
	case "path":
		rr = path.NewResolver(ropts...) // 使用 path 解析器
	case "grpc":
		rr = grpc.NewResolver(ropts...) // 使用 gRPC 解析器
	}

	// 根据配置选择不同的请求处理器
	switch Handler {
	case "rpc":
		log.Logf("Registering API RPC Handler at %s", APIPath) // 记录注册 API RPC Handler 的日志
		rt := regRouter.NewRouter(
			router.WithNamespace(Namespace),                 // 设置命名空间
			router.WithHandler(arpc.Handler),                // 设置处理器类型为 RPC Handler
			router.WithResolver(rr),                         // 设置解析器
			router.WithRegistry(service.Options().Registry), // 设置注册中心
		)
		rp := arpc.NewHandler(
			ahandler.WithNamespace(Namespace), // 设置命名空间
			ahandler.WithRouter(rt),           // 设置路由
			ahandler.WithService(service),     // 设置服务
		)
		r.PathPrefix(APIPath).Handler(rp) // 注册 API 路径前缀的处理器
	case "api":
		log.Logf("Registering API Request Handler at %s", APIPath) // 记录注册 API Request Handler 的日志
		rt := regRouter.NewRouter(
			router.WithNamespace(Namespace),                 // 设置命名空间
			router.WithHandler(aapi.Handler),                // 设置处理器类型为 API Handler
			router.WithResolver(rr),                         // 设置解析器
			router.WithRegistry(service.Options().Registry), // 设置注册中心
		)
		ap := aapi.NewHandler(
			ahandler.WithNamespace(Namespace), // 设置命名空间
			ahandler.WithRouter(rt),           // 设置路由
			ahandler.WithService(service),     // 设置服务
		)
		r.PathPrefix(APIPath).Handler(ap) // 注册 API 路径前缀的处理器
	case "event":
		log.Logf("Registering API Event Handler at %s", APIPath) // 记录注册 API Event Handler 的日志
		rt := regRouter.NewRouter(
			router.WithNamespace(Namespace),                 // 设置命名空间
			router.WithHandler(event.Handler),               // 设置处理器类型为 Event Handler
			router.WithResolver(rr),                         // 设置解析器
			router.WithRegistry(service.Options().Registry), // 设置注册中心
		)
		ev := event.NewHandler(
			ahandler.WithNamespace(Namespace), // 设置命名空间
			ahandler.WithRouter(rt),           // 设置路由
			ahandler.WithService(service),     // 设置服务
		)
		r.PathPrefix(APIPath).Handler(ev) // 注册 API 路径前缀的处理器
	case "http", "proxy":
		log.Logf("Registering API HTTP Handler at %s", ProxyPath) // 记录注册 API HTTP Handler 的日志
		rt := regRouter.NewRouter(
			router.WithNamespace(Namespace),                 // 设置命名空间
			router.WithHandler(ahttp.Handler),               // 设置处理器类型为 HTTP Handler
			router.WithResolver(rr),                         // 设置解析器
			router.WithRegistry(service.Options().Registry), // 设置注册中心
		)
		ht := ahttp.NewHandler(
			ahandler.WithNamespace(Namespace), // 设置命名空间
			ahandler.WithRouter(rt),           // 设置路由
			ahandler.WithService(service),     // 设置服务
		)
		r.PathPrefix(ProxyPath).Handler(ht) // 注册代理路径前缀的处理器
	case "web":
		log.Logf("Registering API Web Handler at %s", APIPath) // 记录注册 API Web Handler 的日志
		rt := regRouter.NewRouter(
			router.WithNamespace(Namespace),                 // 设置命名空间
			router.WithHandler(web.Handler),                 // 设置处理器类型为 Web Handler
			router.WithResolver(rr),                         // 设置解析器
			router.WithRegistry(service.Options().Registry), // 设置注册中心
		)
		w := web.NewHandler(
			ahandler.WithNamespace(Namespace), // 设置命名空间
			ahandler.WithRouter(rt),           // 设置路由
			ahandler.WithService(service),     // 设置服务
		)
		r.PathPrefix(APIPath).Handler(w) // 注册 API 路径前缀的处理器
	default:
		log.Logf("Registering API Default Handler at %s", APIPath) // 记录注册默认 API Handler 的日志
		rt := regRouter.NewRouter(
			router.WithNamespace(Namespace),                 // 设置命名空间
			router.WithResolver(rr),                         // 设置解析器
			router.WithRegistry(service.Options().Registry), // 设置注册中心
		)
		r.PathPrefix(APIPath).Handler(handler.Meta(service, rt)) // 注册默认的 Meta 处理器
	}

	// reverse wrap handler
	plugins := append(Plugins(), plugin.Plugins()...) // 获取所有插件
	for i := len(plugins); i > 0; i-- {
		h = plugins[i-1].Handler()(h) // 反向包装处理器以嵌套调用插件的处理器
	}

	// create the server
	api := httpapi.NewServer(Address) // 创建 HTTP API 服务器
	api.Init(opts...)                 // 初始化服务器配置
	api.Handle("/", h)                // 绑定处理器

	// Start API
	if err := api.Start(); err != nil {
		log.Fatal(err) // 启动服务器失败时记录错误
	}

	// Run server
	if err := service.Run(); err != nil {
		log.Fatal(err) // 运行服务失败时记录错误
	}

	// Stop API
	if err := api.Stop(); err != nil {
		log.Fatal(err) // 停止服务器失败时记录错误
	}

}

// Commands for api
func Commands(options ...micro.Option) []*cli.Command { // 定义函数 Commands，用于生成 CLI 命令
	command := &cli.Command{ // 创建一个 cli.Command 结构体
		Name:  "api",             // 命令名称为 "api"
		Usage: "Run api-gateway", // 命令的用法描述
		Action: func(ctx *cli.Context) error { // 定义命令执行时的操作
			run(ctx, options...) // 调用 run 函数运行 API 网关
			return nil           // 返回 nil 表示操作成功
		},
		Flags: []cli.Flag{ // 定义命令行标志，用于配置 API 网关
			&cli.StringFlag{
				Name:    "address",                              // 标志名称为 "address"
				Usage:   "Set the api address e.g 0.0.0.0:8080", // 标志的用法描述
				EnvVars: []string{"MICRO_API_ADDRESS"},          // 可从环境变量 "MICRO_API_ADDRESS" 获取该标志的值
			},
			&cli.StringFlag{
				Name:    "handler",                                                                                               // 标志名称为 "handler"
				Usage:   "Specify the request handler to be used for mapping HTTP requests to services; {api, event, http, rpc}", // 说明支持的处理器类型
				EnvVars: []string{"MICRO_API_HANDLER"},                                                                           // 可从环境变量 "MICRO_API_HANDLER" 获取该标志的值
			},
			&cli.StringFlag{
				Name:    "namespace",                                              // 标志名称为 "namespace"
				Usage:   "Set the namespace used by the API e.g. com.example.api", // 用于设置 API 使用的命名空间
				EnvVars: []string{"MICRO_API_NAMESPACE"},                          // 可从环境变量 "MICRO_API_NAMESPACE" 获取该标志的值
			},
			&cli.StringFlag{
				Name:    "resolver",                                                     // 标志名称为 "resolver"
				Usage:   "Set the hostname resolver used by the API {host, path, grpc}", // 说明支持的主机名解析器类型
				EnvVars: []string{"MICRO_API_RESOLVER"},                                 // 可从环境变量 "MICRO_API_RESOLVER" 获取该标志的值
			},
			&cli.BoolFlag{
				Name:    "enable_rpc",                                // 标志名称为 "enable_rpc"
				Usage:   "Enable call the backend directly via /rpc", // 是否启用直接通过 /rpc 调用后端
				EnvVars: []string{"MICRO_API_ENABLE_RPC"},            // 可从环境变量 "MICRO_API_ENABLE_RPC" 获取该标志的值
			},
		},
	}

	for _, p := range Plugins() { // 遍历所有插件
		if cmds := p.Commands(); len(cmds) > 0 { // 如果插件有子命令
			command.Subcommands = append(command.Subcommands, cmds...) // 将子命令追加到 command 的子命令列表中
		}

		if flags := p.Flags(); len(flags) > 0 { // 如果插件有标志
			command.Flags = append(command.Flags, flags...) // 将标志追加到 command 的标志列表中
		}
	}

	return []*cli.Command{command} // 返回生成的命令列表（仅包含一个 "api" 命令）
}
