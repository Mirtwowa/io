package api

import (
	"fmt"

	"github.com/micro/micro/v2/plugin"
)

var (
	defaultManager = plugin.NewManager() // 创建一个新的插件管理器实例
)

// Plugins lists the api plugins
func Plugins() []plugin.Plugin { // 定义一个函数 Plugins，返回当前注册的插件列表
	return defaultManager.Plugins() // 调用 defaultManager 的 Plugins 方法，获取已注册的插件列表
}

// Register registers an api plugin
func Register(pl plugin.Plugin) error { // 定义一个函数 Register，接受一个插件作为参数并返回错误
	if plugin.IsRegistered(pl) { // 检查插件是否已经被注册
		return fmt.Errorf("%s registered globally", pl.String()) // 如果已经注册，返回一个错误，提示插件已经注册
	}
	return defaultManager.Register(pl) // 如果未注册，则调用 defaultManager 的 Register 方法注册插件
}
