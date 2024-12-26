package main

import (
	"flag"
	"log"
	"os"
	"time"

	"ProtectorPro/pkg/analyzer"
	"ProtectorPro/pkg/rules"
)

var (
	outputDir = flag.String("output", "output", "输出目录路径")
)

func main() {
	flag.Parse()

	// 创建输出目录
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("创建输出目录失败: %v", err)
	}

	log.Printf("开始执行系统安全评估...")
	log.Printf("输出目录: %s", *outputDir)

	// 加载规则引擎
	ruleEngine := rules.NewRuleEngine()
	if err := ruleEngine.LoadRulesFromFile("rules/default_rules.json"); err != nil {
		log.Printf("加载规则文件失败: %v", err)
	} else {
		log.Printf("成功加载规则文件")
	}

	// 创建安全分析器
	securityAnalyzer := analyzer.NewAnalyzer(ruleEngine)

	// 获取当前时间戳
	timestamp := time.Now().Format("20060102_150405")

	// 进行系统安全评估
	log.Println("开始系统安全评估...")

	// 1. 系统信息分析
	log.Println("1. 分析系统信息...")
	if err := securityAnalyzer.AnalyzeSystem(*outputDir, timestamp); err != nil {
		log.Printf("系统信息分析失败: %v", err)
	}

	// 2. 进程分析
	log.Println("2. 分析进程信息...")
	if err := securityAnalyzer.AnalyzeProcesses(*outputDir, timestamp); err != nil {
		log.Printf("进程分析失败: %v", err)
	}

	// 3. 网络连接分析
	log.Println("3. 分析网络连接...")
	if err := securityAnalyzer.AnalyzeNetwork(*outputDir, timestamp); err != nil {
		log.Printf("网络分析失败: %v", err)
	}

	// 4. 注册表分析
	log.Println("4. 分析注册表...")
	if err := securityAnalyzer.AnalyzeRegistry(*outputDir, timestamp); err != nil {
		log.Printf("注册表分析失败: %v", err)
	}

	// 5. 事件日志分析
	log.Println("5. 分析事件日志...")
	if err := securityAnalyzer.AnalyzeEventLogs(*outputDir, timestamp); err != nil {
		log.Printf("事件日志分析失败: %v", err)
	}

	log.Println("系统安全评估完成.")
}
