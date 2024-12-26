package rules

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
)

// Rule 定义了一个检测规则
type Rule struct {
	ID          string   `json:"id"`           // 规则ID
	Name        string   `json:"name"`         // 规则名称
	Description string   `json:"description"`  // 规则描述
	Category    string   `json:"category"`     // 规则类别（进程、网络、注册表等）
	Severity    string   `json:"severity"`     // 严重程度（高、中、低）
	Conditions  []string `json:"conditions"`   // 条件列表
	Action      string   `json:"action"`       // 检测到时的动作
	Enabled     bool     `json:"enabled"`      // 是否启用
}

// RuleEngine 规则引擎
type RuleEngine struct {
	Rules []*Rule
}

// NewRuleEngine 创建新的规则引擎
func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		Rules: make([]*Rule, 0),
	}
}

// LoadRulesFromFile 从文件加载规则
func (re *RuleEngine) LoadRulesFromFile(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("读取规则文件失败: %v", err)
	}

	var rulesWrapper struct {
		Rules []*Rule `json:"rules"`
	}
	if err := json.Unmarshal(data, &rulesWrapper); err != nil {
		return fmt.Errorf("解析规则文件失败: %v", err)
	}

	re.Rules = append(re.Rules, rulesWrapper.Rules...)
	return nil
}

// SaveRulesToFile 保存规则到文件
func (re *RuleEngine) SaveRulesToFile(filename string) error {
	data, err := json.MarshalIndent(re.Rules, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化规则失败: %v", err)
	}

	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("保存规则文件失败: %v", err)
	}

	return nil
}

// AddRule 添加新规则
func (re *RuleEngine) AddRule(rule *Rule) error {
	// 检查规则ID是否已存在
	for _, r := range re.Rules {
		if r.ID == rule.ID {
			return fmt.Errorf("规则ID已存在: %s", rule.ID)
		}
	}

	re.Rules = append(re.Rules, rule)
	return nil
}

// RemoveRule 删除规则
func (re *RuleEngine) RemoveRule(ruleID string) error {
	for i, rule := range re.Rules {
		if rule.ID == ruleID {
			re.Rules = append(re.Rules[:i], re.Rules[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("规则不存在: %s", ruleID)
}

// GetRule 获取规则
func (re *RuleEngine) GetRule(ruleID string) (*Rule, error) {
	for _, rule := range re.Rules {
		if rule.ID == ruleID {
			return rule, nil
		}
	}
	return nil, fmt.Errorf("规则不存在: %s", ruleID)
}

// EvaluateRule 评估单个规则
func (re *RuleEngine) EvaluateRule(rule *Rule, data map[string]interface{}) bool {
	if !rule.Enabled {
		return false
	}

	for _, condition := range rule.Conditions {
		if !evaluateCondition(condition, data) {
			return false
		}
	}
	return true
}

// evaluateCondition 评估单个条件
func evaluateCondition(condition string, data map[string]interface{}) bool {
	// 解析条件
	parts := strings.Split(condition, " ")
	if len(parts) < 3 {
		return false
	}

	field := parts[0]
	operator := parts[1]
	value := strings.Join(parts[2:], " ")

	// 获取字段值
	fieldValue, ok := data[field]
	if !ok {
		return false
	}

	// 根据操作符评估条件
	switch operator {
	case "==":
		return fmt.Sprintf("%v", fieldValue) == value
	case "!=":
		return fmt.Sprintf("%v", fieldValue) != value
	case ">":
		return compareValues(fieldValue, value) > 0
	case "<":
		return compareValues(fieldValue, value) < 0
	case ">=":
		return compareValues(fieldValue, value) >= 0
	case "<=":
		return compareValues(fieldValue, value) <= 0
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", fieldValue), value)
	case "matches":
		re, err := regexp.Compile(value)
		if err != nil {
			return false
		}
		return re.MatchString(fmt.Sprintf("%v", fieldValue))
	default:
		return false
	}
}

// compareValues 比较两个值
func compareValues(a, b interface{}) int {
	// 转换为字符串进行比较
	aStr := fmt.Sprintf("%v", a)
	bStr := fmt.Sprintf("%v", b)

	// 尝试转换为数字比较
	var aFloat, bFloat float64
	aFloat, errA := parseFloat(aStr)
	bFloat, errB := parseFloat(bStr)
	if errA == nil && errB == nil {
		if aFloat < bFloat {
			return -1
		}
		if aFloat > bFloat {
			return 1
		}
		return 0
	}

	// 字符串比较
	return strings.Compare(aStr, bStr)
}

// parseFloat 尝试将字符串解析为浮点数
func parseFloat(s string) (float64, error) {
	// 移除可能的单位后缀
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)

	// 处理常见的单位
	multiplier := 1.0
	if strings.HasSuffix(s, "kb") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "kb")
	} else if strings.HasSuffix(s, "mb") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "mb")
	} else if strings.HasSuffix(s, "gb") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "gb")
	} else if strings.HasSuffix(s, "tb") {
		multiplier = 1024 * 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "tb")
	}

	value, err := parseFloatBase(s)
	if err != nil {
		return 0, err
	}

	return value * multiplier, nil
}

// parseFloatBase 基础浮点数解析
func parseFloatBase(s string) (float64, error) {
	// 处理百分比
	if strings.HasSuffix(s, "%") {
		s = strings.TrimSuffix(s, "%")
		value, err := parseFloatBase(s)
		if err != nil {
			return 0, err
		}
		return value / 100.0, nil
	}

	var value float64
	_, err := fmt.Sscanf(s, "%f", &value)
	return value, err
}
