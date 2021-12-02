package password

import (
	"fmt"
	"testing"
)

// 测试密码的创建和校验
func TestCheckPassword(t *testing.T) {
	result := EncodeDefault("root")
	fmt.Println(result)
	fmt.Println(VerifyDefault("root", result))
}
