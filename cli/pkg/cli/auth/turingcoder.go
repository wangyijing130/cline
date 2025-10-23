package auth

import (
    "context"
    "fmt"
    
    "github.com/cline/cli/pkg/cli/task"
    "github.com/cline/grpc-go/cline"
    "google.golang.org/protobuf/proto"
    "google.golang.org/protobuf/types/known/fieldmaskpb"
)

// TuringCoder预设配置常量
const (
    TuringCoderBaseURL = "https://codegpt-copilot.asiainfo.com.cn/api/prompt/commander/chat?t=1"
    TuringCoderAPIKey  = "TuringCoder"
    TuringCoderModelID = "gpt-5"
)

// IsTuringCoderProvider 检查所选提供商是否为TuringCoder
func IsTuringCoderProvider(provider cline.ApiProvider, providerName string) bool {
    return providerName == "TuringCoder" && provider == cline.ApiProvider_OPENAI
}

// ConfigureTuringCoder 自动配置TuringCoder提供商
// 使用预设的内网OpenAI配置，无需用户输入
func ConfigureTuringCoder(ctx context.Context, manager *task.Manager) error {
    fmt.Println("配置TuringCoder内置提供商...")
    
    // 创建自定义配置
    apiConfig := &cline.ModelsApiConfiguration{}
    
    // 设置基础URL (OpenAI Base URL字段)
    apiConfig.OpenAiBaseUrl = proto.String(TuringCoderBaseURL)
    
    // 设置API密钥
    apiConfig.OpenAiApiKey = proto.String(TuringCoderAPIKey)
    
    // 设置模型ID
    apiConfig.PlanModeApiModelId = proto.String(TuringCoderModelID)
    apiConfig.ActModeApiModelId = proto.String(TuringCoderModelID)
    
    // 设置为活动提供商
    provider := cline.ApiProvider_OPENAI
    apiConfig.PlanModeApiProvider = &provider
    apiConfig.ActModeApiProvider = &provider
    
    // 添加TuringCoder特定的Model ID字段
    apiConfig.PlanModeOpenAiModelId = proto.String(TuringCoderModelID)
    apiConfig.ActModeOpenAiModelId = proto.String(TuringCoderModelID)
    
    // 构建字段掩码
    fieldPaths := []string{
        "openAiBaseUrl",
        "openAiApiKey",
        "planModeApiModelId",
        "actModeApiModelId",
        "planModeApiProvider",
        "actModeApiProvider",
        "planModeOpenAiModelId",
        "actModeOpenAiModelId",
    }
    
    // 应用配置
    request := &cline.UpdateApiConfigurationPartialRequest{
        ApiConfiguration: apiConfig,
        UpdateMask: &fieldmaskpb.FieldMask{Paths: fieldPaths},
    }
    
    if _, err := manager.GetClient().Models.UpdateApiConfigurationPartial(ctx, request); err != nil {
        return fmt.Errorf("配置TuringCoder失败: %w", err)
    }
    
    // 完成配置
    fmt.Println("✓ TuringCoder提供商配置成功！")
    fmt.Println("  模型: gpt-5")
    fmt.Println("  基础URL: 已配置为内网地址")
    
    return nil
}
