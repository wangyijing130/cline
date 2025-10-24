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

// IsAccountAuthenticated 检查是否已通过账号认证
func IsAccountAuthenticated() bool {
    return CurrentAuthInfo != nil && CurrentAuthInfo.Token != ""
}

// ConfigureTuringCoder 自动配置TuringCoder提供商
// 使用预设的内网OpenAI配置，需要先通过账号认证
func ConfigureTuringCoder(ctx context.Context, manager *task.Manager) error {
    // 检查是否已通过账号认证
    if !IsAccountAuthenticated() {
        return fmt.Errorf("使用TuringCoder需要先通过NT Account或Platform account认证")
    }
    
    // 检查token和用户账号是否有效（必填项）
    if CurrentAuthInfo.Token == "" {
        return fmt.Errorf("登录Token不能为空，请重新登录")
    }
    
    if CurrentAuthInfo.UserAcct == "" {
        return fmt.Errorf("用户账号不能为空，请重新登录")
    }
    
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
    
    // 将登录token和用户账号添加到请求头中
    apiConfig.OpenAiHeaders = map[string]string{
        "loginToken": CurrentAuthInfo.Token,
        "userAcct": CurrentAuthInfo.UserAcct,
    }
    
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
        "openAiHeaders",
    }
    
    // 应用配置
    request := &cline.UpdateApiConfigurationPartialRequest{
        ApiConfiguration: apiConfig,
        UpdateMask: &fieldmaskpb.FieldMask{Paths: fieldPaths},
    }
    
// 应用配置
    if _, err := manager.GetClient().Models.UpdateApiConfigurationPartial(ctx, request); err != nil {
        return fmt.Errorf("配置TuringCoder失败: %w", err)
    }

    // 完成配置
    fmt.Println("✓ TuringCoder提供商配置成功！")
    fmt.Println("  模型: gpt-5")
    fmt.Println("  基础URL: 已配置为内网地址")
    fmt.Println("  认证信息: 已将登录Token和用户账号添加到请求头")

    // 关键修复：配置成功后，设置 welcomeViewCompleted 状态，确保 CLI 能正确识别认证完成
    if err := setWelcomeViewCompleted(ctx, manager); err != nil {
        fmt.Printf("Warning: Failed to mark welcome view as completed: %v\n", err)
    }

    return nil
}
