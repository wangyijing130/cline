package auth

import (
    "context"
    "crypto/md5"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/base64"
    "encoding/hex"
    "bytes"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "net/http"
    "os"
    "path/filepath"

    "github.com/charmbracelet/huh"
    "github.com/cline/cli/pkg/cli/display"
    "github.com/cline/cli/pkg/cli/global"
    "github.com/cline/cli/pkg/cli/task"
    "github.com/cline/grpc-go/cline"
)

// contextKey is a distinct type for context keys to avoid collisions
type contextKey string

const authInstanceAddressKey contextKey = "authInstanceAddress"

// AuthAction represents the type of authentication action
type AuthAction string


const (
    AuthActionClineLogin         AuthAction = "cline_login"
    AuthActionBYOSetup           AuthAction = "provider_setup"
    AuthActionChangeClineModel   AuthAction = "change_cline_model"
    AuthActionSelectOrganization AuthAction = "select_organization"
    AuthActionSelectProvider     AuthAction = "select_provider"
    AuthActionExit               AuthAction = "exit_wizard"
    AuthActionNTAccountLogin     AuthAction = "nt_account_login"
    AuthActionPlatformLogin      AuthAction = "platform_login"
)

//  Cline Auth Menu
//  Example Layout
//
//    ┃ Cline Account: <authenticated/not authenticated>
//    ┃ Active Provider: <provider name or none configured>
//    ┃ Active Model: <model name or none configured>
//    ┃
//    ┃ What would you like to do?
//    ┃   Change Cline model (only if authenticated)                - hidden if not authenticated
//    ┃   Authenticate with Cline account / Sign out of Cline        - changes based on auth status
//    ┃   Select active provider (Cline or BYO)                    - always shown. Used to switch between Cline and BYO providers
//    ┃   Configure BYO API providers                                - always shown. Launches provider setup wizard
//    ┃   Exit authorization wizard                                - always shown. Exits the auth menu

// RunAuthFlow is the entry point for the entire auth flow with instance management
// It spawns a fresh instance for auth operations and cleans it up when done
func RunAuthFlow(ctx context.Context, args []string) error {
    // 初始化认证状态（自动重新登录）
    if err := InitializeAuth(ctx); err != nil {
        verboseLog("初始化认证状态失败: %v", err)
        fmt.Println("初始化认证状态失败: %v", err)
    }

    // Spawn a fresh instance for auth operations
    instanceInfo, err := global.Clients.StartNewInstance(ctx)
    if err != nil {
        return fmt.Errorf("failed to start auth instance: %w", err)
    }

    // Cleanup when done (success, error, or panic)
    defer func() {
        verboseLog("Shutting down auth instance at %s", instanceInfo.Address)
        if err := global.KillInstanceByAddress(context.Background(), global.Clients.GetRegistry(), instanceInfo.Address); err != nil {
            verboseLog("Warning: Failed to kill auth instance: %v", err)
        }
    }()

    // Store instance address in context for all auth handlers to use
    authCtx := context.WithValue(ctx, authInstanceAddressKey, instanceInfo.Address)

    // Route to existing auth flow
    return HandleAuthCommand(authCtx, args)
}

// Main entry point for handling the `cline auth` command
// HandleAuthCommand routes the auth command based on the number of arguments
func HandleAuthCommand(ctx context.Context, args []string) error {

    // Check if flags are provided for quick setup
    if QuickProvider != "" || QuickAPIKey != "" || QuickModelID != "" || QuickBaseURL != "" {
        if QuickProvider == "" || QuickAPIKey == "" || QuickModelID == "" {
            return fmt.Errorf("quick setup requires --provider, --apikey, and --modelid flags. Use 'cline auth --help' for more information")
        }
        return QuickSetupFromFlags(ctx, QuickProvider, QuickAPIKey, QuickModelID, QuickBaseURL)
    }

    switch len(args) {
    case 0:
        // No args: Show uth wizard
        return HandleAuthMenuNoArgs(ctx)
    case 1, 2, 3, 4:
        fmt.Println("Invalid positional arguments. Correct usage:")
        fmt.Println("  cline auth --provider <provider> --apikey <key> --modelid <model> --baseurl <optional>")
        return nil
    default:
        return fmt.Errorf("too many arguments. Use flags for quick setup: --provider, --apikey, --modelid --baseurl(optional)")
    }
}

// getAuthInstanceAddress retrieves the auth instance address from context
// Returns empty string if not found (falls back to default behavior)
func getAuthInstanceAddress(ctx context.Context) string {
    if addr, ok := ctx.Value(authInstanceAddressKey).(string); ok {
        return addr
    }
    return ""
}

// HandleAuthMenuNoArgs prepares the auth menu when no arguments are provided
func HandleAuthMenuNoArgs(ctx context.Context) error {
    // Check if Cline is authenticated
    isClineAuth := IsAuthenticated(ctx)

    // Get current provider config for display
    var currentProvider string
    var currentModel string
    if manager, err := createTaskManager(ctx); err == nil {
        if providerList, err := GetProviderConfigurations(ctx, manager); err == nil {
            if providerList.ActProvider != nil {
                currentProvider = GetProviderDisplayName(providerList.ActProvider.Provider)
                currentModel = providerList.ActProvider.ModelID
            }
        }
    }

    // Fetch organizations if authenticated
    var hasOrganizations bool
    if isClineAuth {
        if client, err := global.GetDefaultClient(ctx); err == nil {
            if orgsResponse, err := client.Account.GetUserOrganizations(ctx, &cline.EmptyRequest{}); err == nil {
                hasOrganizations = len(orgsResponse.GetOrganizations()) > 0
            }
        }
    }

    action, err := ShowAuthMenuWithStatus(isClineAuth, hasOrganizations, currentProvider, currentModel)
    if err != nil {
        // Check if user cancelled - propagate for clean exit
        if err == huh.ErrUserAborted {
            return huh.ErrUserAborted
        }
        return err
    }

    switch action {
    case AuthActionClineLogin:
        return HandleClineAuth(ctx)
    case AuthActionBYOSetup:
        return HandleAPIProviderSetup(ctx)
    case AuthActionChangeClineModel:
        return HandleChangeClineModel(ctx)
    case AuthActionSelectOrganization:
        return HandleSelectOrganization(ctx)
    case AuthActionSelectProvider:
        return HandleSelectProvider(ctx)
    case AuthActionNTAccountLogin:
        return HandleNTAccountAuth(ctx)
    case AuthActionPlatformLogin:
        return HandlePlatformAuth(ctx)
    case AuthActionExit:
        return nil
    default:
        return fmt.Errorf("invalid action")
    }
}

// ShowAuthMenuWithStatus displays the main auth menu with Cline + provider status
func ShowAuthMenuWithStatus(isClineAuthenticated bool, hasOrganizations bool, currentProvider, currentModel string) (AuthAction, error) {
    var action AuthAction
    var options []huh.Option[AuthAction]

    // Build menu options based on authentication status
    if isClineAuthenticated {
        options = []huh.Option[AuthAction]{
            huh.NewOption("Change Cline model", AuthActionChangeClineModel),
        }

        // Add organization selection if user has organizations
        if hasOrganizations {
            options = append(options, huh.NewOption("Select organization", AuthActionSelectOrganization))
        }

        options = append(options,
            huh.NewOption("Sign out of Cline", AuthActionClineLogin),
            huh.NewOption("Select active provider (Cline or BYO)", AuthActionSelectProvider),
            huh.NewOption("Configure BYO API providers", AuthActionBYOSetup),
            huh.NewOption("Exit authorization wizard", AuthActionExit),
        )
    } else {
        options = []huh.Option[AuthAction]{
            huh.NewOption("Authenticate with Cline account", AuthActionClineLogin),
            huh.NewOption("Authenticate with NT Account", AuthActionNTAccountLogin),
            huh.NewOption("Authenticate with Platform account", AuthActionPlatformLogin),
            huh.NewOption("Select active provider (Cline or BYO)", AuthActionSelectProvider),
            huh.NewOption("Configure BYO API providers", AuthActionBYOSetup),
            huh.NewOption("Exit authorization wizard", AuthActionExit),
        }
    }

    // Determine menu title based on status
    var title string
    renderer := display.NewRenderer(global.Config.OutputFormat)

    // Always show Cline authentication status
    if isClineAuthenticated {
        title = fmt.Sprintf("Cline Account: %s Authenticated\n", renderer.Green("✓"))
    } else {
        title = fmt.Sprintf("Cline Account: %s Not authenticated\n", renderer.Red("✗"))
    }

    // Show active provider and model if configured (regardless of Cline auth status)
    if currentProvider != "" && currentModel != "" {
        title += fmt.Sprintf("Active Provider: %s\nActive Model: %s\n",
            renderer.White(currentProvider),
            renderer.White(currentModel))
    }

    // Always end with a huh?
    title += "\nWhat would you like to do?"

    form := huh.NewForm(
        huh.NewGroup(
            huh.NewSelect[AuthAction]().
                Title(title).
                Options(options...).
                Value(&action),
        ),
    )

    if err := form.Run(); err != nil {
        // Check if user cancelled with Control-C
        if err == huh.ErrUserAborted {
            // Return the error to allow deferred cleanup to run
            return "", huh.ErrUserAborted
        }
        return "", fmt.Errorf("failed to get menu choice: %w", err)
    }

    return action, nil
}

// HandleAPIProviderSetup launches the API provider configuration wizard
func HandleAPIProviderSetup(ctx context.Context) error {
    wizard, err := NewProviderWizard(ctx)
    if err != nil {
        return fmt.Errorf("failed to create provider wizard: %w", err)
    }

    return wizard.Run()
}

// HandleSelectProvider allows users to switch between Cline provider and BYO providers
func HandleSelectProvider(ctx context.Context) error {
    // Get task manager
    manager, err := createTaskManager(ctx)
    if err != nil {
        return fmt.Errorf("failed to create task manager: %w", err)
    }

    // Detect all providers with valid configurations (is an API key present)
    availableProviders, err := DetectAllConfiguredProviders(ctx, manager)
    if err != nil {
        return fmt.Errorf("failed to detect configured providers: %w", err)
    }

    // Build list of available providers
    var providerOptions []huh.Option[string]
    var providerMapping = make(map[string]cline.ApiProvider)

    // Add each configured provider to the selection menu
    for _, provider := range availableProviders {
        providerName := GetProviderDisplayName(provider)
        providerKey := fmt.Sprintf("provider_%d", provider)
        providerOptions = append(providerOptions, huh.NewOption(providerName, providerKey))
        providerMapping[providerKey] = provider
    }

    if len(providerOptions) == 0 {
        fmt.Println("No providers available. Please configure a provider first.")
        return HandleAuthMenuNoArgs(ctx)
    }

    providerOptions = append(providerOptions, huh.NewOption("(Cancel)", "cancel"))

    // Show selection menu
    var selected string
    form := huh.NewForm(
        huh.NewGroup(
            huh.NewSelect[string]().
                Title("Select which provider to use").
                Options(providerOptions...).
                Value(&selected),
        ),
    )

    if err := form.Run(); err != nil {
        // Check if user cancelled with Control-C
        if err == huh.ErrUserAborted {
            return huh.ErrUserAborted
        }
        return fmt.Errorf("failed to select provider: %w", err)
    }

    if selected == "cancel" {
        return HandleAuthMenuNoArgs(ctx)
    }

    // Get the selected provider
    selectedProvider := providerMapping[selected]

    // Apply the selected provider
    if selectedProvider == cline.ApiProvider_CLINE {
        // Configure Cline as the active provider
        return SelectClineModel(ctx, manager)
    } else {
        // Switch to the selected BYO provider
        return SwitchToBYOProvider(ctx, manager, selectedProvider)
    }
}

// createTaskManager is a helper to create a task manager (avoids import cycles)
// Uses the auth instance address from context if available, otherwise falls back to default
func createTaskManager(ctx context.Context) (*task.Manager, error) {
    authAddr := getAuthInstanceAddress(ctx)
    if authAddr != "" {
        return task.NewManagerForAddress(ctx, authAddr)
    }
    return task.NewManagerForDefault(ctx)
}

func verboseLog(format string, args ...interface{}) {
    if global.Config != nil && global.Config.Verbose {
        fmt.Printf("[VERBOSE] "+format+"\n", args...)
    }
}

// AccountAuthInfo 存储账号认证信息
type AccountAuthInfo struct {
    Token      string `json:"token"`
    Bu         string `json:"bu"`
    UserName   string `json:"userName"`
    UserAcct   string `json:"userAcct"`
    LoginType  int    `json:"loginType"` // 1: Platform account, 2: NT Account
    Password   string `json:"password"`  // 加密后的密码（用于自动重新登录）
}

// 全局变量，用于存储当前认证状态
var CurrentAuthInfo *AccountAuthInfo

// HandleNTAccountAuth 处理NT账号认证
func HandleNTAccountAuth(ctx context.Context) error {
    return handleAccountAuth(ctx, 2) // NT Account 类型为 2
}

// HandlePlatformAuth 处理Platform账号认证
func HandlePlatformAuth(ctx context.Context) error {
    return handleAccountAuth(ctx, 1) // Platform account 类型为 1
}

// handleAccountAuth 处理账号认证的通用逻辑
func handleAccountAuth(ctx context.Context, loginType int) error {
    // 获取用户名和密码
    var username, password string
    
    usernameForm := huh.NewForm(
        huh.NewGroup(
            huh.NewInput().
                Title("用户名").
                Value(&username).
                Validate(func(s string) error {
                    if s == "" {
                        return fmt.Errorf("用户名不能为空")
                    }
                    return nil
                }),
        ),
    )
    
    if err := usernameForm.Run(); err != nil {
        return err
    }
    
    passwordForm := huh.NewForm(
        huh.NewGroup(
            huh.NewInput().
                Title("密码").
                // EchoMode(huh.EchoModePassword). // 暂时禁用密码回显模式以便调试
                Value(&password).
                Validate(func(s string) error {
                    if s == "" {
                        return fmt.Errorf("密码不能为空")
                    }
                    return nil
                }),
        ),
    )
    
    verboseLog("准备获取密码输入...")
    
    if err := passwordForm.Run(); err != nil {
        return err
    }
    
    // 处理密码加密
    var encryptedPassword string
    if loginType == 1 {
        // Platform account 使用 MD5 加密
        // fmt.Println("原始密码: %s", password)
        encryptedPassword = md5Encrypt(password)
        // fmt.Println("MD5加密后密码: %s", encryptedPassword)
    } else {
        // NT Account 使用 RSA 加密
        // fmt.Println("原始密码: %s", password)
        encryptedPassword = rsaEncrypt(password)
        // fmt.Println("RSA加密后密码: %s", encryptedPassword)
    }
    
    if encryptedPassword == "" {
        fmt.Println("密码加密失败，请重试")
        return HandleAuthMenuNoArgs(ctx)
    }
    
    // 准备HTTP请求参数
    loginTypeStr := fmt.Sprintf("%d", loginType)

    // fmt.Println("准备发送登录请求，参数: loginType=%s, userAcct=%s, pwd=%s", loginTypeStr, username, encryptedPassword)
    authResult, err := accountLogin(loginTypeStr, username, encryptedPassword)
    if err != nil {
        fmt.Printf("认证失败: %v\n", err)
        return HandleAuthMenuNoArgs(ctx)
    }
    
    // 扩展认证信息，包含登录类型和加密后的密码（用于自动重新登录）
    authResult.LoginType = loginType
    authResult.Password = encryptedPassword
    
    // 保存认证信息到全局变量
    CurrentAuthInfo = authResult
    
    fmt.Printf("✓ 认证成功! 欢迎 %s\n", authResult.UserName)
    
    // 认证成功后，自动配置TuringCoder API Provider
    manager, err := createTaskManager(ctx)
    if err != nil {
        return fmt.Errorf("创建任务管理器失败: %w", err)
    }
    
    return ConfigureTuringCoder(ctx, manager)
}

// md5Encrypt 使用MD5加密密码
func md5Encrypt(password string) string {
    if password == "" {
        verboseLog("MD5加密失败: 密码为空")
        return ""
    }
    hash := md5.Sum([]byte(password))
    return hex.EncodeToString(hash[:])
}

// rsaEncrypt 使用RSA公钥加密密码
func rsaEncrypt(password string) string {
    if password == "" {
        fmt.Println("RSA加密失败: 密码为空")
        return ""
    }

    // 公钥必须包含PEM格式的头部和尾部
    publicKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoOMDGcMpAB5ha0QtaZ106
pcpa9GoEXxKjIPCer5L0fLU7uCHQqa5naD2XUd5Qi5rVhGnPtg3OEVqWlh8dj2pdS
A8f+AFbOSxfhi19WKgm/HDZX9mYutwdNvH6R2+cJkU1e+TyHZkn0PNtEET1X6OXYe
PYgRptkD7mkudzpkL4ff5snDhxReYINbQd+xVEcV17/OoK+bbqciXjpGWmBjjp0bD
GoPjPrJfMDRTe4Chwia1CVSQy4WV8lPR5tUcPeKf3qUVCrudtd21Cc5D3NbxJzJFy
0foXmVKnsZ9UEoZtJFbh0L2yalT/488HM9nR5W/A7Pmgz4tJceEW2eg29HdcQIDAQAB
-----END PUBLIC KEY-----`

    // 解码PEM格式的公钥
    block, _ := pem.Decode([]byte(publicKey))
    if block == nil {
        fmt.Println("RSA加密失败: 无法解码PEM块")
        return ""
    }

    // 解析公钥
    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        fmt.Printf("RSA加密失败: 解析公钥错误: %v\n", err)
        return ""
    }

    // 断言为RSA公钥
    rsaPub, ok := pub.(*rsa.PublicKey)
    if !ok {
        fmt.Println("RSA加密失败: 不是有效的RSA公钥")
        return ""
    }

    // 使用PKCS#1 v1.5填充方案加密（与JSEncrypt一致）
    encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, []byte(password))
    if err != nil {
        fmt.Printf("RSA加密失败: 加密错误: %v\n", err)
        return ""
    }

    // 返回Base64编码的结果
    return base64.StdEncoding.EncodeToString(encrypted)
}

// 认证信息存储路径
const AuthInfoPath = ".cline_auth_info.json"

// SaveAuthInfo 将认证信息保存到本地文件
func SaveAuthInfo(info *AccountAuthInfo) error {
    // 获取用户主目录
    homeDir, err := os.UserHomeDir()
    if err != nil {
        return fmt.Errorf("获取用户主目录失败: %w", err)
    }
    
    // 构建存储路径
    filePath := filepath.Join(homeDir, AuthInfoPath)
    
    // 序列化认证信息
    data, err := json.Marshal(info)
    if err != nil {
        return fmt.Errorf("序列化认证信息失败: %w", err)
    }
    
    // 写入文件（使用 0600 权限确保只有用户本人可以访问）
    err = os.WriteFile(filePath, data, 0600)
    if err != nil {
        return fmt.Errorf("写入认证信息失败: %w", err)
    }
    
    return nil
}

// LoadAuthInfo 从本地文件加载认证信息
func LoadAuthInfo() (*AccountAuthInfo, error) {
    // 获取用户主目录
    homeDir, err := os.UserHomeDir()
    if err != nil {
        return nil, fmt.Errorf("获取用户主目录失败: %w", err)
    }
    
    // 构建存储路径
    filePath := filepath.Join(homeDir, AuthInfoPath)
    
    // 检查文件是否存在
    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        return nil, nil // 文件不存在，返回 nil
    }
    
    // 读取文件
    data, err := os.ReadFile(filePath)
    if err != nil {
        return nil, fmt.Errorf("读取认证信息失败: %w", err)
    }
    
    // 反序列化认证信息
    var info AccountAuthInfo
    if err := json.Unmarshal(data, &info); err != nil {
        return nil, fmt.Errorf("解析认证信息失败: %w", err)
    }
    
    return &info, nil
}

// ClearAuthInfo 清除保存的认证信息
func ClearAuthInfo() error {
    // 获取用户主目录
    homeDir, err := os.UserHomeDir()
    if err != nil {
        return fmt.Errorf("获取用户主目录失败: %w", err)
    }
    
    // 构建存储路径
    filePath := filepath.Join(homeDir, AuthInfoPath)
    
    // 检查文件是否存在
    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        return nil // 文件不存在，无需清除
    }
    
    // 删除文件
    if err := os.Remove(filePath); err != nil {
        return fmt.Errorf("清除认证信息失败: %w", err)
    }
    
    return nil
}

// InitializeAuth 初始化认证状态
func InitializeAuth(ctx context.Context) error {
    // 尝试加载保存的认证信息
    authInfo, err := LoadAuthInfo()
    if err != nil {
        verboseLog("加载认证信息失败: %v", err)
        return nil // 继续运行程序，不阻塞启动
    }
    
    // 如果没有保存的认证信息，则不进行处理
    if authInfo == nil {
        return nil
    }
    
    // 只处理新增的两种认证方式
    if authInfo.LoginType != 1 && authInfo.LoginType != 2 {
        return nil
    }
    
    fmt.Println("检测到已保存的认证信息，尝试自动重新登录...")
    verboseLog("检测到已保存的认证信息，尝试自动重新登录...")
    
    // 准备HTTP请求参数
    loginTypeStr := fmt.Sprintf("%d", authInfo.LoginType)
    
    // 使用保存的用户名和密码进行重新登录
    newAuthInfo, err := accountLogin(loginTypeStr, authInfo.UserAcct, authInfo.Password)
    if err != nil {
        verboseLog("自动重新登录失败: %v，请手动登录", err)
        // 清除失效的认证信息
        if clearErr := ClearAuthInfo(); clearErr != nil {
            verboseLog("清除认证信息失败: %v", clearErr)
        }
        return nil
    }
    
    // 更新全局认证信息，保留登录类型和密码信息
    newAuthInfo.LoginType = authInfo.LoginType
    newAuthInfo.Password = authInfo.Password
    CurrentAuthInfo = newAuthInfo
    
    // 更新保存的认证信息
    if err := SaveAuthInfo(newAuthInfo); err != nil {
        verboseLog("更新认证信息失败: %v", err)
    }
    
    fmt.Println("自动重新登录成功，用户: %s", newAuthInfo.UserName)
    verboseLog("自动重新登录成功，用户: %s", newAuthInfo.UserName)
    
    // 自动配置TuringCoder API Provider
    manager, err := createTaskManager(ctx)
    if err != nil {
        verboseLog("创建任务管理器失败: %v", err)
        return nil
    }
    
    if err := ConfigureTuringCoder(ctx, manager); err != nil {
        verboseLog("配置TuringCoder失败: %v", err)
    }
    
    return nil
}

// accountLogin 发送HTTP请求进行账号验证
func accountLogin(loginType, userAcct, userPwd string) (*AccountAuthInfo, error) {
    url := "https://codegpt-copilot.asiainfo.com.cn/api/prompt/user/login"
    
    // 构建请求参数
    params := map[string]string{
        "loginType": loginType,
        "userAcct": userAcct,
        "userPwd":  userPwd,
        "pluginLogin":  "true",
    }
    
    // 发送HTTP POST请求
    jsonData, err := json.Marshal(params)
    if err != nil {
        return nil, fmt.Errorf("序列化请求参数失败: %w", err)
    }
    
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
    }
    
    req.Header.Set("Content-Type", "application/json")
    
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("发送HTTP请求失败: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("认证失败，状态码: %d", resp.StatusCode)
    }
    
    // 定义响应结构体
    type apiResponse struct {
        Code string `json:"code"`
        Msg string `json:"msg"`
        Data struct {
            Token    string `json:"realToken"`
            Bu       string `json:"bu"`
            UserAcct string `json:"userAcct"`
            UserName string `json:"userName"`
        } `json:"data"`
    }

    // 解析响应
    var response apiResponse
    if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
        return nil, fmt.Errorf("解析响应失败: %w", err)
    }

    // 检查响应码
    if response.Code != "200" {
        return nil, fmt.Errorf("认证失败: %s", response.Code +":" + response.Msg + "。参数：loginType=" + loginType + ",userAcct=" + userAcct + ",pwd=" + userPwd)
    }

    // 构建认证信息
    authInfo := &AccountAuthInfo{
        Token:    response.Data.Token,
        Bu:       response.Data.Bu,
        UserAcct: response.Data.UserAcct,
        UserName: response.Data.UserName,
    }
    
    return authInfo, nil
}
