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
)

// TuringCoderAuthInfo 存储账号认证信息
type TuringCoderAuthInfo struct {
    Token      string `json:"token"`      // 认证令牌
    Bu         string `json:"bu"`         // 业务单元
    UserName   string `json:"userName"`   // 用户名
    UserAcct   string `json:"userAcct"`   // 账号
    LoginType  int    `json:"loginType"`  // 1: PlatformAccount，2: NTAccount
    Password   string `json:"password"`   // 加密后的密码（用于自动重新登录）
}

// currentTuringCoderAuthInfo 全局变量，用于存储当前认证状态
var currentTuringCoderAuthInfo *TuringCoderAuthInfo

// HandleTuringCoderNTAuth 处理NTAccount认证（供auth_menu.go调用）
func HandleTuringCoderNTAuth(ctx context.Context) error {
    return handleTuringCoderAuth(ctx, 2) // NTAccount 类型为 2
}

// HandleTuringCoderPlatformAuth 处理PlatformAccount认证（供auth_menu.go调用）
func HandleTuringCoderPlatformAuth(ctx context.Context) error {
    return handleTuringCoderAuth(ctx, 1) // PlatformAccount 类型为 1
}

// handleTuringCoderAuth 处理账号认证的通用逻辑
func handleTuringCoderAuth(ctx context.Context, loginType int) error {
    // 获取用户名和密码
    var username, password string

    // 用户名输入表单
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

    // 密码输入表单
    passwordForm := huh.NewForm(
        huh.NewGroup(
            huh.NewInput().
                Title("密码").
                Value(&password).
                Validate(func(s string) error {
                    if s == "" {
                        return fmt.Errorf("密码不能为空")
                    }
                    return nil
                }),
        ),
    )

    if err := passwordForm.Run(); err != nil {
        return err
    }

    // 处理密码加密
    var encryptedPassword string
    if loginType == 1 {
        // PlatformAccount 使用 MD5 加密
        encryptedPassword = md5Encrypt(password)
    } else {
        // NTAccount 使用 RSA 加密
        encryptedPassword = rsaEncrypt(password)
    }

    if encryptedPassword == "" {
        fmt.Println("密码加密失败，请重试")
        return nil
    }

    // 准备HTTP请求参数
    loginTypeStr := fmt.Sprintf("%d", loginType)

    authResult, err := doTuringCoderLogin(loginTypeStr, username, encryptedPassword)
    if err != nil {
        fmt.Printf("认证失败: %v\n", err)
        return nil
    }

    // 扩展认证信息，包含登录类型和加密后的密码（用于自动重新登录）
    authResult.LoginType = loginType
    authResult.Password = encryptedPassword

    // 保存认证信息到全局变量
    currentTuringCoderAuthInfo = authResult

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

    // 使用PKCS#1 v1.5填充方案加密
    encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, []byte(password))
    if err != nil {
        fmt.Printf("RSA加密失败: 加密错误: %v\n", err)
        return ""
    }

    // 返回Base64编码的结果
    return base64.StdEncoding.EncodeToString(encrypted)
}

// 认证信息存储路径
const TuringCoderAuthInfoPath = ".turing_coder_auth_info.json"

// SaveTuringCoderAuthInfo 将认证信息保存到本地文件
func SaveTuringCoderAuthInfo(info *TuringCoderAuthInfo) error {
    homeDir, err := os.UserHomeDir()
    if err != nil {
        return fmt.Errorf("获取用户主目录失败: %w", err)
    }
    filePath := filepath.Join(homeDir,".cline", "data", TuringCoderAuthInfoPath)
    data, err := json.Marshal(info)
    if err != nil {
        return fmt.Errorf("序列化认证信息失败: %w", err)
    }
    err = os.WriteFile(filePath, data, 0600)
    if err != nil {
        return fmt.Errorf("写入认证信息失败: %w", err)
    }
    return nil
}

// LoadTuringCoderAuthInfo 从本地文件加载认证信息
func LoadTuringCoderAuthInfo() (*TuringCoderAuthInfo, error) {
    homeDir, err := os.UserHomeDir()
    if err != nil {
        return nil, fmt.Errorf("获取用户主目录失败: %w", err)
    }
    filePath := filepath.Join(homeDir,".cline", "data", TuringCoderAuthInfoPath)
    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        return nil, nil
    }
    data, err := os.ReadFile(filePath)
    if err != nil {
        return nil, fmt.Errorf("读取认证信息失败: %w", err)
    }
    var info TuringCoderAuthInfo
    if err := json.Unmarshal(data, &info); err != nil {
        return nil, fmt.Errorf("解析认证信息失败: %w", err)
    }
    return &info, nil
}

// ClearTuringCoderAuthInfo 清除保存的认证信息
func ClearTuringCoderAuthInfo() error {
    homeDir, err := os.UserHomeDir()
    if err != nil {
        return fmt.Errorf("获取用户主目录失败: %w", err)
    }
    filePath := filepath.Join(homeDir,".cline", "data", TuringCoderAuthInfoPath)
    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        return nil
    }
    if err := os.Remove(filePath); err != nil {
        return fmt.Errorf("清除认证信息失败: %w", err)
    }
    return nil
}

// InitializeTuringCoderAuth 初始化认证状态
func InitializeTuringCoderAuth(ctx context.Context) error {
    authInfo, err := LoadTuringCoderAuthInfo()
    if err != nil {
        return nil
    }
    if authInfo == nil {
        return nil
    }
    if authInfo.LoginType != 1 && authInfo.LoginType != 2 {
        return nil
    }
    fmt.Println("检测到已保存的认证信息，尝试自动重新登录...")
    loginTypeStr := fmt.Sprintf("%d", authInfo.LoginType)
    newAuthInfo, err := doTuringCoderLogin(loginTypeStr, authInfo.UserAcct, authInfo.Password)
    if err != nil {
        if clearErr := ClearTuringCoderAuthInfo(); clearErr != nil {
        }
        return nil
    }
    newAuthInfo.LoginType = authInfo.LoginType
    newAuthInfo.Password = authInfo.Password
    currentTuringCoderAuthInfo = newAuthInfo
    if err := SaveTuringCoderAuthInfo(newAuthInfo); err != nil {
    }
    fmt.Println("自动重新登录成功，用户: %s", newAuthInfo.UserName)
    manager, err := createTaskManager(ctx)
    if err != nil {
        return nil
    }
    if err := ConfigureTuringCoder(ctx, manager); err != nil {
    }
    return nil
}

// doTuringCoderLogin 发送HTTP请求进行账号验证
func doTuringCoderLogin(loginType, userAcct, userPwd string) (*TuringCoderAuthInfo, error) {
    url := "https://codegpt-copilot.asiainfo.com.cn/api/prompt/user/login"
    params := map[string]string{
        "loginType":   loginType,
        "userAcct":    userAcct,
        "userPwd":     userPwd,
        "pluginLogin": "true",
    }
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
    type apiResponse struct {
        Code string `json:"code"`
        Msg  string `json:"msg"`
        Data struct {
            Token    string `json:"realToken"`
            Bu       string `json:"bu"`
            UserAcct string `json:"userAcct"`
            UserName string `json:"userName"`
        } `json:"data"`
    }
    var response apiResponse
    if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
        return nil, fmt.Errorf("解析响应失败: %w", err)
    }
    if response.Code != "200" {
        return nil, fmt.Errorf("认证失败: %s", response.Code+":"+response.Msg+"。参数：loginType="+loginType+",userAcct="+userAcct+",pwd="+userPwd)
    }
    authInfo := &TuringCoderAuthInfo{
        Token:    response.Data.Token,
        Bu:       response.Data.Bu,
        UserAcct: response.Data.UserAcct,
        UserName: response.Data.UserName,
    }
    return authInfo, nil
}

